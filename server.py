#!/usr/bin/env python3
"""Console that installs 1C platform packages from vendor zip archives."""

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from hostadmin import (
    apply_system,
    auth_hint,
    backup_dir,
    cluster_catalog,
    github_changelog,
    github_release,
    new_stamp,
    open_backup,
    prune,
    read_system,
    schedule_power,
    schedule_update,
    sql_backup,
    sql_catalog,
    update_offer,
    vm_catalog,
)
from ops import deliver, list_storage, probe, public_copy, run_vm, schedule_due

PRODUCT_VERSION = "1.2.12"
LOGIN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")

STATE_DIR = Path(os.environ.get("ONEC_STATE_DIR", "/var/lib/onec-console"))
CACHE_DIR = Path(os.environ.get("ONEC_CACHE_DIR", "/var/cache/onec-platform"))
PASSWORD_FILE = Path(os.environ.get("ONEC_PASSWORD_FILE", "/etc/onec-console/initial-password"))
HOST = os.environ.get("ONEC_HOST", "0.0.0.0")
PORT = int(os.environ.get("ONEC_PORT", "8780"))
HERE = Path(__file__).resolve().parent
MAX_UPLOAD = 2_000_000_000

INSTALL_ORDER = ("common", "common-nls", "server", "server-nls", "client", "client-nls", "thin-client", "thin-client-nls")
SKIP_REASON = {
    "ws": "Веб-публикация для бекапа не нужна",
    "ws-nls": "Языковой пакет веб-модуля не нужен",
    "crs": "Сервер хранилища не нужен",
}
ROLE_RE_PARTS = (
    "thin-client-nls",
    "thin-client",
    "common-nls",
    "server-nls",
    "client-nls",
    "ws-nls",
    "common",
    "server",
    "client",
    "ws",
    "crs",
)

LOCK = threading.Lock()
INSTALL_LOCK = threading.Lock()


def pbkdf2(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return digest.hex()


def blank_state() -> dict:
    return {
        "users": [],
        "sessions": {},
        "archives": {},
        "installed": None,
        "log": [],
        "storages": [],
        "hosts": [],
        "jobs": [],
        "bases": [],
        "clusters": [],
        "chosenBases": [],
        "chosenVms": [],
        "sqlServers": [],
        "chosenSql": [],
        "backupJobs": [],
    }


def load_state() -> dict:
    path = STATE_DIR / "state.json"
    if not path.exists():
        return blank_state()
    state = json.loads(path.read_text(encoding="utf-8"))
    for key, value in blank_state().items():
        state.setdefault(key, value)
    return state


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    target = STATE_DIR / "state.json"
    temporary = STATE_DIR / "state.json.tmp"
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)


def ensure_admin() -> None:
    with LOCK:
        state = load_state()
        if state["users"]:
            return
        if not PASSWORD_FILE.is_file():
            raise SystemExit(f"no users and no password file: {PASSWORD_FILE}")
        password = PASSWORD_FILE.read_text(encoding="utf-8").strip()
        if len(password) < 8:
            raise SystemExit("initial password file is empty or too short")
        salt = secrets.token_hex(16)
        state["users"].append(
            {
                "login": "admin",
                "name": "Администратор",
                "salt": salt,
                "passHash": pbkdf2(password, salt),
                "mustChange": True,
                "blocked": False,
            }
        )
        save_state(state)


def version_from_text(text: str):
    import re

    dotted = re.search(r"(\d+\.\d+\.\d+)\.(\d{3,})", text)
    if dotted:
        return f"{dotted.group(1)}.{dotted.group(2)}"
    package = re.search(r"_(\d+\.\d+\.\d+)-(\d+)_", text)
    if package:
        return f"{package.group(1)}.{package.group(2)}"
    underscored = re.search(r"(\d+)_(\d+)_(\d+)_(\d+)", text)
    if underscored:
        return ".".join(underscored.groups())
    return None


def classify(file_name: str) -> dict:
    import re

    base = Path(file_name).name
    match = re.search(
        r"1c-enterprise(?:\d+|-[\d.]+)-(" + "|".join(ROLE_RE_PARTS) + r")(?:_|\.)",
        base,
        re.IGNORECASE,
    )
    role = match.group(1).lower() if match else "unknown"
    return {"fileName": base, "role": role, "version": version_from_text(base)}


def build_plan(packages: list) -> dict:
    known = [item for item in packages if item["role"] != "unknown"]
    versions = sorted({item["version"] for item in known if item["version"]})
    if len(versions) > 1:
        return {"steps": [], "version": None, "error": "В архивах разные версии платформы: " + ", ".join(versions)}
    by_role = {}
    for item in known:
        by_role.setdefault(item["role"], item)
    steps = []
    for role in INSTALL_ORDER:
        item = by_role.get(role)
        if item:
            reason = "Ставится вместе с толстым клиентом" if role.startswith("thin-client") else "Нужен для Конфигуратора и сервера"
            steps.append({**item, "action": "install", "reason": reason})
    for role, reason in SKIP_REASON.items():
        item = by_role.get(role)
        if item:
            steps.append({**item, "action": "skip", "reason": reason})
    roles = {step["role"] for step in steps if step["action"] == "install"}
    error = None
    if "common" not in roles or "server" not in roles:
        error = "Нет серверного архива: нужны пакеты common и server."
    elif "client" not in roles:
        error = "Нет полного клиента. Архив тонкого клиента не подходит."
    return {"steps": steps, "version": versions[0] if versions else None, "error": error}


def safe_zip_names(path: Path) -> list:
    names = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            raw = info.filename.replace("\\", "/")
            if raw.startswith("/") or ".." in raw.split("/"):
                raise ValueError("В архиве небезопасный путь.")
            if raw.lower().endswith(".deb"):
                names.append(classify(raw))
    return names


def current_plan(state: dict) -> dict:
    packages = []
    for kind in ("server", "client", "thin"):
        slot = state["archives"].get(kind)
        if slot:
            packages.extend(slot["packages"])
    return build_plan(packages)


class Handler(BaseHTTPRequestHandler):
    server_version = "onec-console"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _session_user(self, state: dict):
        cookie = self.headers.get("Cookie", "")
        token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("onec_session="):
                token = part.split("=", 1)[1]
        login = state["sessions"].get(token)
        if not login:
            return None
        return next((user for user in state["users"] if user["login"] == login), None)

    def _send(self, code: int, body, content_type="application/json", cookie=None) -> None:
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("Слишком большой запрос.")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode() or "{}")

    def _guard(self, state):
        user = self._session_user(state)
        if not user:
            self._send(401, {"error": "Нужен вход."})
            return None
        if user.get("blocked"):
            self._send(401, {"error": "Учётная запись заблокирована."})
            return None
        return user

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            page = (HERE / "index.html").read_bytes()
            self._send(200, page, "text/html; charset=utf-8")
            return
        if path == "/logo.png":
            logo = (HERE / "logo.png").read_bytes()
            self._send(200, logo, "image/png")
            return
        with LOCK:
            state = load_state()
        if path == "/api/state":
            user = self._guard(state)
            if not user:
                return
            public_users = [
                {"login": item["login"], "name": item["name"], "mustChange": item["mustChange"], "blocked": bool(item.get("blocked"))}
                for item in state["users"]
            ]
            archives = {
                kind: {"fileName": slot["fileName"], "count": len(slot["packages"])}
                for kind, slot in state["archives"].items()
            }
            self._send(
                200,
                {
                    "me": {"login": user["login"], "name": user["name"], "mustChange": user["mustChange"]},
                    "users": public_users,
                    "archives": archives,
                    "plan": current_plan(state),
                    "installed": state["installed"],
                    "log": state["log"],
                    "version": PRODUCT_VERSION,
                    "storages": public_copy(state["storages"]),
                    "hosts": public_copy(state["hosts"]),
                    "jobs": state["jobs"],
                    "bases": state["bases"],
                    "clusters": public_copy(state["clusters"]),
                    "chosenBases": state["chosenBases"],
                    "chosenVms": state["chosenVms"],
                    "sqlServers": public_copy(state["sqlServers"]),
                    "chosenSql": state["chosenSql"],
                    "backupJobs": state["backupJobs"],
                },
            )
            return
        if path == "/api/storages/browse":
            user = self._guard(state)
            if not user:
                return
            query = parse_qs(urlparse(self.path).query)
            item_id = (query.get("id") or [""])[0]
            rel = (query.get("path") or [""])[0]
            item = next((row for row in state["storages"] if row["id"] == item_id), None)
            if not item:
                self._send(404, {"error": "Хранилище не найдено."})
                return
            try:
                self._send(200, list_storage(item, rel))
            except Exception as error:
                self._send(400, {"error": str(error)})
            return
        if path in ("/api/system", "/api/release", "/api/changelog", "/api/update"):
            user = self._guard(state)
            if not user:
                return
            if path == "/api/system":
                payload = read_system()
            elif path == "/api/release":
                payload = github_release()
            elif path == "/api/update":
                payload = update_offer(PRODUCT_VERSION)
            else:
                payload = github_changelog()
            self._send(200, payload)
            return
        self._send(404, {"error": "Не найдено."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/login":
            self._login()
            return
        if path == "/api/logout":
            self._logout()
            return
        with LOCK:
            state = load_state()
        user = self._guard(state)
        if not user:
            return
        if path == "/api/password":
            self._password(state, user)
            return
        if path == "/api/operators":
            self._add_operator(state)
            return
        if path == "/api/operators/update":
            self._update_operator(user)
            return
        if path == "/api/archive":
            self._upload(state)
            return
        if path == "/api/install":
            self._install(state)
            return
        if path == "/api/storages":
            self._add_storage()
            return
        if path == "/api/hosts":
            self._add_host()
            return
        if path == "/api/jobs":
            self._add_job()
            return
        if path == "/api/jobs/run":
            self._run_job()
            return
        if path == "/api/bases":
            self._add_base()
            return
        if path == "/api/schedule":
            self._schedule()
            return
        if path == "/api/system":
            self._apply_system()
            return
        if path == "/api/power":
            self._power()
            return
        if path == "/api/update":
            self._update()
            return
        if path == "/api/clusters":
            self._add_cluster()
            return
        if path == "/api/clusters/catalog":
            self._refresh_cluster()
            return
        if path == "/api/hosts/catalog":
            self._refresh_host()
            return
        if path == "/api/sql":
            self._add_sql()
            return
        if path == "/api/sql/catalog":
            self._refresh_sql()
            return
        if path == "/api/chosen":
            self._add_chosen()
            return
        if path == "/api/backup-jobs":
            self._add_backup_job()
            return
        if path == "/api/backup-jobs/run":
            self._run_backup_job()
            return
        self._send(404, {"error": "Не найдено."})

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        with LOCK:
            state = load_state()
        user = self._guard(state)
        if not user:
            return
        query = parse_qs(parsed.query)
        if parsed.path == "/api/operators":
            login = query.get("login", [""])[0]
            if login == user["login"]:
                self._send(400, {"error": "Нельзя удалить свою учётную запись."})
                return
            state["users"] = [item for item in state["users"] if item["login"] != login]
            state["sessions"] = {token: who for token, who in state["sessions"].items() if who != login}
        elif parsed.path == "/api/storages":
            item_id = query.get("id", [""])[0]
            state["storages"] = [item for item in state["storages"] if item["id"] != item_id]
        elif parsed.path == "/api/hosts":
            item_id = query.get("id", [""])[0]
            state["hosts"] = [item for item in state["hosts"] if item["id"] != item_id]
            state["jobs"] = [item for item in state["jobs"] if item["hostId"] != item_id]
            state["chosenVms"] = [item for item in state["chosenVms"] if item["sourceId"] != item_id]
        elif parsed.path == "/api/clusters":
            item_id = query.get("id", [""])[0]
            state["clusters"] = [item for item in state["clusters"] if item["id"] != item_id]
            state["chosenBases"] = [item for item in state["chosenBases"] if item["sourceId"] != item_id]
        elif parsed.path == "/api/sql":
            item_id = query.get("id", [""])[0]
            gone = {item["id"] for item in state["chosenSql"] if item["sourceId"] == item_id}
            state["sqlServers"] = [item for item in state["sqlServers"] if item["id"] != item_id]
            state["chosenSql"] = [item for item in state["chosenSql"] if item["sourceId"] != item_id]
            state["backupJobs"] = [item for item in state["backupJobs"] if not (item["kind"] == "sql" and item["targetId"] in gone)]
        elif parsed.path == "/api/chosen":
            item_id = query.get("id", [""])[0]
            kind = query.get("kind", [""])[0]
            chosen_keys = {"base": "chosenBases", "vm": "chosenVms", "sql": "chosenSql"}
            key = chosen_keys.get(kind)
            if not key:
                self._send(400, {"error": "Неизвестный список."})
                return
            state[key] = [item for item in state[key] if item["id"] != item_id]
            state["backupJobs"] = [item for item in state["backupJobs"] if not (item["kind"] == kind and item["targetId"] == item_id)]
        elif parsed.path == "/api/backup-jobs":
            item_id = query.get("id", [""])[0]
            state["backupJobs"] = [item for item in state["backupJobs"] if item["id"] != item_id]
        elif parsed.path == "/api/jobs":
            item_id = query.get("id", [""])[0]
            state["jobs"] = [item for item in state["jobs"] if item["id"] != item_id]
        elif parsed.path == "/api/bases":
            item_id = query.get("id", [""])[0]
            state["bases"] = [item for item in state["bases"] if item["id"] != item_id]
        else:
            self._send(404, {"error": "Не найдено."})
            return
        with LOCK:
            fresh = load_state()
            for key in ("users", "sessions", "storages", "hosts", "jobs", "bases", "clusters", "chosenBases", "chosenVms", "sqlServers", "chosenSql", "backupJobs"):
                fresh[key] = state[key]
            save_state(fresh)
        self._send(200, {"ok": True})

    def _login(self) -> None:
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        login = str(payload.get("login", "")).strip()
        password = str(payload.get("password", ""))
        with LOCK:
            state = load_state()
            found = next((item for item in state["users"] if item["login"] == login), None)
            if not found or found["passHash"] != pbkdf2(password, found["salt"]):
                self._send(401, {"error": "Неверный логин или пароль."})
                return
            if found.get("blocked"):
                self._send(403, {"error": "Учётная запись заблокирована."})
                return
            token = secrets.token_urlsafe(32)
            state["sessions"][token] = found["login"]
            save_state(state)
        self._send(
            200,
            {"ok": True},
            cookie=f"onec_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
        )

    def _logout(self) -> None:
        token = ""
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("onec_session="):
                token = part.split("=", 1)[1]
        with LOCK:
            state = load_state()
            state["sessions"].pop(token, None)
            save_state(state)
        self._send(200, {"ok": True}, cookie="onec_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")

    def _password(self, state, user) -> None:
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        current = str(payload.get("current", ""))
        new_password = str(payload.get("password", ""))
        if user["passHash"] != pbkdf2(current, user["salt"]):
            self._send(400, {"error": "Текущий пароль не совпал."})
            return
        if len(new_password) < 8:
            self._send(400, {"error": "Новый пароль — не короче 8 символов."})
            return
        salt = secrets.token_hex(16)
        user["salt"] = salt
        user["passHash"] = pbkdf2(new_password, salt)
        user["mustChange"] = False
        with LOCK:
            fresh = load_state()
            fresh["users"] = [user if item["login"] == user["login"] else item for item in fresh["users"]]
            save_state(fresh)
        if PASSWORD_FILE.exists():
            PASSWORD_FILE.unlink()
        self._send(200, {"ok": True})

    def _add_operator(self, state) -> None:
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        login = str(payload.get("login", "")).strip().lower()
        name = str(payload.get("name", "")).strip()
        password = str(payload.get("password", ""))
        if not LOGIN_RE.fullmatch(login) or not name or len(password) < 8:
            self._send(400, {"error": "Логин — латиница, цифры, точка или дефис. Имя и пароль от 8 символов."})
            return
        if any(item["login"] == login for item in state["users"]):
            self._send(400, {"error": "Такой логин уже есть."})
            return
        salt = secrets.token_hex(16)
        state["users"].append(
            {"login": login, "name": name, "salt": salt, "passHash": pbkdf2(password, salt), "mustChange": False, "blocked": False}
        )
        with LOCK:
            fresh = load_state()
            if any(item["login"] == login for item in fresh["users"]):
                self._send(400, {"error": "Такой логин уже есть."})
                return
            fresh["users"].append(state["users"][-1])
            save_state(fresh)
        self._send(200, {"ok": True})

    def _update_operator(self, actor) -> None:
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        old = str(payload.get("login", "")).strip().lower()
        new_login = str(payload.get("newLogin", old)).strip().lower()
        name = str(payload.get("name", "")).strip()
        blocked = bool(payload.get("blocked"))
        if not name or not LOGIN_RE.fullmatch(new_login or ""):
            self._send(400, {"error": "Имя не пустое, логин — латиница, цифры, точка, дефис."})
            return
        with LOCK:
            fresh = load_state()
            found = next((item for item in fresh["users"] if item["login"] == old), None)
            if not found:
                self._send(404, {"error": "Пользователь не найден."})
                return
            if new_login != old and any(item["login"] == new_login for item in fresh["users"]):
                self._send(400, {"error": "Такой логин уже есть."})
                return
            if blocked and old == actor["login"]:
                self._send(400, {"error": "Нельзя заблокировать свою учётную запись."})
                return
            others = [item for item in fresh["users"] if item["login"] != old and not item.get("blocked")]
            if blocked and not others:
                self._send(400, {"error": "Нужна хотя бы одна действующая учётная запись."})
                return
            found["name"] = name
            found["blocked"] = blocked
            found["login"] = new_login
            sessions = {}
            for token, who in fresh["sessions"].items():
                if who != old:
                    sessions[token] = who
                elif not blocked:
                    sessions[token] = new_login
            fresh["sessions"] = sessions
            save_state(fresh)
        self._send(200, {"ok": True})

    def _upload(self, state) -> None:
        query = parse_qs(urlparse(self.path).query)
        kind = query.get("kind", [""])[0]
        if kind not in ("server", "client", "thin"):
            self._send(400, {"error": "Нужен kind=server, kind=client или kind=thin."})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD:
            self._send(400, {"error": "Пустой или слишком большой архив."})
            return
        file_name = Path(self.headers.get("X-Filename", "archive.zip")).name
        if not file_name.lower().endswith(".zip"):
            self._send(400, {"error": "Нужен zip-архив."})
            return
        incoming = CACHE_DIR / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        target = incoming / f"{kind}-{secrets.token_hex(4)}-{file_name}"
        remaining = length
        with target.open("wb") as handle:
            while remaining:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                handle.write(chunk)
                remaining -= len(chunk)
        try:
            packages = safe_zip_names(target)
        except (zipfile.BadZipFile, ValueError) as error:
            target.unlink(missing_ok=True)
            self._send(400, {"error": str(error) if isinstance(error, ValueError) else "Файл не похож на zip-архив."})
            return
        if not packages:
            target.unlink(missing_ok=True)
            self._send(400, {"error": "В архиве нет deb-пакетов платформы."})
            return
        with LOCK:
            fresh = load_state()
            previous = fresh["archives"].get(kind)
            fresh["archives"][kind] = {"fileName": file_name, "path": str(target), "packages": packages}
            fresh["log"] = []
            save_state(fresh)
        if previous:
            Path(previous["path"]).unlink(missing_ok=True)
        self._send(200, {"ok": True, "count": len(packages)})

    def _install(self, state) -> None:
        if not INSTALL_LOCK.acquire(blocking=False):
            self._send(409, {"error": "Установка уже идёт."})
            return
        try:
            plan = current_plan(state)
            if plan["error"] or not plan["version"]:
                self._send(400, {"error": plan["error"] or "План установки пуст."})
                return
            log = self._run_install(state, plan)
            self._send(200, {"ok": True, "log": log, "installed": load_state()["installed"]})
        finally:
            INSTALL_LOCK.release()

    def _run_install(self, state, plan) -> list:
        version = plan["version"]
        dest = CACHE_DIR / version
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        wanted = {step["fileName"]: step for step in plan["steps"] if step["action"] == "install"}
        log = [f"Версия платформы {version}. Архивы согласованы."]
        for kind in ("server", "client", "thin"):
            slot = state["archives"].get(kind)
            if not slot:
                continue
            log.append(f"Распаковка {slot['fileName']} → {dest}")
            with zipfile.ZipFile(slot["path"]) as archive:
                for info in archive.infolist():
                    base = Path(info.filename).name
                    if base not in wanted:
                        continue
                    target = dest / base
                    with archive.open(info) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
        for step in plan["steps"]:
            if step["action"] == "skip":
                log.append(f"пропуск  {step['fileName']} — {step['reason']}")
                continue
            package = dest / step["fileName"]
            log.append(f"dpkg -i {package}")
            result = subprocess.run(
                ["dpkg", "-i", str(package)],
                text=True,
                capture_output=True,
                check=False,
            )
            tail = (result.stdout + result.stderr).strip().splitlines()
            log.extend(tail[-8:])
            if result.returncode != 0:
                log.append(f"dpkg завершился с кодом {result.returncode}")
                self._store_log(log, None)
                return log
        log.append("apt-get install -f -y")
        apt = subprocess.run(["apt-get", "install", "-f", "-y"], text=True, capture_output=True, check=False)
        tail = (apt.stdout + apt.stderr).strip().splitlines()
        log.extend(tail[-8:])
        binary = Path(f"/opt/1cv8/x86_64/{version}/1cv8")
        log.append(f"проверка  test -x {binary}")
        installed = None
        if binary.is_file() and os.access(binary, os.X_OK):
            log.append(f"готово  {binary}")
            installed = {"version": version, "binary": str(binary)}
        else:
            log.append(f"бинарник не найден: {binary}")
        self._store_log(log, installed)
        return log

    def _store_log(self, log, installed) -> None:
        with LOCK:
            fresh = load_state()
            fresh["log"] = log
            if installed:
                fresh["installed"] = installed
            save_state(fresh)

    def _add_storage(self) -> None:
        payload = self._read_json()
        role = payload.get("role")
        kind = str(payload.get("kind", ""))
        name = str(payload.get("name", "")).strip()
        endpoint = str(payload.get("endpoint", "")).strip()
        secret = str(payload.get("secret", ""))
        if role not in ("disk", "cloud") or not name or not endpoint or not secret:
            self._send(400, {"error": "Нужны тип, имя, адрес и секрет."})
            return
        item = {
            "id": secrets.token_hex(8),
            "role": role,
            "kind": kind,
            "name": name,
            "endpoint": endpoint,
            "login": str(payload.get("login", "")).strip(),
            "secret": secret,
        }
        ok, detail = probe(item)
        item["status"] = "ready" if ok else "error"
        item["detail"] = detail
        with LOCK:
            state = load_state()
            state["storages"].append(item)
            save_state(state)
        self._send(200, {"ok": ok, "detail": detail})

    def _add_host(self) -> None:
        payload = self._read_json()
        name = str(payload.get("name", "")).strip()
        host = str(payload.get("host", "")).strip()
        login = str(payload.get("login", "")).strip()
        secret = str(payload.get("secret", ""))
        kind = payload.get("kind")
        if kind not in ("esxi", "vsphere") or not name or not host or not login or not secret:
            self._send(400, {"error": "Заполните гипервизор, адрес, логин и пароль."})
            return
        with LOCK:
            state = load_state()
            state["hosts"].append(
                {"id": secrets.token_hex(8), "kind": kind, "name": name, "host": host, "login": login, "secret": secret, "catalog": []}
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _add_job(self) -> None:
        payload = self._read_json()
        schedule = payload.get("schedule") or {"enabled": False, "days": [0, 1, 2, 3, 4], "time": "02:00"}
        vm_name = str(payload.get("vmName", "")).strip()
        host_id = str(payload.get("hostId", ""))
        storage_id = str(payload.get("storageId", ""))
        if not vm_name or not host_id or not storage_id:
            self._send(400, {"error": "Выберите гипервизор, машину и диск."})
            return
        with LOCK:
            state = load_state()
            state["jobs"].append(
                {
                    "id": secrets.token_hex(8),
                    "hostId": host_id,
                    "vmName": vm_name,
                    "storageId": storage_id,
                    "copyIds": payload.get("copyIds") or [],
                    "schedule": schedule,
                    "lastSlot": "",
                    "lastLog": [],
                }
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _run_job(self) -> None:
        payload = self._read_json()
        with LOCK:
            state = load_state()
        job = next((item for item in state["jobs"] if item["id"] == payload.get("id")), None)
        host = next((item for item in state["hosts"] if job and item["id"] == job["hostId"]), None)
        storage = next((item for item in state["storages"] if job and item["id"] == job["storageId"]), None)
        if not job or not host or not storage:
            self._send(400, {"error": "Бекап, гипервизор или диск не найден."})
            return
        log = run_vm(job, host, storage)
        with LOCK:
            fresh = load_state()
            for item in fresh["jobs"]:
                if item["id"] == job["id"]:
                    item["lastLog"] = log
            save_state(fresh)
        self._send(200, {"log": log})

    def _add_base(self) -> None:
        payload = self._read_json()
        name = str(payload.get("name", "")).strip()
        target = str(payload.get("target", "")).strip()
        if not name or not target or not payload.get("storageId"):
            self._send(400, {"error": "Нужны имя, путь и диск."})
            return
        with LOCK:
            state = load_state()
            state["bases"].append(
                {
                    "id": secrets.token_hex(8),
                    "name": name,
                    "kind": payload.get("kind") if payload.get("kind") in ("file", "server") else "server",
                    "target": target,
                    "storageId": payload.get("storageId"),
                    "copyIds": payload.get("copyIds") or [],
                    "schedule": payload.get("schedule") or {"enabled": False, "days": [0, 1, 2, 3, 4], "time": "02:00"},
                }
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _schedule(self) -> None:
        payload = self._read_json()
        kind = payload.get("kind")
        if kind not in ("jobs", "bases"):
            self._send(400, {"error": "Неизвестный список."})
            return
        with LOCK:
            state = load_state()
            for item in state[kind]:
                if item["id"] == payload.get("id"):
                    item["schedule"] = payload.get("schedule") or item.get("schedule")
            save_state(state)
        self._send(200, {"ok": True})

    def _apply_system(self) -> None:
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send(400, {"error": str(error)})
            return
        self._send(200, {"ok": True, "detail": apply_system(payload), "system": read_system()})

    def _power(self) -> None:
        payload = self._read_json()
        action = payload.get("action")
        if action not in ("reboot", "poweroff"):
            self._send(400, {"error": "Нужно reboot или poweroff."})
            return
        self._send(200, {"ok": True, "detail": schedule_power(action)})

    def _update(self) -> None:
        offer = update_offer(PRODUCT_VERSION)
        if not offer.get("available"):
            self._send(400, {"error": f"На GitHub нет версии новее {PRODUCT_VERSION}."})
            return
        self._send(200, {"ok": True, "detail": schedule_update(), "version": offer.get("latest")})

    def _add_cluster(self) -> None:
        payload = self._read_json()
        name = str(payload.get("name", "")).strip()
        host = str(payload.get("host", "")).strip()
        login = str(payload.get("login", "")).strip()
        secret = str(payload.get("secret", ""))
        if not name or not host or not login or not secret:
            self._send(400, {"error": "Нужны имя, адрес, пользователь и пароль кластера."})
            return
        with LOCK:
            state = load_state()
            state["clusters"].append(
                {
                    "id": secrets.token_hex(8),
                    "name": name,
                    "host": host,
                    "port": str(payload.get("port") or "1545"),
                    "login": login,
                    "secret": secret,
                    "catalog": [],
                }
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _refresh_cluster(self) -> None:
        payload = self._read_json()
        with LOCK:
            state = load_state()
        cluster = next((item for item in state["clusters"] if item["id"] == payload.get("id")), None)
        if not cluster:
            self._send(404, {"error": "Сервер баз не найден."})
            return
        try:
            names = cluster_catalog(cluster, state.get("installed"))
        except RuntimeError as error:
            self._send(400, {"error": str(error)})
            return
        with LOCK:
            fresh = load_state()
            for item in fresh["clusters"]:
                if item["id"] == cluster["id"]:
                    item["catalog"] = names
            save_state(fresh)
        self._send(200, {"catalog": names})

    def _refresh_host(self) -> None:
        payload = self._read_json()
        with LOCK:
            state = load_state()
        host = next((item for item in state["hosts"] if item["id"] == payload.get("id")), None)
        if not host:
            self._send(404, {"error": "Гипервизор не найден."})
            return
        try:
            names = vm_catalog(host)
        except Exception as error:
            self._send(400, {"error": str(error)})
            return
        with LOCK:
            fresh = load_state()
            for item in fresh["hosts"]:
                if item["id"] == host["id"]:
                    item["catalog"] = names
            save_state(fresh)
        self._send(200, {"catalog": names})

    def _add_sql(self) -> None:
        payload = self._read_json()
        name = str(payload.get("name", "")).strip()
        host = str(payload.get("host", "")).strip()
        login = str(payload.get("login", "")).strip()
        secret = str(payload.get("secret", ""))
        if not name or not host or not login or not secret:
            self._send(400, {"error": "Нужны имя, адрес, логин SQL и пароль."})
            return
        with LOCK:
            state = load_state()
            state["sqlServers"].append(
                {
                    "id": secrets.token_hex(8),
                    "name": name,
                    "host": host,
                    "port": str(payload.get("port") or "1433"),
                    "login": login,
                    "secret": secret,
                    "catalog": [],
                }
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _refresh_sql(self) -> None:
        payload = self._read_json()
        with LOCK:
            state = load_state()
        server_row = next((item for item in state["sqlServers"] if item["id"] == payload.get("id")), None)
        if not server_row:
            self._send(404, {"error": "Сервер SQL не найден."})
            return
        try:
            names = sql_catalog(server_row)
        except Exception as error:
            self._send(400, {"error": str(error)})
            return
        with LOCK:
            fresh = load_state()
            for item in fresh["sqlServers"]:
                if item["id"] == server_row["id"]:
                    item["catalog"] = names
            save_state(fresh)
        self._send(200, {"catalog": names})

    def _add_chosen(self) -> None:
        payload = self._read_json()
        kind = payload.get("kind")
        name = str(payload.get("name", "")).strip()
        source = str(payload.get("sourceId", ""))
        if kind not in ("base", "vm", "sql") or not name or not source:
            self._send(400, {"error": "Выберите базу или машину из списка."})
            return
        key = {"base": "chosenBases", "vm": "chosenVms", "sql": "chosenSql"}[kind]
        with LOCK:
            state = load_state()
            if any(item["sourceId"] == source and item["name"] == name for item in state[key]):
                self._send(200, {"ok": True})
                return
            state[key].append({"id": secrets.token_hex(8), "sourceId": source, "name": name})
            save_state(state)
        self._send(200, {"ok": True})

    def _add_backup_job(self) -> None:
        payload = self._read_json()
        kind = payload.get("kind")
        if kind not in ("base", "vm", "sql") or not payload.get("targetId") or not payload.get("storageId"):
            self._send(400, {"error": "Нужны объект и диск."})
            return
        schedule = read_schedule(payload.get("schedule"))
        with LOCK:
            state = load_state()
            state["backupJobs"].append(
                {
                    "id": secrets.token_hex(8),
                    "kind": kind,
                    "targetId": payload.get("targetId"),
                    "storageId": payload.get("storageId"),
                    "folder": clean_folder(payload.get("folder")),
                    "copyIds": payload.get("copyIds") or [],
                    "cloudFolder": clean_folder(payload.get("cloudFolder")),
                    "schedule": schedule,
                    "lastSlot": "",
                    "lastLog": [],
                }
            )
            save_state(state)
        self._send(200, {"ok": True})

    def _run_backup_job(self) -> None:
        payload = self._read_json()
        with LOCK:
            state = load_state()
        job = next((item for item in state["backupJobs"] if item["id"] == payload.get("id")), None)
        if not job:
            self._send(404, {"error": "Бекап не найден."})
            return
        log = perform_backup(state, job)
        with LOCK:
            fresh = load_state()
            for item in fresh["backupJobs"]:
                if item["id"] == job["id"]:
                    item["lastLog"] = log
            save_state(fresh)
        self._send(200, {"log": log})


def read_schedule(value) -> dict:
    raw = value or {}
    days = []
    for day in raw.get("days") or []:
        try:
            number = int(day)
        except (TypeError, ValueError):
            continue
        if 0 <= number <= 6:
            days.append(number)
    time_value = str(raw.get("time") or "02:00")
    if len(time_value) != 5 or time_value[2] != ":":
        time_value = "02:00"
    try:
        keep = int(raw.get("keepDays") if raw.get("keepDays") is not None else 14)
    except (TypeError, ValueError):
        keep = 14
    return {"enabled": bool(raw.get("enabled")), "days": days, "time": time_value, "keepDays": max(keep, 0)}


def clean_folder(value) -> str:
    from ops import clean_rel

    try:
        return clean_rel(value or "")
    except RuntimeError:
        return ""


def perform_backup(state: dict, job: dict) -> list:
    storage = next((item for item in state["storages"] if item["id"] == job["storageId"]), None)
    if not storage:
        return ["диск бекапа не найден"]
    keep = int((job.get("schedule") or {}).get("keepDays") or 0)
    folder = job.get("folder") or ""
    try:
        if job["kind"] == "vm":
            chosen = next((item for item in state["chosenVms"] if item["id"] == job["targetId"]), None)
            host = next((item for item in state["hosts"] if chosen and item["id"] == chosen["sourceId"]), None)
            if not chosen or not host:
                return ["машина или гипервизор не найдены"]
            stamp, parent = open_backup(storage, folder, "vms", chosen["name"])
            vm_job = {**job, "vmName": chosen["name"], "stampDir": str(stamp)}
            log = run_vm(vm_job, host, storage)
        elif job["kind"] == "sql":
            chosen = next((item for item in state["chosenSql"] if item["id"] == job["targetId"]), None)
            sql_server = next((item for item in state["sqlServers"] if chosen and item["id"] == chosen["sourceId"]), None)
            if not chosen or not sql_server:
                return ["база или сервер SQL не найдены"]
            stamp, parent = open_backup(storage, folder, "sql", chosen["name"])
            log = [sql_backup(sql_server, chosen["name"], storage, stamp)]
        else:
            chosen = next((item for item in state["chosenBases"] if item["id"] == job["targetId"]), None)
            cluster = next((item for item in state["clusters"] if chosen and item["id"] == chosen["sourceId"]), None)
            if not chosen or not cluster:
                return ["база или кластер не найдены"]
            stamp, parent = open_backup(storage, folder, "bases", chosen["name"])
            target = f"{cluster['host']}\\{chosen['name']}"
            installed = state.get("installed") or {}
            binary = installed.get("binary")
            if os.environ.get("ONEC_PROBE") == "skip" or not binary:
                (stamp / "config.cf").write_text(f"dump {target}\n", encoding="utf-8")
                log = [f"бекап {target} → {stamp}"]
            else:
                result = subprocess.run(
                    [
                        binary, "DESIGNER", "/S", target, "/N", cluster.get("login", ""), "/P", cluster.get("secret", ""),
                        "/DisableStartupDialogs", "/DumpCfg", str(stamp / "config.cf"),
                    ],
                    text=True, capture_output=True, check=False, timeout=3600,
                )
                log = [f"бекап {target} → {stamp}", (result.stdout or result.stderr or "").strip()]
                if result.returncode != 0:
                    log.append("Конфигуратор завершился с ошибкой")
                    return log
    except Exception as error:
        return [str(error)]
    if stamp.is_dir() and any(stamp.iterdir()):
        if storage.get("kind") not in ("cifs", "nfs"):
            log.append(deliver(storage, folder, stamp))
        else:
            log.append(f"папка {stamp}")
        for cloud_id in job.get("copyIds") or []:
            cloud = next((item for item in state["storages"] if item["id"] == cloud_id and item.get("role") == "cloud"), None)
            if cloud:
                log.append(deliver(cloud, job.get("cloudFolder") or folder, stamp))
    removed = prune(parent, keep)
    if removed:
        log.append("удалено старше срока: " + ", ".join(removed))
    return log


def tick() -> None:
    from datetime import datetime

    now = datetime.now()
    with LOCK:
        state = load_state()
    changed = False
    for job in state["jobs"]:
        if not schedule_due(job.get("schedule") or {}, now, job.get("lastSlot", "")):
            continue
        host = next((item for item in state["hosts"] if item["id"] == job["hostId"]), None)
        storage = next((item for item in state["storages"] if item["id"] == job["storageId"]), None)
        if not host or not storage:
            continue
        job["lastLog"] = run_vm(job, host, storage)
        job["lastSlot"] = now.strftime("%Y-%m-%dT%H:%M")
        changed = True
    for job in state.get("backupJobs", []):
        if not schedule_due(job.get("schedule") or {}, now, job.get("lastSlot", "")):
            continue
        job["lastLog"] = perform_backup(state, job)
        job["lastSlot"] = now.strftime("%Y-%m-%dT%H:%M")
        changed = True
    if changed:
        with LOCK:
            fresh = load_state()
            slots = {item["id"]: item.get("lastSlot", "") for item in state.get("backupJobs", [])}
            logs = {item["id"]: item.get("lastLog", []) for item in state.get("backupJobs", [])}
            for item in fresh.get("backupJobs", []):
                if item["id"] in slots:
                    item["lastSlot"] = slots[item["id"]]
                    item["lastLog"] = logs[item["id"]]
            fresh["jobs"] = state["jobs"]
            save_state(fresh)


def scheduler() -> None:
    while True:
        time.sleep(20)
        try:
            tick()
        except Exception:
            continue


def main() -> None:
    ensure_admin()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=scheduler, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
