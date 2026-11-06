#!/usr/bin/env python3
"""Console that installs 1C platform packages from vendor zip archives."""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ops import probe, public_copy, run_vm, schedule_due

PRODUCT_VERSION = "1.1.0"

STATE_DIR = Path(os.environ.get("ONEC_STATE_DIR", "/var/lib/onec-console"))
CACHE_DIR = Path(os.environ.get("ONEC_CACHE_DIR", "/var/cache/onec-platform"))
PASSWORD_FILE = Path(os.environ.get("ONEC_PASSWORD_FILE", "/etc/onec-console/initial-password"))
HOST = os.environ.get("ONEC_HOST", "0.0.0.0")
PORT = int(os.environ.get("ONEC_PORT", "8780"))
HERE = Path(__file__).resolve().parent
MAX_UPLOAD = 2_000_000_000

INSTALL_ORDER = ("common", "common-nls", "server", "server-nls", "client", "client-nls")
SKIP_REASON = {
    "thin-client": "Тонкий клиент не содержит Конфигуратор",
    "thin-client-nls": "Языковой пакет тонкого клиента не нужен",
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
            steps.append({**item, "action": "install", "reason": "Нужен для Конфигуратора и сервера"})
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
    for kind in ("server", "client"):
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
        return user

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            page = (HERE / "index.html").read_bytes()
            self._send(200, page, "text/html; charset=utf-8")
            return
        with LOCK:
            state = load_state()
        if path == "/api/state":
            user = self._guard(state)
            if not user:
                return
            public_users = [
                {"login": item["login"], "name": item["name"], "mustChange": item["mustChange"]}
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
                },
            )
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
            for key in ("users", "sessions", "storages", "hosts", "jobs", "bases"):
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
        if not login or not name or len(password) < 8:
            self._send(400, {"error": "Логин, имя и пароль от 8 символов."})
            return
        if any(item["login"] == login for item in state["users"]):
            self._send(400, {"error": "Такой логин уже есть."})
            return
        salt = secrets.token_hex(16)
        state["users"].append(
            {"login": login, "name": name, "salt": salt, "passHash": pbkdf2(password, salt), "mustChange": False}
        )
        with LOCK:
            fresh = load_state()
            if any(item["login"] == login for item in fresh["users"]):
                self._send(400, {"error": "Такой логин уже есть."})
                return
            fresh["users"].append(state["users"][-1])
            save_state(fresh)
        self._send(200, {"ok": True})

    def _upload(self, state) -> None:
        query = parse_qs(urlparse(self.path).query)
        kind = query.get("kind", [""])[0]
        if kind not in ("server", "client"):
            self._send(400, {"error": "Нужен kind=server или kind=client."})
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
        for kind in ("server", "client"):
            slot = state["archives"][kind]
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
                {"id": secrets.token_hex(8), "kind": kind, "name": name, "host": host, "login": login, "secret": secret}
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
    if changed:
        with LOCK:
            fresh = load_state()
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
