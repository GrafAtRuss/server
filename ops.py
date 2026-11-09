"""Storage mounts, cloud checks, and ESXi/vSphere power cycle."""

import http.client
import json
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

MOUNT_ROOT = Path(os.environ.get("ONEC_MOUNT_ROOT", "/mnt/onec-console"))
CTX = ssl._create_unverified_context()


def probe(item: dict) -> tuple[bool, str]:
    kind = item["kind"]
    if os.environ.get("ONEC_PROBE") == "skip":
        return True, "проверка отложена"
    try:
        if kind == "ftp":
            return probe_ftp(item["endpoint"], item.get("login", ""), item.get("secret", ""))
        if kind == "webdav":
            return probe_webdav(item["endpoint"], item.get("login", ""), item.get("secret", ""))
        if kind == "mail":
            return probe_webdav("https://webdav.cloud.mail.ru/", item.get("login", ""), item.get("secret", ""))
        if kind == "yandex":
            return probe_bearer("https://cloud-api.yandex.net/v1/disk/", f"OAuth {item.get('secret', '')}")
        if kind == "google":
            return probe_bearer("https://www.googleapis.com/drive/v3/about?fields=user", f"Bearer {item.get('secret', '')}")
        if kind in ("cifs", "nfs"):
            return mount_disk(item)
    except Exception as error:
        return False, str(error)
    return False, "неизвестный тип хранилища"


def probe_ftp(endpoint: str, login: str, secret: str) -> tuple[bool, str]:
    import ftplib

    host, port = split_host(endpoint, 21)
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=12)
    ftp.login(login or "anonymous", secret or "guest")
    ftp.nlst()
    ftp.quit()
    return True, f"FTP {host} отвечает"


def probe_webdav(url: str, login: str, secret: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, method="PROPFIND", headers={"Depth": "0"})
    if login or secret:
        token = b64encode(f"{login}:{secret}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(request, timeout=15, context=CTX) as response:
        return 200 <= response.status < 300, "WebDAV отвечает"


def probe_bearer(url: str, header: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"Authorization": header})
    with urllib.request.urlopen(request, timeout=15, context=CTX) as response:
        return response.status == 200, "облако отвечает"


def mount_disk(item: dict) -> tuple[bool, str]:
    target = MOUNT_ROOT / item["id"]
    target.mkdir(parents=True, exist_ok=True)
    if os.path.ismount(target):
        return True, str(target)
    if item["kind"] == "nfs":
        command = ["mount", "-t", "nfs", item["endpoint"], str(target)]
    else:
        cred = target.parent / f".{item['id']}.cred"
        cred.write_text(f"username={item.get('login', '')}\npassword={item.get('secret', '')}\n", encoding="utf-8")
        os.chmod(cred, 0o600)
        command = ["mount", "-t", "cifs", item["endpoint"], str(target), "-o", f"credentials={cred}"]
    result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "mount не выполнен").strip()
        return False, detail
    return True, str(target)


def split_host(endpoint: str, default_port: int) -> tuple[str, int]:
    host = endpoint.replace("ftp://", "").split("/")[0]
    if ":" in host:
        name, port = host.rsplit(":", 1)
        return name, int(port)
    return host, default_port


def public_copy(items: list) -> list:
    hidden = {"secret"}
    return [{key: value for key, value in item.items() if key not in hidden} for item in items]


def clean_rel(path: str) -> str:
    parts = []
    for part in str(path or "").replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise RuntimeError("путь вне хранилища")
        parts.append(part)
    return "/".join(parts)


def list_storage(item: dict, path: str) -> dict:
    rel = clean_rel(path)
    if os.environ.get("ONEC_PROBE") == "skip":
        child = f"{rel}/backup" if rel else "backup"
        return {"name": item.get("name", ""), "path": rel, "entries": [
            {"name": "backup", "kind": "dir", "size": None, "modified": "", "path": child},
        ]}
    kind = item.get("kind")
    if kind in ("cifs", "nfs"):
        listing = list_mounted(item, rel)
    elif kind == "ftp":
        listing = list_ftp(item, rel)
    elif kind in ("webdav", "mail"):
        listing = list_webdav(item, rel)
    elif kind == "yandex":
        listing = list_yandex(item, rel)
    elif kind == "google":
        listing = list_google(item, rel)
    else:
        raise RuntimeError("неизвестный тип хранилища")
    listing["name"] = item.get("name", "")
    listing["path"] = rel
    listing["entries"] = sorted(listing["entries"], key=lambda row: (row["kind"] != "dir", row["name"].lower()))[:500]
    return listing


def list_mounted(item: dict, rel: str) -> dict:
    ok, detail = mount_disk(item)
    if not ok:
        raise RuntimeError(detail)
    root = (MOUNT_ROOT / item["id"]).resolve()
    return {"entries": list_tree(root, rel)}


def list_tree(root: Path, rel: str) -> list:
    target = (root / rel).resolve() if rel else root
    if os.path.commonpath([str(root), str(target)]) != str(root):
        raise RuntimeError("путь вне хранилища")
    if not target.is_dir():
        raise RuntimeError("это не каталог")
    entries = []
    for child in target.iterdir():
        try:
            resolved = child.resolve()
            if os.path.commonpath([str(root), str(resolved)]) != str(root):
                continue
            stat = child.stat()
            is_dir = child.is_dir()
        except OSError:
            continue
        entries.append({
            "name": child.name,
            "kind": "dir" if is_dir else "file",
            "size": None if is_dir else stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="minutes"),
            "path": str(resolved.relative_to(root)) if is_dir else "",
        })
    return entries


def list_ftp(item: dict, rel: str) -> dict:
    import ftplib

    host, port = split_host(item["endpoint"], 21)
    root = ftp_dir(item["endpoint"])
    target = root if not rel else root.rstrip("/") + "/" + rel
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=20)
    ftp.login(item.get("login") or "anonymous", item.get("secret") or "anonymous@")
    ftp.cwd(target)
    entries = []
    try:
        for name, facts in ftp.mlsd():
            if name in (".", ".."):
                continue
            is_dir = facts.get("type") == "dir"
            size = facts.get("size")
            entries.append(entry(name, is_dir, size, facts.get("modify", ""), rel))
    except Exception:
        for name in ftp.nlst():
            base = name.rstrip("/").split("/")[-1]
            if base in (".", "..", ""):
                continue
            entries.append(entry(base, False, None, "", rel))
    ftp.quit()
    return {"entries": entries}


def ftp_dir(endpoint: str) -> str:
    raw = str(endpoint).replace("ftp://", "")
    tail = raw.split("/", 1)[1].strip("/") if "/" in raw else ""
    return "/" + tail if tail else "/"


def list_webdav(item: dict, rel: str) -> dict:
    base = webdav_base(item)
    url = join_url(base, rel)
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<d:propfind xmlns:d="DAV:"><d:prop>'
        "<d:displayname/><d:getcontentlength/><d:getlastmodified/><d:resourcetype/>"
        "</d:prop></d:propfind>"
    ).encode()
    request = urllib.request.Request(url, data=body, method="PROPFIND", headers={"Depth": "1", "Content-Type": "application/xml"})
    login = item.get("login", "")
    secret = item.get("secret", "")
    if login or secret:
        request.add_header("Authorization", "Basic " + b64encode(f"{login}:{secret}".encode()).decode())
    with urllib.request.urlopen(request, timeout=25, context=CTX) as response:
        payload = response.read()
    return {"entries": parse_webdav(payload, rel)}


def webdav_base(item: dict) -> str:
    if item.get("kind") == "mail":
        extra = str(item.get("endpoint", "")).strip("/")
        base = "https://webdav.cloud.mail.ru/"
        return base + extra + "/" if extra and not extra.startswith("http") else base
    return str(item.get("endpoint", ""))


def join_url(base: str, rel: str) -> str:
    root = base if base.endswith("/") else base + "/"
    if not rel:
        return root
    return root + "/".join(urllib.parse.quote(part) for part in rel.split("/"))


def parse_webdav(payload: bytes, rel: str) -> list:
    import xml.etree.ElementTree as ET

    tree = ET.fromstring(payload)
    entries = []
    responses = [node for node in tree.iter() if node.tag.split("}")[-1] == "response"]
    for index, node in enumerate(responses):
        if index == 0:
            continue
        name = text_of(node, "displayname")
        href = text_of(node, "href")
        if not name and href:
            name = urllib.parse.unquote(href.rstrip("/").split("/")[-1])
        if not name or name in (".", ".."):
            continue
        is_dir = any(child.tag.split("}")[-1] == "collection" for child in node.iter())
        entries.append(entry(name, is_dir, text_of(node, "getcontentlength"), text_of(node, "getlastmodified"), rel))
    return entries


def text_of(node, name: str) -> str:
    for child in node.iter():
        if child.tag.split("}")[-1] == name and child.text:
            return child.text.strip()
    return ""


def list_yandex(item: dict, rel: str) -> dict:
    disk = yandex_root(item.get("endpoint", ""))
    if rel:
        disk = disk.rstrip("/") + "/" + rel
    query = urllib.parse.urlencode({"path": disk, "limit": 200})
    request = urllib.request.Request(
        "https://cloud-api.yandex.net/v1/disk/resources?" + query,
        headers={"Authorization": f"OAuth {item.get('secret', '')}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:240]
        raise RuntimeError(f"Яндекс Диск {error.code}: {detail}") from error
    entries = []
    for row in (data.get("_embedded") or {}).get("items") or []:
        is_dir = row.get("type") == "dir"
        entries.append(entry(row.get("name") or "", is_dir, row.get("size"), row.get("modified", ""), rel))
    return {"entries": [row for row in entries if row["name"]]}


def yandex_root(endpoint: str) -> str:
    value = str(endpoint or "").strip()
    if value.startswith("disk:"):
        return value
    return "disk:/" + value.strip("/")


def list_google(item: dict, rel: str) -> dict:
    parent = rel or google_root(item.get("endpoint", ""))
    query = urllib.parse.urlencode({
        "q": f"'{parent}' in parents and trashed=false",
        "fields": "files(id,name,mimeType,size,modifiedTime)",
        "pageSize": 200,
        "orderBy": "folder,name",
    })
    request = urllib.request.Request(
        "https://www.googleapis.com/drive/v3/files?" + query,
        headers={"Authorization": f"Bearer {item.get('secret', '')}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:240]
        raise RuntimeError(f"Google Drive {error.code}: {detail}") from error
    entries = []
    for row in data.get("files") or []:
        is_dir = row.get("mimeType") == "application/vnd.google-apps.folder"
        entries.append({
            "name": row.get("name") or "",
            "kind": "dir" if is_dir else "file",
            "size": None if is_dir else int(row.get("size") or 0),
            "modified": row.get("modifiedTime") or "",
            "path": (row.get("id") or "") if is_dir else "",
        })
    return {"entries": [row for row in entries if row["name"]]}


def google_root(endpoint: str) -> str:
    value = str(endpoint or "").strip()
    if not value or value in ("/", "root"):
        return "root"
    return value


def entry(name: str, is_dir: bool, size, modified: str, rel: str) -> dict:
    next_path = f"{rel}/{name}".strip("/") if is_dir else ""
    number = None
    if not is_dir and size not in (None, ""):
        try:
            number = int(size)
        except (TypeError, ValueError):
            number = None
    return {"name": name, "kind": "dir" if is_dir else "file", "size": number, "modified": modified or "", "path": next_path}


def run_vm(job: dict, host: dict, storage: dict, step=None) -> list:
    log = []

    def note(percent: int, phase: str, line: str) -> None:
        log.append(line)
        if step:
            step(percent, phase, line)

    if os.environ.get("ONEC_VM") == "skip":
        note(30, "выключение", f"мягкое выключение {job['vmName']}")
        note(50, "выключена", "гость выключен")
        note(70, "копирование", f"бекап на {storage['name']}")
        note(90, "включение", "включение")
        return log
    turned_off = False
    control = None
    try:
        note(20, "подключение к гипервизору", f"подключение к {host.get('host', '')}")
        control = connect_host(host)
        note(30, "мягкое выключение", f"мягкое выключение {job['vmName']}")
        control.shutdown(job["vmName"])
        if not control.wait_off(job["vmName"]):
            note(100, "ошибка", "машина не выключилась за 3 минуты, бекап отменён")
            return log
        turned_off = True
        note(55, "машина выключена", "машина выключена")
        stamp_dir = Path(job["stampDir"]) if job.get("stampDir") else None
        if stamp_dir is None:
            folder = MOUNT_ROOT / storage["id"] / "vms" / safe_name(job["vmName"])
            stamp_dir = folder / datetime.now().strftime("%Y%m%d-%H%M%S")
            stamp_dir.mkdir(parents=True, exist_ok=True)
        stamp_dir.mkdir(parents=True, exist_ok=True)
        note_path = stamp_dir / "backup.txt"
        note_path.write_text(f"{job['vmName']} off, host {host['host']}\n", encoding="utf-8")
        note(65, "копирование файлов", f"отметка бекапа {note_path}")
        copied = copy_vm_files(host, job["vmName"], stamp_dir)
        note(80, "копирование файлов", copied)
    except Exception as error:
        note(100, "ошибка", str(error))
    finally:
        if turned_off and control:
            try:
                control.power_on(job["vmName"])
                note(90, "включение", f"включение {job['vmName']}")
            except Exception as error:
                note(90, "ошибка включения", f"не удалось включить: {error}")
    return log


def copy_vm_files(host: dict, vm_name: str, folder: Path) -> str:
    if not shutil_which("sshpass"):
        return "файлы ВМ не скопированы: нет sshpass, метка бекапа записана"
    target = f"{host['login']}@{host['host'].split('://')[-1].split('/')[0]}"
    remote = f"vim-cmd vmsvc/getallvms | awk -F '  +' -v n='{vm_name}' '$2==n {{print $4}}'"
    result = subprocess.run(
        ["sshpass", "-p", host["secret"], "ssh", "-o", "StrictHostKeyChecking=accept-new", target, remote],
        text=True,
        capture_output=True,
        check=False,
        timeout=40,
    )
    vmx = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 or not vmx:
        return "каталог ВМ на ESXi не найден, метка бекапа записана"
    directory = str(Path(vmx[0]).parent)
    archive = folder / "vm.tar"
    stream = subprocess.run(
        ["sshpass", "-p", host["secret"], "ssh", "-o", "StrictHostKeyChecking=accept-new", target, "tar", "-C", directory, "-cf", "-", "."],
        stdout=archive.open("wb"),
        stderr=subprocess.PIPE,
        check=False,
        timeout=3600,
    )
    if stream.returncode != 0:
        return "копия файлов ВМ не удалась"
    return f"файлы ВМ записаны в {archive}"


def shutil_which(name: str):
    from shutil import which

    return which(name)


def api_base(host: str) -> str:
    value = str(host).strip()
    if not value.startswith("http"):
        value = "https://" + value
    parts = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parts.scheme or "https", parts.netloc, "", "", ""))


def http_exchange(url: str, method: str, headers: dict, body: bytes = b"", keep_method: bool = False):
    current = url
    payload = body
    for _ in range(5):
        parts = urllib.parse.urlsplit(current)
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=25, context=CTX)
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=25)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(method, path, body=payload if payload is not None else None, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        location = response.getheader("Location")
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        cookies = [value for key, value in response.getheaders() if key.lower() == "set-cookie"]
        if cookies:
            response_headers["set-cookie"] = "; ".join(cookies)
        conn.close()
        if status in (301, 302, 303, 307, 308) and location:
            current = urllib.parse.urljoin(current, location)
            if not keep_method and status in (301, 302, 303):
                method = "GET"
                payload = None
            continue
        return status, raw, response_headers
    raise RuntimeError("слишком много перенаправлений")


def vsphere_login(base: str, login: str, secret: str, kind: str = "") -> tuple[str, str]:
    """Сессия vCenter 7 или ESXi. Пароль не теряется на переадресации."""
    secret = str(secret or "").replace("\ufeff", "").strip()
    errors = []
    for user in login_variants(login, kind):
        session, curl_errors = curl_login(base, user, secret)
        errors.extend(curl_errors)
        if session:
            return session
        token = b64encode(f"{user}:{secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {token}",
            "vmware-use-header-authn": "true",
            "Accept": "application/json",
        }
        for root, path in (("/api", "/session"), ("/rest", "/com/vmware/cis/session")):
            url = base.rstrip("/") + root + path
            try:
                status, raw, response_headers = http_exchange(url, "POST", headers, None, keep_method=True)
            except Exception as error:
                errors.append(f"{root} {user}: {error}")
                continue
            text = raw.decode("utf-8", "replace").strip()
            if status >= 400:
                errors.append(f"{root} {user} ответил {status}: {auth_detail(text)}")
                continue
            session_id = response_headers.get("vmware-api-session-id", "")
            if not session_id:
                session_id = json.loads(text) if text.startswith("{") or text.startswith('"') else text.strip('"')
            if isinstance(session_id, dict):
                session_id = session_id.get("value", "")
            if session_id:
                return str(session_id).strip('"'), root
            errors.append(f"{root} {user} не вернул сессию")
    raise RuntimeError("vCenter или ESXi не пустил (1.2.16): " + "; ".join(errors))


def auth_detail(text: str) -> str:
    if "authentication.invalid" in text or "Invalid credentials" in text or "incorrect user name" in text.lower():
        return "логин или пароль не приняты"
    if "authentication.required" in text or "Authentication required" in text:
        return "заголовок с паролем отклонён"
    compact = " ".join(text.split())
    return compact[:180] if compact else "пустой ответ"


def curl_login(base: str, login: str, secret: str):
    curl = shutil_which("curl")
    if not curl:
        return None, ["curl не установлен"]
    errors = []
    for path, root in (("/api/session", "/api"), ("/rest/com/vmware/cis/session", "/rest")):
        result = subprocess.run(
            [
                curl, "-sk", "--path-as-is", "--max-time", "20",
                "--location-trusted", "--post301", "--post302", "--post303",
                "-u", f"{login}:{secret}",
                "-H", "vmware-use-header-authn: true",
                "-H", "Accept: application/json",
                "-X", "POST",
                "-w", "\n%{http_code}", base.rstrip("/") + path,
            ],
            capture_output=True, text=True, timeout=25, check=False,
        )
        lines = (result.stdout or "").splitlines()
        code = lines[-1] if lines else ""
        raw = "\n".join(lines[:-1]).strip()
        if code != "200" or not raw:
            errors.append(f"curl {root} {code or result.returncode}: {auth_detail(raw or result.stderr or '')}")
            continue
        session = json.loads(raw) if raw.startswith("{") or raw.startswith('"') else raw.strip('"')
        if isinstance(session, dict):
            session = session.get("value", "")
        if session:
            return (str(session).strip('"'), root), []
    return None, errors


def login_variants(login: str, kind: str = "") -> list:
    login = str(login or "").replace("\ufeff", "").strip()
    names = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in names:
            names.append(value)

    if kind == "vsphere" and "@" not in login and "\\" not in login:
        add(f"{login}@vsphere.local")
        if login.lower() in ("root", "admin", "administrator"):
            add("administrator@vsphere.local")
        add(login)
        return names or [login]
    add(login)
    if "\\" in login:
        domain, user = login.split("\\", 1)
        add(f"{user}@{domain.lower()}")
    elif "@" in login:
        user, domain = login.split("@", 1)
        add(f"{user}@{domain.lower()}")
    return names or [login]


def login_names(login: str) -> list:
    return login_variants(login)


def list_vm_names(host: dict) -> list:
    return connect_host(host).names()


def connect_host(host: dict):
    base = api_base(host["host"])
    rest_error = ""
    kind = host.get("kind") or ""
    try:
        session, root = vsphere_login(base, host.get("login", ""), host.get("secret", ""), kind)
        return RestHost(base, root, session)
    except RuntimeError as error:
        rest_error = str(error)
    try:
        return SoapHost.login(base, host.get("login", ""), host.get("secret", ""), kind)
    except RuntimeError as error:
        secret = str(host.get("secret", "")).strip()
        hint = (
            f" Логин «{str(host.get('login', '')).strip()}», длина пароля {len(secret)}. "
            + (
                "Для vCenter 7 нужен логин administrator@vsphere.local и тип vSphere."
                if kind == "vsphere"
                else "Если это vCenter, а не ESXi, выберите тип vSphere и логин administrator@vsphere.local."
            )
        )
        raise RuntimeError(f"{rest_error}. {error}.{hint}") from error


class RestHost:
    def __init__(self, base: str, root: str, session: str):
        self.base = base
        self.root = root
        self.session = session
        self.vm_id = ""

    def names(self) -> list:
        payload = api(self.base, self.root, self.session, "/vcenter/vm")
        rows = payload.get("value", payload) if isinstance(payload, dict) else payload
        return [row.get("name") for row in rows or [] if isinstance(row, dict) and row.get("name")]

    def shutdown(self, name: str) -> None:
        self.vm_id = find_vm(self.base, self.root, self.session, name)
        api(self.base, self.root, self.session, f"/vcenter/vm/{self.vm_id}/guest/power?action=shutdown", method="POST")

    def wait_off(self, name: str) -> bool:
        return wait_off(self.base, self.root, self.session, self.vm_id)

    def power_on(self, name: str) -> None:
        api(self.base, self.root, self.session, f"/vcenter/vm/{self.vm_id}/power?action=start", method="POST")


class SoapHost:
    def __init__(self, base: str, cookie: str, collector: str, view_manager: str, root_folder: str, action: str):
        self.base = base
        self.cookie = cookie
        self.collector = collector
        self.view_manager = view_manager
        self.root_folder = root_folder
        self.action = action
        self.style = "plain"
        self.morefs = {}

    @classmethod
    def login(cls, base: str, login: str, secret: str, kind: str = ""):
        content = ""
        action = ""
        errors = []
        chosen = ""
        for style in ("plain", "prefixed"):
            for candidate in ('"urn:vim25/7.0"', '"urn:vim25/6.7"', '"urn:vim25/8.0"', "urn:vim25"):
                try:
                    content, _ = soap_call(
                        base,
                        "<urn:RetrieveServiceContent><urn:_this type=\"ServiceInstance\">ServiceInstance</urn:_this></urn:RetrieveServiceContent>",
                        action=candidate,
                        style=style,
                    )
                except RuntimeError as error:
                    errors.append(str(error))
                    continue
                if soap_value(content, "sessionManager"):
                    action = candidate
                    chosen = style
                    break
            if action:
                break
        if not action:
            raise RuntimeError(errors[-1] if errors else "ESXi SOAP не ответил")
        collector = soap_value(content, "propertyCollector")
        view_manager = soap_value(content, "viewManager") or "ViewManager"
        root_folder = soap_value(content, "rootFolder") or "ha-folder-root"
        session_manager = soap_value(content, "sessionManager")
        if not collector or not session_manager:
            raise RuntimeError("ESXi SOAP не отдал службу входа")
        secret = str(secret or "").replace("\ufeff", "").strip()
        users = login_variants(login, kind)
        login_error = ""
        for user in users:
            body = (
                "<urn:Login>"
                f"<urn:_this type=\"SessionManager\">{xml_escape(session_manager)}</urn:_this>"
                f"<urn:userName>{xml_escape(user)}</urn:userName>"
                f"<urn:password>{xml_escape(secret)}</urn:password>"
                "</urn:Login>"
            )
            try:
                _, cookie = soap_call(base, body, action=action, style="plain")
            except RuntimeError as error:
                login_error = f"{user}: {error}"
                if "incorrect user name" in str(error).lower() or "не принят" in str(error).lower():
                    continue
                break
            if "vmware_soap_session" in cookie.lower():
                host = cls(base, cookie, collector, view_manager, root_folder, action)
                host.style = "plain"
                return host
            login_error = f"{user}: сессия не выдана"
        raise RuntimeError(login_error or "vCenter SOAP не открыл сессию")

    def names(self) -> list:
        self.morefs = soap_vm_map(self)
        return list(self.morefs)

    def shutdown(self, name: str) -> None:
        moref = self.moref(name)
        soap_call(self.base, f"<urn:ShutdownGuest><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:ShutdownGuest>", self.cookie, self.action, self.style)

    def wait_off(self, name: str) -> bool:
        moref = self.moref(name)
        deadline = time.time() + 180
        while time.time() < deadline:
            if soap_power(self, moref) == "poweredOff":
                return True
            time.sleep(5)
        return False

    def power_on(self, name: str) -> None:
        moref = self.moref(name)
        soap_call(self.base, f"<urn:PowerOnVM_Task><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:PowerOnVM_Task>", self.cookie, self.action, self.style)

    def moref(self, name: str) -> str:
        if name not in self.morefs:
            self.morefs = soap_vm_map(self)
        if name not in self.morefs:
            raise RuntimeError(f"машина {name} не найдена")
        return self.morefs[name]


def soap_call(base: str, body: str, cookie: str = "", action: str = '"urn:vim25/7.0"', style: str = "plain") -> tuple[str, str]:
    fragment = body
    if style == "plain":
        fragment = body.replace("<urn:", "<").replace("</urn:", "</")
        fragment = re.sub(r"^(\s*<)(\w+)", r'\1\2 xmlns="urn:vim25"', fragment, count=1)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:urn="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<soapenv:Body>{fragment}</soapenv:Body></soapenv:Envelope>"
    ).encode()
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": action}
    if cookie:
        headers["Cookie"] = cookie.split(";", 1)[0]
    status, raw, response_headers = http_exchange(base.rstrip("/") + "/sdk", "POST", headers, xml, keep_method=True)
    payload = raw.decode("utf-8", "replace")
    fault = soap_fault(payload)
    if status >= 400 or fault:
        raise RuntimeError(fault or f"ESXi SOAP {status}")
    return payload, response_headers.get("set-cookie", "") or cookie


def soap_fault(payload: str) -> str:
    match = re.search(r"<(?:\w+:)?faultstring[^>]*>(.*?)</(?:\w+:)?faultstring>", payload, re.S)
    return match.group(1).strip() if match else ""


def soap_value(payload: str, tag: str) -> str:
    match = re.search(rf"<(?:\w+:)?{tag}[^>]*>([^<]+)", payload)
    return match.group(1).strip() if match else ""


def soap_vm_map(host: SoapHost) -> dict:
    created, _ = soap_call(
        host.base,
        "<urn:CreateContainerView>"
        f"<urn:_this type=\"ViewManager\">{xml_escape(host.view_manager)}</urn:_this>"
        f"<urn:container type=\"Folder\">{xml_escape(host.root_folder)}</urn:container>"
        "<urn:type>VirtualMachine</urn:type><urn:recursive>true</urn:recursive>"
        "</urn:CreateContainerView>",
        host.cookie,
        host.action,
        host.style,
    )
    view = soap_value(created, "returnval")
    if not view:
        raise RuntimeError("ESXi не отдал список машин")
    props, _ = soap_call(
        host.base,
        "<urn:RetrieveProperties>"
        f"<urn:_this type=\"PropertyCollector\">{xml_escape(host.collector)}</urn:_this>"
        "<urn:specSet><urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>name</urn:pathSet></urn:propSet>"
        f"<urn:objectSet><urn:obj type=\"ContainerView\">{xml_escape(view)}</urn:obj><urn:skip>true</urn:skip>"
        '<urn:selectSet xsi:type="urn:TraversalSpec"><urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet>'
        "</urn:objectSet></urn:specSet></urn:RetrieveProperties>",
        host.cookie,
        host.action,
        host.style,
    )
    found = {}
    for block in re.findall(r"<(?:\w+:)?returnval>(.*?)</(?:\w+:)?returnval>", props, re.S):
        moref = re.search(r'type="VirtualMachine"[^>]*>([^<]+)', block)
        name = re.search(r"<(?:\w+:)?val[^>]*>([^<]+)", block)
        if moref and name:
            found[name.group(1).strip()] = moref.group(1).strip()
    return found


def soap_power(host: SoapHost, moref: str) -> str:
    payload, _ = soap_call(
        host.base,
        "<urn:RetrieveProperties>"
        f"<urn:_this type=\"PropertyCollector\">{xml_escape(host.collector)}</urn:_this>"
        "<urn:specSet><urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>runtime.powerState</urn:pathSet></urn:propSet>"
        f"<urn:objectSet><urn:obj type=\"VirtualMachine\">{xml_escape(moref)}</urn:obj></urn:objectSet></urn:specSet>"
        "</urn:RetrieveProperties>",
        host.cookie,
        host.action,
        host.style,
    )
    return soap_value(payload, "val")


def api(base: str, root: str, session: str, path: str, method="GET"):
    status, raw, _ = http_exchange(
        base.rstrip("/") + root + path,
        method,
        {"vmware-api-session-id": session, "Accept": "application/json"},
        b"" if method != "GET" else None,
        keep_method=method != "GET",
    )
    body = raw.decode("utf-8", "replace")
    if status >= 400:
        raise RuntimeError(f"vSphere {status}: {auth_detail(body)}")
    if not body:
        return None
    return json.loads(body)


def find_vm(base: str, root: str, session: str, name: str) -> str:
    payload = api(base, root, session, "/vcenter/vm")
    rows = payload.get("value", payload) if isinstance(payload, dict) else payload
    for row in rows or []:
        if row.get("name") == name:
            return row["vm"]
    raise RuntimeError(f"машина {name} не найдена")


def wait_off(base: str, root: str, session: str, vm_id: str) -> bool:
    deadline = time.time() + 180
    while time.time() < deadline:
        payload = api(base, root, session, f"/vcenter/vm/{vm_id}/power")
        state = payload.get("state") if isinstance(payload, dict) and "state" in payload else payload.get("value", {}).get("state")
        if state == "POWERED_OFF":
            return True
        time.sleep(5)
    return False


def safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_." else "_" for char in value)
    return cleaned or "vm"


def deliver(storage: dict, remote_folder: str, stamp: Path) -> str:
    if os.environ.get("ONEC_PROBE") == "skip":
        return f"копия {stamp.name} отложена"
    try:
        rel = f"{clean_rel(remote_folder)}/{stamp.name}".strip("/")
        kind = storage.get("kind")
        if kind in ("cifs", "nfs"):
            return f"записано в {stamp}"
        if kind == "ftp":
            upload_ftp_tree(storage, rel, stamp)
        elif kind in ("webdav", "mail"):
            upload_webdav_tree(storage, rel, stamp)
        elif kind == "yandex":
            upload_yandex_tree(storage, rel, stamp)
        elif kind == "google":
            upload_google_tree(storage, rel, stamp)
        else:
            return "копия не отправлена: неизвестный тип"
        return f"копия в {storage.get('name')} / {rel}"
    except Exception as error:
        return f"копия не ушла: {error}"


def upload_ftp_tree(item: dict, remote: str, stamp: Path) -> None:
    import ftplib

    host, port = split_host(item["endpoint"], 21)
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=30)
    ftp.login(item.get("login") or "anonymous", item.get("secret") or "anonymous@")
    root = ftp_dir(item["endpoint"]).rstrip("/")
    for file in stamp.rglob("*"):
        if not file.is_file():
            continue
        rel = f"{remote}/{file.relative_to(stamp).as_posix()}"
        ftp_mkdirs(ftp, f"{root}/{rel}".rsplit("/", 1)[0])
        with file.open("rb") as handle:
            ftp.storbinary(f"STOR {root}/{rel}", handle)
    ftp.quit()


def ftp_mkdirs(ftp, path: str) -> None:
    built = ""
    for part in path.split("/"):
        if not part:
            continue
        built += "/" + part
        try:
            ftp.mkd(built)
        except Exception:
            continue


def upload_webdav_tree(item: dict, remote: str, stamp: Path) -> None:
    for file in stamp.rglob("*"):
        if not file.is_file():
            continue
        rel = f"{remote}/{file.relative_to(stamp).as_posix()}"
        webdav_mkcol(item, rel.rsplit("/", 1)[0])
        data = file.read_bytes()
        request = urllib.request.Request(join_url(webdav_base(item), rel), data=data, method="PUT")
        webdav_auth(request, item)
        with urllib.request.urlopen(request, timeout=120, context=CTX):
            pass


def webdav_mkcol(item: dict, rel: str) -> None:
    built = []
    for part in rel.split("/"):
        if not part:
            continue
        built.append(part)
        request = urllib.request.Request(join_url(webdav_base(item), "/".join(built)), method="MKCOL")
        webdav_auth(request, item)
        try:
            with urllib.request.urlopen(request, timeout=20, context=CTX):
                pass
        except urllib.error.HTTPError as error:
            if error.code not in (301, 405, 409):
                raise


def webdav_auth(request, item: dict) -> None:
    login = item.get("login", "")
    secret = item.get("secret", "")
    if login or secret:
        request.add_header("Authorization", "Basic " + b64encode(f"{login}:{secret}".encode()).decode())


def upload_yandex_tree(item: dict, remote: str, stamp: Path) -> None:
    token = item.get("secret", "")
    root = yandex_root(item.get("endpoint", "")).rstrip("/")
    for file in stamp.rglob("*"):
        if not file.is_file():
            continue
        disk_path = f"{root}/{remote}/{file.relative_to(stamp).as_posix()}"
        yandex_mkdir(token, disk_path.rsplit("/", 1)[0])
        href = yandex_href(token, disk_path)
        request = urllib.request.Request(href, data=file.read_bytes(), method="PUT")
        with urllib.request.urlopen(request, timeout=120):
            pass


def yandex_mkdir(token: str, path: str) -> None:
    query = urllib.parse.urlencode({"path": path})
    request = urllib.request.Request(
        "https://cloud-api.yandex.net/v1/disk/resources?" + query,
        method="PUT",
        headers={"Authorization": f"OAuth {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20):
            pass
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise


def yandex_href(token: str, path: str) -> str:
    query = urllib.parse.urlencode({"path": path, "overwrite": "true"})
    request = urllib.request.Request(
        "https://cloud-api.yandex.net/v1/disk/resources/upload?" + query,
        headers={"Authorization": f"OAuth {token}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())["href"]


def upload_google_tree(item: dict, remote: str, stamp: Path) -> None:
    token = item.get("secret", "")
    parent = google_root(item.get("endpoint", ""))
    for part in [part for part in clean_rel(remote).split("/") if part]:
        parent = google_folder(token, parent, part)
    for file in stamp.rglob("*"):
        if not file.is_file():
            continue
        folder = parent
        for part in file.parent.relative_to(stamp).parts:
            folder = google_folder(token, folder, part)
        google_upload(token, folder, file)


def google_folder(token: str, parent: str, name: str) -> str:
    safe = name.replace("'", "")
    query = urllib.parse.urlencode({
        "q": f"name='{safe}' and '{parent}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false",
        "fields": "files(id)",
    })
    request = urllib.request.Request(
        "https://www.googleapis.com/drive/v3/files?" + query,
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        found = json.loads(response.read().decode()).get("files") or []
    if found:
        return found[0]["id"]
    body = json.dumps({"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent]}).encode()
    request = urllib.request.Request(
        "https://www.googleapis.com/drive/v3/files",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())["id"]


def google_upload(token: str, parent: str, file: Path) -> None:
    boundary = "onecboundary"
    meta = json.dumps({"name": file.name, "parents": [parent]}).encode()
    body = (
        f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode()
        + meta
        + f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
        + file.read_bytes()
        + f"\r\n--{boundary}--".encode()
    )
    request = urllib.request.Request(
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": f"multipart/related; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=120):
        pass


def schedule_due(schedule: dict, now: datetime, last_slot: str) -> bool:
    if not schedule or not schedule.get("enabled"):
        return False
    slot = now.strftime("%Y-%m-%dT%H:%M")
    if last_slot == slot or now.strftime("%H:%M") != schedule.get("time"):
        return False
    return now.weekday() in schedule.get("days", [])
