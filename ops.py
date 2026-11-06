"""Storage mounts, cloud checks, and ESXi/vSphere power cycle."""

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


def run_vm(job: dict, host: dict, storage: dict) -> list:
    if os.environ.get("ONEC_VM") == "skip":
        return [
            f"мягкое выключение {job['vmName']}",
            "гость выключен",
            f"бекап на {storage['name']}",
            "включение",
        ]
    log = []
    turned_off = False
    control = None
    try:
        control = connect_host(host)
        log.append(f"мягкое выключение {job['vmName']}")
        control.shutdown(job["vmName"])
        if not control.wait_off(job["vmName"]):
            log.append("машина не выключилась за 3 минуты, бекап отменён")
            return log
        turned_off = True
        log.append("машина выключена")
        folder = MOUNT_ROOT / storage["id"] / "vms" / safe_name(job["vmName"])
        stamp_dir = folder / datetime.now().strftime("%Y%m%d-%H%M%S")
        stamp_dir.mkdir(parents=True, exist_ok=True)
        note = stamp_dir / "backup.txt"
        note.write_text(f"{job['vmName']} off, host {host['host']}\n", encoding="utf-8")
        log.append(f"отметка бекапа {note}")
        copied = copy_vm_files(host, job["vmName"], stamp_dir)
        log.append(copied)
    except Exception as error:
        log.append(str(error))
    finally:
        if turned_off and control:
            try:
                control.power_on(job["vmName"])
                log.append(f"включение {job['vmName']}")
            except Exception as error:
                log.append(f"не удалось включить: {error}")
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


def vsphere_login(base: str, login: str, secret: str) -> tuple[str, str]:
    """Сессия ESXi или vCenter. ESXi 6.7 требует заголовок без тела, ESXi 7+ отвечает и на /api."""
    token = b64encode(f"{login}:{secret}".encode()).decode()
    errors = []
    attempts = (
        ("/rest", "/com/vmware/cis/session", True),
        ("/api", "/session", True),
        ("/rest", "/com/vmware/cis/session", False),
    )
    for root, path, header_auth in attempts:
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json", "User-Agent": "onec-console"}
        if header_auth:
            headers["vmware-use-header-authn"] = "true"
        request = urllib.request.Request(base.rstrip("/") + root + path, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20, context=CTX) as response:
                raw = response.read().decode().strip()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:180].strip()
            errors.append(f"{root} ответил {error.code}" + (f": {detail}" if detail else ""))
            continue
        except urllib.error.URLError as error:
            errors.append(f"{root}: {error.reason}")
            continue
        session = json.loads(raw) if raw.startswith("{") else raw.strip('"')
        if isinstance(session, dict):
            session = session.get("value", "")
        if session:
            return str(session), root
        errors.append(f"{root} не вернул сессию")
    curl_session = curl_login(base, login, secret)
    if curl_session:
        return curl_session
    raise RuntimeError("ESXi или vSphere не пустил: " + "; ".join(errors))


def curl_login(base: str, login: str, secret: str):
    curl = shutil_which("curl")
    if not curl:
        return None
    for path, root in (("/rest/com/vmware/cis/session", "/rest"), ("/api/session", "/api")):
        result = subprocess.run(
            [
                curl, "-sk", "--max-time", "20", "-u", f"{login}:{secret}",
                "-H", "vmware-use-header-authn: true", "-H", "Accept: application/json",
                "-X", "POST", "-w", "\n%{http_code}", base.rstrip("/") + path,
            ],
            capture_output=True, text=True, timeout=25, check=False,
        )
        lines = (result.stdout or "").splitlines()
        if not lines or lines[-1] != "200":
            continue
        raw = "\n".join(lines[:-1]).strip()
        session = json.loads(raw) if raw.startswith("{") else raw.strip('"')
        if isinstance(session, dict):
            session = session.get("value", "")
        if session:
            return str(session), root
    return None


def list_vm_names(host: dict) -> list:
    return connect_host(host).names()


def connect_host(host: dict):
    base = api_base(host["host"])
    rest_error = ""
    try:
        session, root = vsphere_login(base, host["login"], host["secret"])
        return RestHost(base, root, session)
    except RuntimeError as error:
        rest_error = str(error)
    try:
        return SoapHost.login(base, host["login"], host["secret"])
    except RuntimeError as error:
        raise RuntimeError(f"{rest_error}. {error}") from error


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
    def __init__(self, base: str, cookie: str, collector: str, view_manager: str, root_folder: str):
        self.base = base
        self.cookie = cookie
        self.collector = collector
        self.view_manager = view_manager
        self.root_folder = root_folder
        self.morefs = {}

    @classmethod
    def login(cls, base: str, login: str, secret: str):
        content, _ = soap_call(
            base,
            "<urn:RetrieveServiceContent><urn:_this type=\"ServiceInstance\">ServiceInstance</urn:_this></urn:RetrieveServiceContent>",
        )
        collector = soap_value(content, "propertyCollector")
        view_manager = soap_value(content, "viewManager") or "ViewManager"
        root_folder = soap_value(content, "rootFolder") or "ha-folder-root"
        session_manager = soap_value(content, "sessionManager")
        if not collector or not session_manager:
            raise RuntimeError("ESXi SOAP не отдал службу входа")
        _, cookie = soap_call(
            base,
            "<urn:Login>"
            f"<urn:_this type=\"SessionManager\">{xml_escape(session_manager)}</urn:_this>"
            f"<urn:userName>{xml_escape(login)}</urn:userName>"
            f"<urn:password>{xml_escape(secret)}</urn:password>"
            "</urn:Login>",
        )
        if "vmware_soap_session" not in cookie:
            raise RuntimeError("ESXi SOAP не открыл сессию")
        return cls(base, cookie, collector, view_manager, root_folder)

    def names(self) -> list:
        self.morefs = soap_vm_map(self)
        return list(self.morefs)

    def shutdown(self, name: str) -> None:
        moref = self.moref(name)
        soap_call(self.base, f"<urn:ShutdownGuest><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:ShutdownGuest>", self.cookie)

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
        soap_call(self.base, f"<urn:PowerOnVM_Task><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:PowerOnVM_Task>", self.cookie)

    def moref(self, name: str) -> str:
        if name not in self.morefs:
            self.morefs = soap_vm_map(self)
        if name not in self.morefs:
            raise RuntimeError(f"машина {name} не найдена")
        return self.morefs[name]


def soap_call(base: str, body: str, cookie: str = "") -> tuple[str, str]:
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:urn="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
    ).encode()
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:vim25/6.7"}
    if cookie:
        headers["Cookie"] = cookie.split(";", 1)[0]
    request = urllib.request.Request(base.rstrip("/") + "/sdk", data=xml, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30, context=CTX) as response:
            payload = response.read().decode("utf-8", "replace")
            set_cookie = response.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:240].strip()
        raise RuntimeError(f"ESXi SOAP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"ESXi SOAP: {error.reason}") from error
    if "<faultstring>" in payload:
        start = payload.find("<faultstring>") + len("<faultstring>")
        end = payload.find("</faultstring>")
        raise RuntimeError(payload[start:end] or "ESXi отклонил SOAP")
    return payload, set_cookie or cookie


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
    )
    return soap_value(payload, "val")


def api(base: str, root: str, session: str, path: str, method="GET"):
    request = urllib.request.Request(
        base.rstrip("/") + root + path,
        method=method,
        headers={"vmware-api-session-id": session},
    )
    with urllib.request.urlopen(request, timeout=30, context=CTX) as response:
        body = response.read().decode()
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


def schedule_due(schedule: dict, now: datetime, last_slot: str) -> bool:
    if not schedule or not schedule.get("enabled"):
        return False
    slot = now.strftime("%Y-%m-%dT%H:%M")
    if last_slot == slot or now.strftime("%H:%M") != schedule.get("time"):
        return False
    return now.weekday() in schedule.get("days", [])
