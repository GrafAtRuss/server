"""Storage mounts, cloud checks, and ESXi/vSphere power cycle."""

import http.client
import json
import os
import re
import signal
import ssl
import subprocess
import threading
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
CANCELLED = set()
PROCESSES = {}
CONNECTIONS = {}
CANCEL_LOCK = threading.Lock()
CURRENT_JOB = threading.local()


class Stopped(Exception):
    pass


def bind_job(job_id: str) -> None:
    CURRENT_JOB.id = job_id
    with CANCEL_LOCK:
        CANCELLED.discard(job_id)


def current_job() -> str:
    return getattr(CURRENT_JOB, "id", "") or ""


def job_stopped(job_id: str = "") -> bool:
    job_id = job_id or current_job()
    return bool(job_id) and job_id in CANCELLED


def track_proc(proc) -> None:
    job_id = current_job()
    if not job_id or proc is None:
        return
    with CANCEL_LOCK:
        PROCESSES.setdefault(job_id, []).append(proc)


def untrack_proc(proc) -> None:
    job_id = current_job()
    with CANCEL_LOCK:
        rows = PROCESSES.get(job_id, [])
        if proc in rows:
            rows.remove(proc)


def track_conn(connection) -> None:
    job_id = current_job()
    if not job_id or connection is None:
        return
    with CANCEL_LOCK:
        CONNECTIONS.setdefault(job_id, []).append(connection)


def untrack_conn(connection) -> None:
    job_id = current_job()
    with CANCEL_LOCK:
        rows = CONNECTIONS.get(job_id, [])
        if connection in rows:
            rows.remove(connection)


def kill_proc(proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return
    try:
        proc.wait(timeout=3)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def stop_job(job_id: str) -> None:
    with CANCEL_LOCK:
        CANCELLED.add(job_id)
        procs = list(PROCESSES.get(job_id, []))
        conns = list(CONNECTIONS.get(job_id, []))
    for proc in procs:
        kill_proc(proc)
    for connection in conns:
        try:
            connection.close()
        except Exception:
            pass


def check_job() -> None:
    if job_stopped():
        raise Stopped("резервное копирование прервано")


def run_job(args, timeout=None, **kwargs):
    if kwargs.pop("capture_output", False):
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    kwargs.pop("check", None)
    proc = subprocess.Popen(args, start_new_session=True, **kwargs)
    return run_job_proc(proc, timeout)


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
    hidden = {"secret", "fileSecret"}
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


def timed_out(error: Exception) -> bool:
    text = str(error).lower()
    return isinstance(error, TimeoutError) or "timed out" in text or "timeout" in text


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
    requested_off = False
    control = None
    failed = ""
    try:
        note(20, "подключение к гипервизору", f"подключение к {host.get('host', '')}")
        control = connect_host(host)
        note(30, "мягкое выключение", f"мягкое выключение {job['vmName']}")

        def waiting(elapsed: int) -> None:
            note(40, "жду выключения", f"жду выключения, {elapsed} с")

        try:
            control.shutdown(job["vmName"])
            requested_off = True
        except Stopped:
            requested_off = True
            raise
        except Exception as error:
            requested_off = True
            if timed_out(error):
                note(35, "жду выключения", "запрос выключения отправлен, ответ гипервизора не дождались и проверяю состояние")
            else:
                note(35, "выключение питанием", f"мягкое выключение не принято: {error}. Выключаю питанием.")
                control.power_off(job["vmName"])
        if not control.wait_off(job["vmName"], seconds=600, tick=waiting):
            note(45, "выключение питанием", "мягкое выключение не завершилось, выключаю питанием")
            control.power_off(job["vmName"])
            if not control.wait_off(job["vmName"], seconds=120, tick=waiting):
                failed = "машина не выключилась, бекап отменён"
                note(100, "ошибка", failed)
            else:
                turned_off = True
        else:
            turned_off = True
        if turned_off:
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
            copied = copy_vm_files(host, job["vmName"], stamp_dir, control, lambda line: note(70, "копирование файлов", line), storage, job.get("id", ""))
            if str(copied).startswith("файлы ВМ записаны"):
                note(80, "копирование файлов", copied)
            else:
                failed = copied
                note(100, "ошибка", copied)
    except Stopped:
        raise
    except Exception as error:
        failed = str(error)
        note(100, "ошибка", failed)
    finally:
        if requested_off and control:
            try:
                control.power_on(job["vmName"])
                note(90, "включение", f"включение {job['vmName']}")
            except Exception as error:
                note(90, "ошибка включения", f"не удалось включить: {error}")
    if failed:
        error = RuntimeError(failed)
        error.log = log
        raise error
    return log


def ssh_host(host: dict) -> str:
    login = str(host.get("login", ""))
    address = str(host.get("host", "")).split("://")[-1].split("/")[0].split(":")[0]
    return f"{login}@{address}"


def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def ssh_exec(host: dict, command: str, timeout: int = 60, stdout=None, stdin=None):
    proc = subprocess.Popen(
        [
            "sshpass", "-p", str(host.get("secret", "")),
            "ssh", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "PreferredAuthentications=password",
            ssh_host(host),
            command,
        ],
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=stdin,
        start_new_session=True,
    )
    return run_job_proc(proc, timeout)


def run_job_proc(proc, timeout=None):
    track_proc(proc)
    started = time.time()
    try:
        while proc.poll() is None:
            if job_stopped():
                kill_proc(proc)
                raise Stopped("резервное копирование прервано")
            if timeout and time.time() - started > timeout:
                kill_proc(proc)
                raise TimeoutError("время команды истекло")
            time.sleep(0.4)
        stdout, stderr = proc.communicate()
        return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    finally:
        untrack_proc(proc)


def ssh_text(host: dict, command: str, timeout: int = 60) -> tuple[int, str, str]:
    result = ssh_exec(host, command, timeout=timeout)
    out = (result.stdout or b"").decode("utf-8", "replace")
    err = (result.stderr or b"").decode("utf-8", "replace")
    return result.returncode, out, err


def vmx_directory(vmx: str) -> str:
    text = vmx.strip()
    if text.startswith("[") and "]" in text:
        store, rest = text[1:].split("]", 1)
        parent = str(Path(rest.strip()).parent)
        suffix = "" if parent in ("", ".") else "/" + parent
        return f"/vmfs/volumes/{store.strip()}{suffix}"
    return str(Path(text).parent)


def looks_like_tar(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size < 512:
        return False
    head = path.read_bytes()[:200]
    if head.startswith(b"Unknown command") or b"Unknown command" in head:
        return False
    return True


def locate_vm_dir(host: dict, vm_name: str) -> str:
    safe = vm_name.replace("'", "")
    code, out, err = ssh_text(host, "/bin/sh -c 'vim-cmd vmsvc/getallvms'")
    if code != 0 or ("Unknown command" in (err + out)):
        code, out, err = ssh_text(host, "vim-cmd vmsvc/getallvms")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] == "Vmid" or ".vmx" not in line:
            continue
        if parts[1] == safe or f" {vm_name} " in f" {line} ":
            start = line.find("[")
            end = line.find(".vmx")
            if start >= 0 and end > start:
                return vmx_directory(line[start:end + 4].strip())
    detail = (err or out).strip()[:200]
    raise RuntimeError("каталог ВМ на ESXi не найден" + (f": {detail}" if detail else ""))


def rows_of(payload) -> list:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        value = payload.get("value", payload)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
    return []


def backing_path(backing) -> str:
    if not isinstance(backing, dict):
        return ""
    return str(backing.get("vmdk_file") or backing.get("vmdkFile") or "")


def parse_ds_path(path: str) -> tuple[str, str]:
    text = path.strip()
    if not (text.startswith("[") and "]" in text):
        raise RuntimeError(f"непонятный путь хранилища: {text}")
    store, rest = text[1:].split("]", 1)
    parent = str(Path(rest.strip()).parent)
    folder = "" if parent in ("", ".") else parent
    return store.strip(), folder


def copy_vm_files(host: dict, vm_name: str, folder: Path, control=None, progress=None, storage=None, job_id: str = "") -> str:
    if shutil_which("sshpass"):
        try:
            directory = locate_vm_dir(host, vm_name)
        except RuntimeError as error:
            directory = ""
            if progress and "vCenter Server" not in str(error):
                progress(str(error))
        if directory:
            copied = copy_vm_ssh(host, directory, folder)
            if copied.startswith("файлы ВМ записаны"):
                return copied
            if progress:
                progress(copied)
    if progress:
        progress("это vCenter, скачиваю файлы машины через API")
    return download_vm_http(host, vm_name, folder, control, progress, storage, job_id)


def copy_vm_ssh(host: dict, directory: str, folder: Path) -> str:
    quoted = shell_quote(directory)
    archive = folder / "vm.tar"
    last = ""
    for command in (
        f"/bin/sh -c 'cd {quoted} && /bin/tar -cf - .'",
        f"/bin/sh -c 'cd {quoted} && tar -cf - .'",
        f"/bin/sh -c 'cd {quoted} && busybox tar -cf - .'",
    ):
        with archive.open("wb") as handle:
            result = ssh_exec(host, command, timeout=3600, stdout=handle)
        last = (result.stderr or b"").decode("utf-8", "replace").strip()[:300]
        if result.returncode == 0 and looks_like_tar(archive):
            return f"файлы ВМ записаны в {archive}"
    built = copy_vm_by_files(host, directory, archive)
    if built:
        return f"файлы ВМ записаны в {archive}"
    if archive.exists():
        archive.unlink()
    return "копия файлов ВМ не удалась: " + (last or "на гипервизоре нет команды tar")


def download_vm_http(host: dict, vm_name: str, folder: Path, control=None, progress=None, storage=None, job_id: str = "") -> str:
    from html import unescape

    if control is None:
        control = connect_host(host)
    vmdk = ""
    centers = []
    if hasattr(control, "disk_path"):
        try:
            vmdk = control.disk_path(vm_name)
        except Exception as error:
            if progress:
                progress(f"список дисков: {error}")
        try:
            centers = control.datacenters()
        except Exception:
            centers = []
    if not vmdk:
        vmdk = soap_vm_path(host, vm_name, control)
    if not vmdk:
        return "vCenter не сообщил, на каком хранилище лежат файлы машины"
    datastore, remote_folder = parse_ds_path(vmdk)
    if not centers:
        centers = ["Datacenter", "ha-datacenter"]
    base = getattr(control, "base", "") or api_base(host.get("host", ""))
    cookie = folder_cookie(host, control)
    last = ""
    chosen = ""
    names = []
    for dc in centers:
        try:
            html = folder_text(base, host, cookie, datastore, dc, remote_folder)
        except Exception as error:
            last = str(error)
            continue
        found = folder_names(unescape(html), remote_folder)
        if found:
            chosen = dc
            names = found
            break
        last = "каталог пуст или это не список файлов"
    if not names:
        return f"файлы {vm_name} в хранилище {datastore} не открылись: {last}"
    names.sort(key=lambda item: (item.endswith(".vmdk"), item.lower()))
    (folder / "vm-source.txt").write_text(
        f"datastore={datastore}\nfolder={remote_folder}\ndc={chosen}\npath={vmdk}\n",
        encoding="utf-8",
    )
    saved = []
    remote_copy = storage_rel(storage, folder) if storage else ""
    kind = (storage or {}).get("kind")
    uploaded = (not storage) or kind in ("cifs", "nfs") or bool(remote_copy)
    for name in names:
        if progress:
            progress(f"скачиваю {name}")
        remote = f"{remote_folder}/{name}" if remote_folder else name
        url = folder_url(base, datastore, chosen, remote)
        dest = folder / name
        conn, response = http_open(url, folder_headers(host, cookie), timeout=300)
        try:
            if response.status >= 400:
                body = response.read(300).decode("utf-8", "replace")
                raise RuntimeError(f"{name}: HTTP {response.status} {body}")
            total = int(response.getheader("Content-Length") or "0")
            got = 0
            stamp = time.time()
            with dest.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    if job_id and job_stopped(job_id):
                        raise Stopped("резервное копирование прервано")
                    handle.write(chunk)
                    got += len(chunk)
                    now = time.time()
                    if progress and now - stamp >= 5:
                        stamp = now
                        if total:
                            progress(f"{name}: {got // 1048576} МБ из {total // 1048576}")
                        else:
                            progress(f"{name}: {got // 1048576} МБ")
        finally:
            conn.close()
        if got < 64:
            head = dest.read_bytes()[:80]
            if b"<html" in head.lower() or b"<!doctype" in head.lower() or b"Unauthorized" in head:
                dest.unlink(missing_ok=True)
                raise RuntimeError(f"{name}: vCenter вернул страницу вместо файла")
        if total and got < total:
            dest.unlink(missing_ok=True)
            raise RuntimeError(f"{name}: связь оборвалась, получено {got // 1048576} МБ из {total // 1048576}")
        saved.append(name)
        if storage and remote_copy and storage.get("kind") not in ("cifs", "nfs"):
            try:
                note = deliver_file(storage, remote_copy, dest)
                if progress:
                    progress(note)
            except Exception as error:
                uploaded = False
                if progress:
                    progress(f"{name} не ушёл в хранилище: {error}")
        elif storage and storage.get("kind") in ("cifs", "nfs"):
            if progress:
                progress(f"{name} записан на диск")
    if not saved:
        return "файлы машины не скачались"
    if uploaded:
        (folder / ".uploaded").write_text("1", encoding="utf-8")
    return f"файлы ВМ записаны в {folder}: " + ", ".join(saved)


def soap_vm_path(host: dict, vm_name: str, control=None) -> str:
    try:
        soap = control if isinstance(control, SoapHost) else SoapHost.login(
            getattr(control, "base", "") or api_base(host.get("host", "")),
            str(host.get("login", "")),
            str(host.get("secret", "")),
            str(host.get("kind", "")),
        )
    except Exception:
        return ""
    try:
        moref = soap.moref(vm_name)
    except Exception:
        return ""
    payload, _ = soap_call(
        soap.base,
        "<urn:RetrieveProperties>"
        f"<urn:_this type=\"PropertyCollector\">{xml_escape(soap.collector)}</urn:_this>"
        "<urn:specSet><urn:propSet><urn:type>VirtualMachine</urn:type><urn:pathSet>config.files.vmPathName</urn:pathSet></urn:propSet>"
        f"<urn:objectSet><urn:obj type=\"VirtualMachine\">{xml_escape(moref)}</urn:obj></urn:objectSet></urn:specSet>"
        "</urn:RetrieveProperties>",
        soap.cookie,
        soap.action,
        soap.style,
    )
    for value in re.findall(r"<(?:\w+:)?val[^>]*>([^<]+)", payload):
        if value.startswith("[") and ".vm" in value:
            return value.strip()
    return ""


def folder_cookie(host: dict, control) -> str:
    if isinstance(control, SoapHost) and control.cookie:
        return control.cookie.split(";", 1)[0]
    try:
        soap = SoapHost.login(
            getattr(control, "base", "") or api_base(host.get("host", "")),
            str(host.get("login", "")),
            str(host.get("secret", "")),
            str(host.get("kind", "")),
        )
        return soap.cookie.split(";", 1)[0]
    except Exception:
        return ""


def folder_headers(host: dict, cookie: str) -> dict:
    login = str(host.get("login", ""))
    secret = str(host.get("secret", ""))
    token = b64encode(f"{login}:{secret}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    if cookie:
        headers["Cookie"] = cookie
    return headers


def folder_url(base: str, datastore: str, datacenter: str, path: str) -> str:
    encoded = "/".join(urllib.parse.quote(part) for part in path.split("/") if part)
    query = urllib.parse.urlencode({"dcPath": datacenter, "dsName": datastore})
    root = base.rstrip("/") + "/folder"
    if encoded:
        root += "/" + encoded
    return root + "?" + query


def folder_text(base: str, host: dict, cookie: str, datastore: str, datacenter: str, path: str) -> str:
    conn, response = http_open(folder_url(base, datastore, datacenter, path), folder_headers(host, cookie), timeout=60)
    try:
        body = response.read(2_000_000)
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}")
    finally:
        conn.close()
    return body.decode("utf-8", "replace")


def folder_names(html: str, folder: str) -> list:
    names = []
    for href, label in re.findall(r'href="([^"]+)"[^>]*>([^<]+)', html, re.I):
        label = label.strip().rstrip("/")
        if not label or label in ("..", "Parent Directory", folder):
            continue
        if href.rstrip("/").endswith("/" + urllib.parse.quote(label)) is False and label.endswith("/"):
            continue
        if "." not in label:
            continue
        names.append(label)
    return list(dict.fromkeys(names))


def http_open(url: str, headers: dict, method: str = "GET", timeout: int = 120):
    current = url
    for _ in range(6):
        parts = urllib.parse.urlsplit(current)
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=CTX)
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader("Location") or ""
            response.read()
            conn.close()
            if not location:
                break
            current = urllib.parse.urljoin(current, location)
            continue
        return conn, response
    raise RuntimeError("слишком много перенаправлений")


def read_vm_meta(meta_file: Path) -> dict:
    meta = {}
    for line in meta_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            meta[key] = value
    if not meta.get("datastore"):
        raise RuntimeError("в копии нет пути хранилища vCenter")
    return meta


def upload_vm_http(host: dict, archive: Path, meta_file: Path) -> None:
    import tarfile

    meta = read_vm_meta(meta_file)
    control = connect_host(host)
    base = getattr(control, "base", "") or api_base(host.get("host", ""))
    cookie = folder_cookie(host, control)
    headers = folder_headers(host, cookie)
    datacenter = meta.get("dc") or "Datacenter"
    files = [path for path in meta_file.parent.iterdir() if path.is_file() and path.suffix.lower() in {".vmdk", ".vmx", ".nvram", ".vmsd"}]
    if files:
        for local in files:
            remote = f"{meta.get('folder', '')}/{local.name}".strip("/")
            with local.open("rb") as handle:
                put_stream(folder_url(base, meta["datastore"], datacenter, remote), headers, handle, local.stat().st_size)
        return
    with tarfile.open(archive, "r") as bundle:
        for member in bundle.getmembers():
            if not member.isfile():
                continue
            payload = bundle.extractfile(member)
            if payload is None:
                continue
            remote = f"{meta.get('folder', '')}/{member.name}".strip("/")
            put_stream(folder_url(base, meta["datastore"], datacenter, remote), headers, payload, member.size)


def put_stream(url: str, headers: dict, payload, size: int) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=7200, context=CTX)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=7200)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    conn.putrequest("PUT", path)
    for key, value in headers.items():
        conn.putheader(key, value)
    conn.putheader("Content-Length", str(size))
    conn.putheader("Content-Type", "application/octet-stream")
    conn.endheaders()
    while True:
        chunk = payload.read(1024 * 1024)
        if not chunk:
            break
        conn.send(chunk)
    response = conn.getresponse()
    body = response.read(300).decode("utf-8", "replace")
    conn.close()
    if response.status >= 400:
        raise RuntimeError(f"vCenter не принял файл: HTTP {response.status} {body}")


def copy_vm_by_files(host: dict, directory: str, archive: Path) -> bool:
    quoted = shell_quote(directory)
    code, out, _ = ssh_text(host, f"/bin/sh -c 'cd {quoted} && find . -type f'", timeout=120)
    names = [line.strip() for line in out.splitlines() if line.startswith("./") or (line.startswith(".") and line not in (".", ".."))]
    if code != 0 or not names:
        return False
    import tarfile

    with tarfile.open(archive, "w") as bundle:
        for name in names:
            remote = directory.rstrip("/") + "/" + name[2:] if name.startswith("./") else directory.rstrip("/") + "/" + name
            size_code, size_out, _ = ssh_text(host, f"/bin/sh -c 'wc -c < {shell_quote(remote)}'", timeout=60)
            digits = "".join(char for char in size_out if char.isdigit())
            if size_code != 0 or not digits:
                continue
            info = tarfile.TarInfo(name[2:] if name.startswith("./") else name)
            info.size = int(digits)
            proc = subprocess.Popen(
                [
                    "sshpass", "-p", str(host.get("secret", "")),
                    "ssh", "-o", "StrictHostKeyChecking=accept-new",
                    ssh_host(host),
                    f"/bin/sh -c 'cat {shell_quote(remote)}'",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            bundle.addfile(info, proc.stdout)
            proc.wait(timeout=3600)
            if proc.returncode != 0:
                continue
    return looks_like_tar(archive)


def extract_vm_files(host: dict, directory: str, archive: Path) -> None:
    quoted = shell_quote(directory)
    attempts = (
        f"/bin/sh -c 'cd {quoted} && /bin/tar -xf -'",
        f"/bin/sh -c 'cd {quoted} && tar -xf -'",
        f"/bin/sh -c 'cd {quoted} && busybox tar -xf -'",
    )
    last = ""
    for command in attempts:
        with archive.open("rb") as handle:
            result = ssh_exec(host, command, timeout=3600, stdin=handle)
        last = (result.stderr or b"").decode("utf-8", "replace").strip()[:300]
        if result.returncode == 0 and "Unknown command" not in last:
            return
    import tarfile

    with tarfile.open(archive, "r") as bundle:
        for member in bundle.getmembers():
            if not member.isfile():
                continue
            remote = directory.rstrip("/") + "/" + member.name
            payload = bundle.extractfile(member)
            if payload is None:
                continue
            result = ssh_exec(host, f"/bin/sh -c 'cat > {shell_quote(remote)}'", timeout=3600, stdin=payload)
            if result.returncode != 0:
                detail = (result.stderr or b"").decode("utf-8", "replace").strip()[:200]
                raise RuntimeError(detail or f"не записан {member.name}")
    if last and "Unknown command" in last:
        return
    if last:
        raise RuntimeError(last)


def shutil_which(name: str):
    from shutil import which

    return which(name)


def api_base(host: str) -> str:
    value = str(host).strip()
    if not value.startswith("http"):
        value = "https://" + value
    parts = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parts.scheme or "https", parts.netloc, "", "", ""))


def http_exchange(url: str, method: str, headers: dict, body: bytes = b"", keep_method: bool = False, timeout: int = 60):
    current = url
    payload = body
    for _ in range(5):
        parts = urllib.parse.urlsplit(current)
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=CTX)
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
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
        return RestHost(base, root, session, str(host.get("login", "")), str(host.get("secret", "")), kind)
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
    def __init__(self, base: str, root: str, session: str, login: str = "", secret: str = "", kind: str = ""):
        self.base = base
        self.root = root
        self.session = session
        self.login = login
        self.secret = secret
        self.kind = kind
        self.vm_id = ""

    def names(self) -> list:
        payload = api(self.base, self.root, self.session, "/vcenter/vm")
        rows = payload.get("value", payload) if isinstance(payload, dict) else payload
        return [row.get("name") for row in rows or [] if isinstance(row, dict) and row.get("name")]

    def disk_path(self, name: str) -> str:
        if not self.vm_id:
            self.vm_id = find_vm(self.base, self.root, self.session, name)
        encoded = urllib.parse.quote(self.vm_id, safe="")
        payload = api(self.base, self.root, self.session, f"/vcenter/vm/{encoded}/hardware/disk")
        for row in rows_of(payload):
            backing = row.get("backing") if isinstance(row, dict) else None
            path = backing_path(backing)
            if path:
                return path
            disk = row.get("disk") if isinstance(row, dict) else ""
            if not disk:
                continue
            detail = api(self.base, self.root, self.session, f"/vcenter/vm/{encoded}/hardware/disk/{urllib.parse.quote(str(disk), safe='')}")
            path = backing_path(detail.get("backing") if isinstance(detail, dict) else None)
            if not path and isinstance(detail, dict):
                path = backing_path((detail.get("value") or {}).get("backing") if isinstance(detail.get("value"), dict) else None)
            if path:
                return path
        return ""

    def datacenters(self) -> list:
        payload = api(self.base, self.root, self.session, "/vcenter/datacenter")
        return [row.get("name") for row in rows_of(payload) if isinstance(row, dict) and row.get("name")]

    def shutdown(self, name: str) -> None:
        self.vm_id = find_vm(self.base, self.root, self.session, name)
        try:
            api(self.base, self.root, self.session, f"/vcenter/vm/{urllib.parse.quote(self.vm_id, safe='')}/guest/power?action=shutdown", method="POST", timeout=45)
        except Exception as error:
            if not timed_out(error):
                raise

    def wait_off(self, name: str, seconds: int = 600, tick=None) -> bool:
        return wait_off(self.base, self.root, self.session, self.vm_id, seconds=seconds, tick=tick)

    def power_off(self, name: str) -> None:
        if not self.vm_id:
            self.vm_id = find_vm(self.base, self.root, self.session, name)
        encoded = urllib.parse.quote(self.vm_id, safe="")
        last = ""
        for path in (
            f"/vcenter/vm/{encoded}/power/stop",
            f"/vcenter/vm/{encoded}/power?action=stop",
        ):
            try:
                api(self.base, self.root, self.session, path, method="POST", timeout=120)
                return
            except RuntimeError as error:
                last = str(error)
                if "404" not in last and "Not found" not in last and "httpNotFound" not in last:
                    break
        soap = SoapHost.login(self.base, self.login, self.secret, self.kind)
        soap.power_off(name)

    def power_on(self, name: str) -> None:
        try:
            self.vm_id = find_vm(self.base, self.root, self.session, name)
        except Exception:
            if not self.vm_id:
                raise
        encoded = urllib.parse.quote(self.vm_id, safe="")
        last = ""
        for path in (
            f"/vcenter/vm/{encoded}/power/start",
            f"/vcenter/vm/{encoded}/power?action=start",
        ):
            try:
                api(self.base, self.root, self.session, path, method="POST")
                return
            except RuntimeError as error:
                last = str(error)
                if "404" not in last and "Not found" not in last and "httpNotFound" not in last:
                    break
        try:
            soap = SoapHost.login(self.base, self.login, self.secret, self.kind)
            soap.power_on(name)
            return
        except Exception as error:
            raise RuntimeError(f"{last}. Включение через SOAP: {error}") from error


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
        try:
            soap_call(self.base, f"<urn:ShutdownGuest><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:ShutdownGuest>", self.cookie, self.action, self.style, timeout=45)
        except Exception as error:
            if not timed_out(error):
                raise

    def wait_off(self, name: str, seconds: int = 600, tick=None) -> bool:
        moref = self.moref(name)
        started = time.time()
        deadline = started + seconds
        last = 0
        while time.time() < deadline:
            try:
                if soap_power(self, moref) == "poweredOff":
                    return True
            except Exception as error:
                if not timed_out(error):
                    raise
            elapsed = int(time.time() - started)
            if tick and elapsed - last >= 20:
                last = elapsed
                tick(elapsed)
            time.sleep(5)
        return False

    def power_off(self, name: str) -> None:
        moref = self.moref(name)
        soap_call(self.base, f"<urn:PowerOffVM_Task><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:PowerOffVM_Task>", self.cookie, self.action, self.style, timeout=120)

    def power_on(self, name: str) -> None:
        moref = self.moref(name)
        soap_call(self.base, f"<urn:PowerOnVM_Task><urn:_this type=\"VirtualMachine\">{xml_escape(moref)}</urn:_this></urn:PowerOnVM_Task>", self.cookie, self.action, self.style)

    def moref(self, name: str) -> str:
        if name not in self.morefs:
            self.morefs = soap_vm_map(self)
        if name not in self.morefs:
            raise RuntimeError(f"машина {name} не найдена")
        return self.morefs[name]


def soap_call(base: str, body: str, cookie: str = "", action: str = '"urn:vim25/7.0"', style: str = "plain", timeout: int = 60) -> tuple[str, str]:
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
    status, raw, response_headers = http_exchange(base.rstrip("/") + "/sdk", "POST", headers, xml, keep_method=True, timeout=timeout)
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


def api(base: str, root: str, session: str, path: str, method="GET", timeout: int = 60):
    status, raw, _ = http_exchange(
        base.rstrip("/") + root + path,
        method,
        {"vmware-api-session-id": session, "Accept": "application/json"},
        b"" if method != "GET" else None,
        keep_method=method != "GET",
        timeout=timeout,
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


def wait_off(base: str, root: str, session: str, vm_id: str, seconds: int = 600, tick=None) -> bool:
    started = time.time()
    deadline = started + seconds
    last = 0
    while time.time() < deadline:
        try:
            payload = api(base, root, session, f"/vcenter/vm/{urllib.parse.quote(vm_id, safe='')}/power", timeout=60)
            if isinstance(payload, dict) and "state" in payload:
                state = payload.get("state")
            elif isinstance(payload, dict):
                state = payload.get("value", {}).get("state")
            else:
                state = ""
            if state == "POWERED_OFF":
                return True
        except Exception as error:
            if not timed_out(error):
                raise
        elapsed = int(time.time() - started)
        if tick and elapsed - last >= 20:
            last = elapsed
            tick(elapsed)
        time.sleep(5)
    return False


def safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_." else "_" for char in value)
    return cleaned or "vm"


def storage_rel(storage: dict, stamp: Path) -> str:
    try:
        if storage.get("kind") in ("cifs", "nfs"):
            root = (MOUNT_ROOT / storage["id"]).resolve()
        else:
            root = (cache_root() / "stage" / storage["id"]).resolve()
        return stamp.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return ""


def deliver_file(storage: dict, remote_dir: str, local: Path) -> str:
    rel = f"{clean_rel(remote_dir)}/{local.name}".strip("/")
    kind = storage.get("kind")
    if kind == "ftp":
        upload_ftp_file(storage, rel, local)
    elif kind in ("webdav", "mail"):
        upload_webdav_file(storage, rel, local)
    elif kind in ("yandex", "google"):
        upload_linked(storage, remote_dir, local)
    else:
        raise RuntimeError(f"неизвестный тип {kind}")
    return f"{local.name} в хранилище {storage.get('name')} / {rel}"


def upload_ftp_file(item: dict, remote: str, local: Path) -> None:
    import ftplib

    host, port = split_host(item["endpoint"], 21)
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=7200)
    ftp.login(item.get("login") or "anonymous", item.get("secret") or "anonymous@")
    root = ftp_dir(item["endpoint"]).rstrip("/")
    ftp_mkdirs(ftp, f"{root}/{remote}".rsplit("/", 1)[0])
    with local.open("rb") as handle:
        ftp.storbinary(f"STOR {root}/{remote}", handle, blocksize=1024 * 1024)
    ftp.quit()


def upload_webdav_file(item: dict, remote: str, local: Path) -> None:
    webdav_mkcol(item, remote.rsplit("/", 1)[0])
    url = join_url(webdav_base(item), remote)
    token = b64encode(f"{item.get('login', '')}:{item.get('secret', '')}".encode()).decode()
    with local.open("rb") as handle:
        put_stream(url, {"Authorization": f"Basic {token}"}, handle, local.stat().st_size)


def upload_linked(storage: dict, remote_dir: str, local: Path) -> None:
    import tempfile

    parent = Path(tempfile.mkdtemp(prefix="onec-vm-"))
    link = parent / local.name
    try:
        os.link(local, link)
    except OSError:
        os.symlink(local, link)
    if storage.get("kind") == "yandex":
        upload_yandex_tree(storage, clean_rel(remote_dir), parent)
    else:
        upload_google_tree(storage, clean_rel(remote_dir), parent)


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


def cache_root() -> Path:
    return Path(os.environ.get("ONEC_CACHE_DIR", "/var/cache/onec-platform"))


def locate_copy(storage: dict, rel: str) -> Path:
    rel = clean_rel(rel)
    stage = (cache_root() / "stage" / storage["id"] / rel).resolve()
    if stage.is_dir() and any(stage.iterdir()):
        return stage
    if storage.get("kind") in ("cifs", "nfs"):
        ok, detail = mount_disk(storage)
        if not ok:
            raise RuntimeError(detail)
        path = (MOUNT_ROOT / storage["id"] / rel).resolve()
        if not path.is_dir() or not any(path.iterdir()):
            raise RuntimeError("копия на диске не найдена")
        return path
    dest = (cache_root() / "restore" / storage["id"] / rel).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    listing = list_storage(storage, rel)
    for row in listing.get("entries") or []:
        if row.get("kind") != "file" or not row.get("name"):
            continue
        download_file(storage, f"{rel}/{row['name']}".strip("/"), dest / row["name"])
    if not any(dest.iterdir()):
        raise RuntimeError("в хранилище нет файлов этой копии")
    return dest


def download_file(storage: dict, rel: str, dest: Path) -> None:
    kind = storage.get("kind")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if kind == "ftp":
        import ftplib

        host, port = split_host(storage["endpoint"], 21)
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=60)
        ftp.login(storage.get("login") or "anonymous", storage.get("secret") or "anonymous@")
        root = ftp_dir(storage["endpoint"]).rstrip("/")
        with dest.open("wb") as handle:
            ftp.retrbinary(f"RETR {root}/{rel}", handle.write)
        ftp.quit()
        return
    if kind in ("webdav", "mail"):
        request = urllib.request.Request(join_url(webdav_base(storage), rel))
        webdav_auth(request, storage)
        with urllib.request.urlopen(request, timeout=120, context=CTX) as response:
            dest.write_bytes(response.read())
        return
    if kind == "yandex":
        disk = yandex_root(storage.get("endpoint", "")).rstrip("/") + "/" + rel
        query = urllib.parse.urlencode({"path": disk})
        request = urllib.request.Request(
            "https://cloud-api.yandex.net/v1/disk/resources/download?" + query,
            headers={"Authorization": f"OAuth {storage.get('secret', '')}"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            href = json.loads(response.read().decode()).get("href")
        if not href:
            raise RuntimeError("Яндекс Диск не дал ссылку на файл")
        with urllib.request.urlopen(href, timeout=120) as response:
            dest.write_bytes(response.read())
        return
    raise RuntimeError("скачать копию из этого хранилища нельзя, файл уже удалён с этой машины")
