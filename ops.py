"""Storage mounts, cloud checks, and ESXi/vSphere power cycle."""

import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from datetime import datetime
from pathlib import Path

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
    base = api_base(host["host"])
    try:
        session, root = vsphere_login(base, host["login"], host["secret"])
        vm_id = find_vm(base, root, session, job["vmName"])
        log.append(f"мягкое выключение {job['vmName']}")
        api(base, root, session, f"/vcenter/vm/{vm_id}/guest/power?action=shutdown", method="POST")
        if not wait_off(base, root, session, vm_id):
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
        if turned_off:
            try:
                api(base, root, session, f"/vcenter/vm/{vm_id}/power?action=start", method="POST")
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
    """Сессия ESXi или vCenter. ESXi 6.5 отвечает на /rest, ESXi 7+ и vCenter — ещё и на /api."""
    token = b64encode(f"{login}:{secret}".encode()).decode()
    errors = []
    for root, path in (("/api", "/session"), ("/rest", "/com/vmware/cis/session")):
        request = urllib.request.Request(
            base.rstrip("/") + root + path,
            data=b"",
            method="POST",
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        )
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
    raise RuntimeError("ESXi или vSphere не пустил: " + "; ".join(errors))


def list_vm_names(host: dict) -> list:
    base = api_base(host["host"])
    session, root = vsphere_login(base, host["login"], host["secret"])
    payload = api(base, root, session, "/vcenter/vm")
    rows = payload.get("value", payload) if isinstance(payload, dict) else payload
    return [row.get("name") for row in rows or [] if isinstance(row, dict) and row.get("name")]


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
