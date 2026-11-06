"""Host settings, GitHub release, cluster and VM catalogs, backup retention."""

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from ops import MOUNT_ROOT, list_vm_names, safe_name

REPO = "https://github.com/GrafAtRuss/server.git"
SRC = Path("/opt/onec-console-src")
GITHUB_API = "https://api.github.com/repos/GrafAtRuss/server"


def command(args: list, timeout: int = 20) -> tuple[int, str]:
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)
    text = (result.stdout or result.stderr or "").strip()
    return result.returncode, text


def read_system() -> dict:
    _, hostname = command(["hostname"])
    _, timezone = command(["timedatectl", "show", "-p", "Timezone", "--value"])
    _, ntp = command(["timedatectl", "show", "-p", "NTP", "--value"])
    _, now = command(["date", "+%Y-%m-%d %H:%M:%S %Z"])
    _, locale = command(["localectl", "status"])
    dns = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1:
                    dns.append(parts[1])
    _, address = command(["ip", "-br", "addr"])
    code, firewall = command(["ufw", "status"]) if shutil.which("ufw") else (1, "ufw не установлен")
    _, ssh = command(["systemctl", "is-active", "ssh"])
    if ssh not in ("active", "inactive"):
        _, ssh = command(["systemctl", "is-active", "sshd"])
    return {
        "hostname": hostname,
        "timezone": timezone,
        "ntp": ntp.lower() == "yes",
        "time": now,
        "locale": locale,
        "dns": dns,
        "interfaces": address,
        "firewall": firewall,
        "firewallActive": "Status: active" in firewall or "Состояние: активен" in firewall,
        "ssh": ssh,
        "ufwMissing": code != 0 and firewall == "ufw не установлен",
    }


def apply_system(payload: dict) -> str:
    op = payload.get("op")
    value = str(payload.get("value", "")).strip()
    if op == "hostname" and value:
        code, text = command(["hostnamectl", "set-hostname", value])
        return text or ("имя изменено" if code == 0 else "не удалось сменить имя")
    if op == "timezone" and value:
        code, text = command(["timedatectl", "set-timezone", value])
        return text or ("пояс изменён" if code == 0 else "не удалось сменить пояс")
    if op == "ntp":
        code, text = command(["timedatectl", "set-ntp", "true" if payload.get("value") else "false"])
        return text or ("NTP обновлён" if code == 0 else "NTP не изменён")
    if op == "locale" and value:
        code, text = command(["localectl", "set-locale", f"LANG={value}"])
        return text or ("локаль изменена" if code == 0 else "локаль не изменена")
    if op == "dns" and value:
        servers = value.split()
        code, text = command(["resolvectl", "dns", payload.get("iface") or ""] + servers) if payload.get("iface") else (1, "")
        if code != 0:
            lines = ["nameserver " + item for item in servers]
            Path("/etc/resolv.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")
            return "DNS записан в resolv.conf"
        return text or "DNS обновлён"
    if op == "firewall":
        if not shutil.which("ufw"):
            return "ufw не установлен"
        action = "enable" if payload.get("value") else "disable"
        code, text = command(["ufw", "--force", action])
        return text or ("фаервол обновлён" if code == 0 else "фаервол не изменён")
    if op == "firewall-allow" and value.isdigit():
        code, text = command(["ufw", "allow", f"{value}/tcp"])
        return text or ("порт открыт" if code == 0 else "порт не открыт")
    if op == "firewall-delete" and value.isdigit():
        code, text = command(["ufw", "delete", "allow", f"{value}/tcp"])
        return text or ("правило снято" if code == 0 else "правило не снято")
    if op == "ssh":
        action = "start" if payload.get("value") else "stop"
        code, text = command(["systemctl", action, "ssh"])
        command(["systemctl", "enable" if payload.get("value") else "disable", "ssh"])
        return text or ("SSH обновлён" if code == 0 else "SSH не изменён")
    return "неизвестная настройка"


def schedule_power(action: str) -> str:
    if action not in ("reboot", "poweroff"):
        return "неизвестное действие"
    if os.environ.get("ONEC_POWER") == "skip":
        return f"запрошено: {action}"
    if shutil.which("systemd-run"):
        command(["systemd-run", "--on-active=3s", "systemctl", action])
    else:
        subprocess.Popen(["systemctl", action], start_new_session=True)
    return f"{action} через несколько секунд"


def schedule_update() -> str:
    if os.environ.get("ONEC_UPDATE") == "skip":
        return "обновление поставлено в очередь"
    script = f"""
set -eu
if [ ! -d {SRC}/.git ]; then
  rm -rf {SRC}
  git clone {REPO} {SRC}
fi
git -C {SRC} pull --ff-only
deb=$({SRC}/build-deb.sh)
dpkg -i "$deb"
"""
    if shutil.which("systemd-run"):
        command(["systemd-run", "--unit=onec-console-update", "bash", "-c", script], timeout=15)
    else:
        subprocess.Popen(["bash", "-c", script], start_new_session=True)
    return "обновление с GitHub запущено отдельно от службы"


def github_release() -> dict:
    if os.environ.get("ONEC_RELEASE") == "skip":
        return {"title": "v1.2.0", "body": "тест", "url": REPO, "when": "", "source": "release"}
    for path, source in (("releases/latest", "release"), ("commits/main", "commit")):
        request = urllib.request.Request(
            f"{GITHUB_API}/{path}",
            headers={"User-Agent": "onec-console", "Accept": "application/vnd.github+json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode())
        except urllib.error.HTTPError:
            continue
        except OSError as error:
            return {"error": str(error)}
        if source == "release":
            return {
                "title": data.get("tag_name") or data.get("name"),
                "body": data.get("body") or "",
                "url": data.get("html_url") or REPO,
                "when": data.get("published_at") or "",
                "source": "release",
            }
        return {
            "title": (data.get("sha") or "")[:7],
            "body": (data.get("commit") or {}).get("message") or "",
            "url": data.get("html_url") or REPO,
            "when": ((data.get("commit") or {}).get("committer") or {}).get("date") or "",
            "source": "commit",
        }
    return {"error": "GitHub не ответил."}


def rac_path(installed: dict | None) -> str | None:
    if installed and installed.get("version"):
        candidate = Path(f"/opt/1cv8/x86_64/{installed['version']}/rac")
        if candidate.is_file():
            return str(candidate)
    return shutil.which("rac")


def cluster_catalog(cluster: dict, installed: dict | None) -> list:
    if os.environ.get("ONEC_RAC") == "skip":
        return ["trade", "accounting"]
    rac = rac_path(installed)
    if not rac:
        raise RuntimeError("rac не найден. Сначала установите сервер 1С.")
    target = f"{cluster['host']}:{cluster.get('port') or 1545}"
    code, text = command([rac, "cluster", "list", target], timeout=30)
    if code != 0:
        raise RuntimeError(text or "кластер не ответил")
    cluster_id = ""
    for line in text.splitlines():
        if line.strip().lower().startswith("cluster"):
            cluster_id = line.split(":", 1)[-1].strip()
            break
    if not cluster_id:
        raise RuntimeError("в ответе rac нет идентификатора кластера")
    args = [rac, "infobase", f"--cluster={cluster_id}", "summary", "list", target]
    if cluster.get("login"):
        args[2:2] = [f"--cluster-user={cluster['login']}", f"--cluster-pwd={cluster.get('secret', '')}"]
    code, text = command(args, timeout=40)
    if code != 0:
        raise RuntimeError(text or "список баз не получен")
    names = []
    for line in text.splitlines():
        lowered = line.strip().lower()
        if lowered.startswith("name") or lowered.startswith("имя"):
            names.append(line.split(":", 1)[-1].strip())
    return names


def vm_catalog(host: dict) -> list:
    if os.environ.get("ONEC_VM") == "skip":
        return ["trade-vm", "files-vm"]
    return list_vm_names(host)


def prune(folder: Path, keep_days: int) -> list:
    if keep_days <= 0 or not folder.is_dir():
        return []
    cutoff = time.time() - keep_days * 86400
    removed = []
    for child in folder.iterdir():
        try:
            if child.stat().st_mtime < cutoff:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                removed.append(child.name)
        except OSError:
            continue
    return removed


def backup_dir(storage_id: str, kind: str, name: str) -> Path:
    folder = MOUNT_ROOT / storage_id / kind / safe_name(name)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def new_stamp(folder: Path) -> Path:
    stamp = folder / datetime.now().strftime("%Y%m%d-%H%M%S")
    stamp.mkdir(parents=True, exist_ok=True)
    return stamp
