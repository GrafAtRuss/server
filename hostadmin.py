"""Host settings, GitHub release, cluster and VM catalogs, backup retention."""

import json
import os
import re
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
RAW = "https://raw.githubusercontent.com/GrafAtRuss/server/main"
WEB = "https://github.com/GrafAtRuss/server"


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
    dns = resolv_dns()
    code, firewall = command(["ufw", "status", "numbered"]) if shutil.which("ufw") else (1, "ufw не установлен")
    _, ssh = command(["systemctl", "is-active", "ssh"])
    if ssh not in ("active", "inactive"):
        _, ssh = command(["systemctl", "is-active", "sshd"])
    return {
        "hostname": hostname,
        "timezone": timezone,
        "timezones": list_timezones(),
        "ntp": ntp.lower() == "yes",
        "time": now,
        "locale": locale.splitlines()[0] if locale else "",
        "dns": dns,
        "nics": read_nics(),
        "firewall": firewall,
        "firewallRules": read_firewall_rules(firewall),
        "firewallActive": "Status: active" in firewall or "Состояние: активен" in firewall,
        "ssh": ssh,
        "ufwMissing": not shutil.which("ufw"),
        "updateLog": update_log_text(),
    }


def resolv_dns() -> list:
    dns = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1:
                    dns.append(parts[1])
    return dns


_ZONES = None


def list_timezones() -> list:
    global _ZONES
    if _ZONES is None:
        _, text = command(["timedatectl", "list-timezones"], timeout=20)
        _ZONES = [line for line in text.splitlines() if "/" in line or line == "UTC"]
        if not _ZONES:
            _ZONES = [
                "UTC",
                "Europe/Kaliningrad",
                "Europe/Moscow",
                "Europe/Samara",
                "Asia/Yekaterinburg",
                "Asia/Omsk",
                "Asia/Novosibirsk",
                "Asia/Krasnoyarsk",
                "Asia/Irkutsk",
                "Asia/Yakutsk",
                "Asia/Vladivostok",
                "Asia/Magadan",
                "Asia/Kamchatka",
            ]
    return _ZONES


def read_nics() -> list:
    _, text = command(["ip", "-j", "addr"])
    _, route_text = command(["ip", "-j", "route"])
    gateways = {}
    if route_text.startswith("["):
        try:
            for route in json.loads(route_text):
                if route.get("dst") in ("default", "0.0.0.0/0") and route.get("dev"):
                    gateways.setdefault(route["dev"], route.get("gateway", ""))
        except json.JSONDecodeError:
            pass
    found = []
    if text.startswith("["):
        try:
            for item in json.loads(text):
                name = item.get("ifname")
                if not name:
                    continue
                addresses = []
                dynamic = False
                for info in item.get("addr_info") or []:
                    if info.get("family") != "inet":
                        continue
                    local = info.get("local")
                    if local:
                        addresses.append(f"{local}/{info.get('prefixlen')}")
                    if info.get("dynamic"):
                        dynamic = True
                found.append(
                    {
                        "name": name,
                        "state": item.get("operstate") or "",
                        "addresses": addresses,
                        "gateway": gateways.get(name, ""),
                        "mode": "dhcp" if dynamic or name != "lo" and not addresses else "static",
                        "editable": name != "lo",
                    }
                )
        except json.JSONDecodeError:
            found = []
    if not found:
        sysnet = Path("/sys/class/net")
        if sysnet.is_dir():
            for path in sorted(sysnet.iterdir()):
                found.append(
                    {"name": path.name, "state": "", "addresses": [], "gateway": "", "mode": "dhcp", "editable": path.name != "lo"}
                )
    return found


def read_firewall_rules(status_text: str = "") -> list:
    rules = []
    for line in status_text.splitlines():
        match = re.match(r"\[\s*(\d+)\]\s+(.+)$", line.strip())
        if not match:
            continue
        body = re.sub(r"\s{2,}", " | ", match.group(2).strip())
        parts = [part.strip() for part in body.split("|")]
        rules.append(
            {
                "number": match.group(1),
                "text": match.group(2).strip(),
                "to": parts[0] if parts else "",
                "action": parts[1] if len(parts) > 1 else "",
                "source": parts[2] if len(parts) > 2 else "",
            }
        )
    if rules or not shutil.which("ufw"):
        return rules
    _, added = command(["ufw", "show", "added"])
    for line in added.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ufw "):
            continue
        rules.append({"number": "", "text": stripped, "to": stripped, "action": "", "source": "", "spec": stripped[4:]})
    return rules


def valid_ipv4(value: str) -> bool:
    match = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", value)
    return bool(match) and all(0 <= int(part) <= 255 for part in match.groups())


def valid_cidr(value: str) -> bool:
    if "/" not in value:
        return False
    address, prefix = value.split("/", 1)
    return valid_ipv4(address) and prefix.isdigit() and 1 <= int(prefix) <= 32


def apply_system(payload: dict) -> str:
    op = payload.get("op")
    raw = payload.get("value")
    value = raw.strip() if isinstance(raw, str) else ""
    if op == "hostname" and value:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value):
            return "имя хоста содержит недопустимые символы"
        code, text = command(["hostnamectl", "set-hostname", value])
        return text or ("имя изменено" if code == 0 else "не удалось сменить имя")
    if op == "timezone" and value:
        if value not in list_timezones():
            return "такого пояса нет"
        code, text = command(["timedatectl", "set-timezone", value])
        return text or ("пояс изменён" if code == 0 else "не удалось сменить пояс")
    if op == "ntp":
        code, text = command(["timedatectl", "set-ntp", "true" if payload.get("value") else "false"])
        return text or ("NTP обновлён" if code == 0 else "NTP не изменён")
    if op == "locale" and value:
        if not re.fullmatch(r"[A-Za-z0-9@._-]+", value):
            return "локаль содержит недопустимые символы"
        code, text = command(["localectl", "set-locale", f"LANG={value}"])
        return text or ("локаль изменена" if code == 0 else "локаль не изменена")
    if op == "dns" and value:
        servers = value.split()
        if not servers or any(not valid_ipv4(item) for item in servers):
            return "DNS должен быть списком IPv4"
        iface = str(payload.get("iface") or "")
        code, text = command(["resolvectl", "dns", iface, *servers]) if iface else (1, "")
        if code != 0:
            Path("/etc/resolv.conf").write_text("".join(f"nameserver {item}\n" for item in servers), encoding="utf-8")
            return "DNS записан в resolv.conf"
        return text or "DNS обновлён"
    if op == "address":
        return apply_address(payload)
    if op == "firewall":
        if not ensure_ufw():
            return "ufw не установлен и не поставился"
        action = "enable" if payload.get("value") else "disable"
        code, text = command(["ufw", "--force", action])
        return text or ("фаервол обновлён" if code == 0 else "фаервол не изменён")
    if op in ("firewall-allow", "firewall-rule"):
        return firewall_rule(payload, value)
    if op == "firewall-delete":
        return firewall_delete(payload, value)
    if op == "ssh":
        unit = "ssh" if command(["systemctl", "cat", "ssh"])[0] == 0 else "sshd"
        action = "start" if payload.get("value") else "stop"
        code, text = command(["systemctl", action, unit])
        command(["systemctl", "enable" if payload.get("value") else "disable", unit])
        return text or ("SSH обновлён" if code == 0 else "SSH не изменён")
    return "неизвестная настройка"


def ensure_ufw() -> bool:
    if shutil.which("ufw"):
        return True
    code, _ = command(["apt-get", "install", "-y", "ufw"], timeout=180)
    return code == 0 and shutil.which("ufw") is not None


def firewall_rule(payload: dict, value: str) -> str:
    if not ensure_ufw():
        return "ufw не установлен и не поставился"
    action = payload.get("action") or "allow"
    if action not in ("allow", "deny"):
        return "неизвестное действие"
    proto = str(payload.get("proto") or "tcp").lower()
    if proto not in ("tcp", "udp"):
        return "нужен протокол tcp или udp"
    port = str(payload.get("port") or value).strip()
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return "нужен порт"
    source = str(payload.get("source") or "").strip()
    if source and not (valid_ipv4(source.split("/")[0]) and (source == source.split("/")[0] or valid_cidr(source))):
        return "адрес источника некорректен"
    replace = str(payload.get("replace") or "").strip()
    spec = str(payload.get("spec") or "").strip()
    if spec and re.fullmatch(r"[A-Za-z0-9_.:/ -]+", spec):
        command(["ufw", "--force", "delete", *spec.split()])
    elif replace.isdigit():
        command(["ufw", "--force", "delete", replace])
    cmd = ["ufw", action]
    if source:
        cmd += ["from", source, "to", "any", "port", port, "proto", proto]
    else:
        cmd += [f"{port}/{proto}"]
    code, text = command(cmd)
    return text or ("правило записано" if code == 0 else "правило не записано")


def firewall_delete(payload: dict, value: str) -> str:
    if not shutil.which("ufw"):
        return "ufw не установлен"
    number = str(payload.get("number") or value).strip()
    spec = str(payload.get("spec") or "").strip()
    if number.isdigit() and not spec.startswith("allow") and not spec.startswith("deny"):
        code, text = command(["ufw", "--force", "delete", number])
        return text or ("правило удалено" if code == 0 else "правило не удалено")
    if spec and re.fullmatch(r"[A-Za-z0-9_.:/ -]+", spec):
        code, text = command(["ufw", "--force", "delete", *spec.split()])
        return text or ("правило удалено" if code == 0 else "правило не удалено")
    return "нечего удалять"


def apply_address(payload: dict) -> str:
    if os.environ.get("ONEC_SYS") == "skip":
        return "адрес принят"
    iface = str(payload.get("iface") or "")
    if iface == "lo" or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,14}", iface):
        return "этот интерфейс менять нельзя"
    if iface not in {item["name"] for item in read_nics()}:
        return "интерфейс не найден"
    mode = payload.get("mode")
    if mode not in ("dhcp", "static"):
        return "режим должен быть dhcp или static"
    address = str(payload.get("address") or "").strip()
    gateway = str(payload.get("gateway") or "").strip()
    dns = [item for item in str(payload.get("dns") or "").split() if item]
    if mode == "static":
        if not valid_cidr(address):
            return "адрес нужен в виде 192.168.1.10/24"
        if gateway and not valid_ipv4(gateway):
            return "шлюз некорректен"
        if any(not valid_ipv4(item) for item in dns):
            return "DNS должен быть списком IPv4"
    if command(["systemctl", "is-active", "NetworkManager"])[1] == "active" and shutil.which("nmcli"):
        return apply_nm(iface, mode, address, gateway, dns)
    if not shutil.which("netplan"):
        return "нет netplan и NetworkManager, адрес некуда записать"
    return apply_netplan(iface, mode, address, gateway, dns)


def apply_nm(iface: str, mode: str, address: str, gateway: str, dns: list) -> str:
    _, text = command(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show"])
    name = iface
    for line in text.splitlines():
        title, separator, device = line.partition(":")
        if separator and device == iface:
            name = title
            break
    if mode == "dhcp":
        code, detail = command(["nmcli", "connection", "modify", name, "ipv4.method", "auto", "ipv4.gateway", "", "ipv4.addresses", ""])
    else:
        args = ["nmcli", "connection", "modify", name, "ipv4.method", "manual", "ipv4.addresses", address]
        if gateway:
            args += ["ipv4.gateway", gateway]
        if dns:
            args += ["ipv4.dns", ",".join(dns)]
        code, detail = command(args)
    if code != 0:
        return detail or "NetworkManager не принял адрес"
    code, detail = command(["nmcli", "connection", "up", name], timeout=30)
    return detail or ("адрес применён" if code == 0 else "адрес записан, но соединение не поднялось")


def apply_netplan(iface: str, mode: str, address: str, gateway: str, dns: list) -> str:
    lines = ["network:", "  version: 2", "  ethernets:", f"    {iface}:"]
    if mode == "dhcp":
        lines.append("      dhcp4: true")
    else:
        lines += ["      dhcp4: false", "      addresses:", f"        - {address}"]
        if gateway:
            lines += ["      routes:", "        - to: default", f"          via: {gateway}"]
        if dns:
            lines += ["      nameservers:", "        addresses:"]
            lines += [f"          - {item}" for item in dns]
    path = Path("/etc/netplan") / f"99-onec-{iface}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    code, text = command(["netplan", "apply"], timeout=40)
    return text or ("адрес применён" if code == 0 else "netplan не применил адрес")


def update_log_path() -> Path:
    state = Path(os.environ.get("ONEC_STATE_DIR", "/var/lib/onec-console"))
    try:
        state.mkdir(parents=True, exist_ok=True)
    except OSError:
        state = Path("/tmp")
    return state / "update.log"


def update_log_text() -> str:
    path = update_log_path()
    if not path.is_file():
        return ""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(lines[-40:])


def schedule_update() -> str:
    if os.environ.get("ONEC_UPDATE") == "skip":
        return "обновление поставлено в очередь"
    if not shutil.which("git"):
        return "не установлен git. На сервере: apt install git"
    log_path = update_log_path()
    script_path = log_path.parent / "update.sh"
    script_path.write_text(
        f"""#!/bin/bash
set -eu
exec >> {log_path} 2>&1
echo "--- $(date -Is) ---"
git config --global --add safe.directory {SRC} || true
if [ ! -d {SRC}/.git ]; then
  rm -rf {SRC}
  git clone {REPO} {SRC}
fi
git -C {SRC} pull --ff-only
chmod +x {SRC}/build-deb.sh
deb=$({SRC}/build-deb.sh | tail -n 1)
dpkg -i "$deb"
echo "готово $deb"
""",
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    unit = f"onec-update-{int(time.time())}"
    if not shutil.which("systemd-run"):
        subprocess.Popen(["/bin/bash", str(script_path)], start_new_session=True)
        return f"обновление запущено. Журнал: {log_path}"
    code, text = command(
        ["systemd-run", "--collect", "--no-block", f"--unit={unit}", "/bin/bash", str(script_path)],
        timeout=20,
    )
    if code != 0:
        return text or "systemd-run не запустил обновление"
    return f"обновление запущено отдельно от службы ({unit}). Журнал: {log_path}"


def schedule_power(action: str) -> str:
    if action not in ("reboot", "poweroff"):
        return "неизвестное действие"
    if os.environ.get("ONEC_POWER") == "skip":
        return f"запрошено: {action}"
    if shutil.which("systemd-run"):
        command(["systemd-run", "--on-active=3s", "--no-block", "systemctl", action])
    else:
        subprocess.Popen(["systemctl", action], start_new_session=True)
    return f"{action} через несколько секунд"


def github_text(name: str) -> str:
    request = urllib.request.Request(f"{RAW}/{name}", headers={"User-Agent": "onec-console"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read().decode()


def github_release() -> dict:
    if os.environ.get("ONEC_RELEASE") == "skip":
        return {"title": "v1.2.4", "body": "тест", "url": WEB, "when": "", "source": "readme"}
    meta = {"title": "", "url": WEB, "when": "", "source": "readme"}
    for path, source in (("releases/latest", "release"), ("commits/main", "commit")):
        request = urllib.request.Request(
            f"https://api.github.com/repos/GrafAtRuss/server/{path}",
            headers={"User-Agent": "onec-console", "Accept": "application/vnd.github+json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode())
        except urllib.error.HTTPError:
            continue
        except OSError as error:
            return {"error": str(error), "body": "", "url": WEB}
        if source == "release":
            meta = {
                "title": data.get("tag_name") or data.get("name") or "",
                "url": data.get("html_url") or WEB,
                "when": data.get("published_at") or "",
                "source": "readme",
            }
        else:
            meta = {
                "title": (data.get("sha") or "")[:7],
                "url": data.get("html_url") or WEB,
                "when": ((data.get("commit") or {}).get("committer") or {}).get("date") or "",
                "source": "readme",
            }
        break
    else:
        return {"error": "GitHub не ответил.", "body": "", "url": WEB}
    try:
        meta["body"] = github_text("README.md")
    except urllib.error.HTTPError as error:
        return {**meta, "body": "", "error": f"README.md не прочитан: {error.code}"}
    except OSError as error:
        return {**meta, "body": "", "error": str(error)}
    return meta


def github_changelog() -> dict:
    if os.environ.get("ONEC_RELEASE") == "skip":
        return {"body": "## 1.2.4\n\nтест", "url": f"{WEB}/blob/main/CHANGELOG.md"}
    try:
        return {"body": github_text("CHANGELOG.md"), "url": f"{WEB}/blob/main/CHANGELOG.md"}
    except urllib.error.HTTPError as error:
        return {"error": f"CHANGELOG.md не прочитан: {error.code}", "url": f"{WEB}/blob/main/CHANGELOG.md"}
    except OSError as error:
        return {"error": str(error), "url": f"{WEB}/blob/main/CHANGELOG.md"}


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
