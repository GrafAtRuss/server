#!/bin/sh
# Ставит python3-pymssql, а если его нет в репозитории — mssql-tools18.
set -eu
if python3 -c 'import pymssql' >/dev/null 2>&1; then
  exit 0
fi
if [ -x /opt/mssql-tools18/bin/sqlcmd ] || command -v sqlcmd >/dev/null 2>&1; then
  exit 0
fi
i=0
while [ "$i" -lt 60 ]; do
  if python3 -c 'import fcntl; f=open("/var/lib/dpkg/lock-frontend","a"); fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB); fcntl.flock(f, fcntl.LOCK_UN)' >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done
export DEBIAN_FRONTEND=noninteractive
apt-get update || true
apt-get install -y libcups2t64 || apt-get install -y libcups2 || true
if apt-get install -y python3-pymssql; then
  python3 -c 'import pymssql' >/dev/null 2>&1 && exit 0
fi
if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
  apt-get install -y curl ca-certificates gnupg || true
fi
. /etc/os-release
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor --yes -o /usr/share/keyrings/microsoft-prod.gpg
curl -fsSL "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/prod.list" -o /etc/apt/sources.list.d/mssql-release.list
apt-get update || true
ACCEPT_EULA=Y apt-get install -y mssql-tools18 || true
