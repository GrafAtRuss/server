#!/bin/sh
# Ставит библиотеки клиента 1С, python3-pymssql, а если его нет — mssql-tools18.
set -eu
export DEBIAN_FRONTEND=noninteractive
i=0
while [ "$i" -lt 60 ]; do
  if python3 -c 'import fcntl; f=open("/var/lib/dpkg/lock-frontend","a"); fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB); fcntl.flock(f, fcntl.LOCK_UN)' >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done
apt-get update || true
apt-get install -y libsm6 libice6 libx11-6 libxext6 libxrender1 libxtst6 libxi6 libxrandr2 libxinerama1 libxcursor1 libxfixes3 libxss1 libxt6 libxft2 libfontconfig1 libfreetype6 fonts-dejavu-core || true
apt-get install -y libcups2t64 || apt-get install -y libcups2 || true
apt-get install -y libgtk-3-0t64 || apt-get install -y libgtk-3-0 || true
if python3 -c 'import pymssql' >/dev/null 2>&1; then
  exit 0
fi
if [ -x /opt/mssql-tools18/bin/sqlcmd ] || command -v sqlcmd >/dev/null 2>&1; then
  exit 0
fi
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
