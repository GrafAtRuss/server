#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
STAGE=$(mktemp -d)
VERSION=1.2.24
NAME=onec-console
DEST="$STAGE/${NAME}_${VERSION}_all"
OUT=${1:-$ROOT/${NAME}_${VERSION}_all.deb}

mkdir -p "$DEST/DEBIAN" \
  "$DEST/usr/lib/onec-console" \
  "$DEST/lib/systemd/system" \
  "$DEST/usr/share/doc/onec-console" \
  "$(dirname "$OUT")"

install -m 0644 "$ROOT/server.py" "$DEST/usr/lib/onec-console/server.py"
install -m 0644 "$ROOT/ops.py" "$DEST/usr/lib/onec-console/ops.py"
install -m 0644 "$ROOT/hostadmin.py" "$DEST/usr/lib/onec-console/hostadmin.py"
install -m 0644 "$ROOT/index.html" "$DEST/usr/lib/onec-console/index.html"
install -m 0644 "$ROOT/logo.png" "$DEST/usr/lib/onec-console/logo.png"
install -m 0755 "$ROOT/install-sql.sh" "$DEST/usr/lib/onec-console/install-sql.sh"

cat > "$DEST/lib/systemd/system/onec-console.service" << 'EOF'
[Unit]
Description=1C platform install console
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /usr/lib/onec-console/server.py
Restart=on-failure
RestartSec=2
Environment=ONEC_STATE_DIR=/var/lib/onec-console
Environment=ONEC_CACHE_DIR=/var/cache/onec-platform
Environment=ONEC_PASSWORD_FILE=/etc/onec-console/initial-password
Environment=ONEC_HOST=0.0.0.0
Environment=ONEC_PORT=8780

[Install]
WantedBy=multi-user.target
EOF

cat > "$DEST/DEBIAN/control" << EOF
Package: onec-console
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), git, iproute2, curl, ca-certificates, gnupg
Maintainer: Ermakov Alexey <alexey@localhost>
Description: Web console that installs the 1C platform
 Unpacks the server and thick-client zip archives and installs the
 deb packages in dependency order. The thin client is skipped.
 Operators sign in through the web panel and change their own
 passwords. The first password is stored in
 /etc/onec-console/initial-password and is not shown in the page.
EOF

cat > "$DEST/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -eu
install -d -m 0750 /var/lib/onec-console
install -d -m 0750 /var/cache/onec-platform
install -d -m 0755 /etc/onec-console
if [ ! -s /var/lib/onec-console/state.json ] && [ ! -s /etc/onec-console/initial-password ]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_urlsafe(12))' > /etc/onec-console/initial-password
  chmod 600 /etc/onec-console/initial-password
  echo "onec-console: first password is in /etc/onec-console/initial-password"
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --now onec-console.service
else
  echo "onec-console: start it with systemctl enable --now onec-console"
fi
if [ -x /usr/lib/onec-console/install-sql.sh ]; then
  if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemd-run --collect --on-active=8s --unit=onec-sqltools /usr/lib/onec-console/install-sql.sh || true
  else
    /usr/lib/onec-console/install-sql.sh || true
  fi
fi
echo "onec-console: panel on port 8780"
EOF

cat > "$DEST/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl stop onec-console.service || true
fi
EOF

cat > "$DEST/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "${1:-}" = "purge" ]; then
  rm -rf /var/lib/onec-console /var/cache/onec-platform /etc/onec-console
fi
EOF

cat > "$DEST/usr/share/doc/onec-console/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: onec-console
EOF

chmod 0755 "$DEST/DEBIAN/postinst" "$DEST/DEBIAN/prerm" "$DEST/DEBIAN/postrm"
dpkg-deb --root-owner-group --build "$DEST" "$OUT"
rm -rf "$STAGE"
echo "$OUT"
