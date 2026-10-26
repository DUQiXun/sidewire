#!/usr/bin/env bash
# SideWire agent installer for the machine you want to control (Linux).
#
#   sudo ./install-agent.sh                 # install + start as a service
#   sudo ./install-agent.sh --port 7900 --allow-sudo --allow-pkg
#   ./install-agent.sh --uninstall
#
# It is deliberately boring: copy one file, generate one key, write one unit.

set -euo pipefail

PORT=7900
ALLOW_SUDO=0
ALLOW_PKG=0
ALLOW_POWER=0
CIDR=""
PREFIX=/opt/sidewire
ETC=/etc/sidewire
SERVICE=sidewire-agentd
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --allow-sudo) ALLOW_SUDO=1; shift ;;
        --allow-pkg) ALLOW_PKG=1; shift ;;
        --allow-power) ALLOW_POWER=1; shift ;;
        --allow-cidr) CIDR="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" != "0" ]; then
    echo "run me with sudo" >&2
    exit 1
fi

if [ "$UNINSTALL" = "1" ]; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$PREFIX"
    echo "removed the service. $ETC (the key) was left alone on purpose."
    exit 0
fi

SRC="$(cd "$(dirname "$0")" && pwd)/sidewire_agentd.py"
if [ ! -f "$SRC" ]; then
    echo "sidewire_agentd.py not found next to this script" >&2
    exit 1
fi

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

install -d -m 755 "$PREFIX" "$ETC"
install -m 755 "$SRC" "$PREFIX/sidewire_agentd.py"

if [ ! -f "$ETC/agent.key" ]; then
    python3 "$PREFIX/sidewire_agentd.py" --keygen --out "$ETC/agent.key" >/dev/null
    chmod 600 "$ETC/agent.key"
    echo "generated a new key at $ETC/agent.key"
else
    echo "reusing the existing key at $ETC/agent.key"
fi

EXTRA=""
[ "$ALLOW_SUDO" = "1" ] && EXTRA="$EXTRA --allow-sudo"
[ "$ALLOW_PKG" = "1" ] && EXTRA="$EXTRA --allow-pkg"
[ "$ALLOW_POWER" = "1" ] && EXTRA="$EXTRA --allow-power"
[ -n "$CIDR" ] && EXTRA="$EXTRA --allow-cidr $CIDR"

cat > "/etc/systemd/system/$SERVICE.service" <<UNIT
[Unit]
Description=SideWire agent daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(command -v python3) $PREFIX/sidewire_agentd.py --key-file $ETC/agent.key --port $PORT$EXTRA
Restart=always
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 0.5
systemctl --no-pager --lines=3 status "$SERVICE" || true

# firewall, best effort
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q active; then
    ufw allow "$PORT/tcp" >/dev/null 2>&1 && echo "opened $PORT/tcp in ufw"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1 && echo "opened $PORT/tcp in firewalld"
fi

KEY="$(cat "$ETC/agent.key")"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<DONE

  hostname : $(hostname)
  address  : ${IP:-<this machine>}
  port     : $PORT
  key      : $KEY

  on the machine that runs your agent:

    sidewire add sub ${IP:-<ip>} --key $KEY --default

  check it:

    sidewire ping sub

DONE
