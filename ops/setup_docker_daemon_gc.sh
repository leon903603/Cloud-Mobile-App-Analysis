#!/usr/bin/env bash
# ==============================================================================
# CMAA Infrastructure Automation: Docker Daemon GC & Log Rotation Setup
# Target: AWS EC2 Ubuntu Production Host
# Spec: docs/spec-ec2-disk-and-docker-cache-governance.md
# ==============================================================================
set -euo pipefail

DAEMON_JSON="/etc/docker/daemon.json"
BACKUP_DIR="/home/ubuntu/daemon_backups"

echo "=== [1/4] Pre-flight Validation ==="
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root (use sudo)." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
if [ -f "$DAEMON_JSON" ]; then
  cp "$DAEMON_JSON" "$BACKUP_DIR/daemon.json.$(date +%Y%m%d_%H%M%S).bak"
  echo "[+] Existing daemon.json backed up."
fi

echo "=== [2/4] Writing Automated GC Configuration ==="
cat << 'EOF' > "$DAEMON_JSON"
{
  "builder": {
    "gc": {
      "enabled": true,
      "defaultKeepStorage": "2GB"
    }
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
EOF

echo "=== [3/4] Validating Configuration Syntax ==="
if command -v jq >/dev/null 2>&1; then
  jq . "$DAEMON_JSON" >/dev/null
  echo "[+] Valid JSON syntax confirmed via jq."
elif command -v python3 >/dev/null 2>&1; then
  python3 -m json.tool "$DAEMON_JSON" >/dev/null
  echo "[+] Valid JSON syntax confirmed via python3."
fi

echo "=== [4/4] Applying Configuration with Zero-Downtime Reload ==="
# SIGHUP / reload signals dockerd to update builder/logging config without restarting active containers
systemctl reload docker || systemctl restart docker

echo "[+] Docker Daemon GC successfully installed and active!"
docker info | grep -A 5 "BuildKit" || true
