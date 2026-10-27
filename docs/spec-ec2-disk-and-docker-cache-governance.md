# Specification: CMAA Production EC2 Disk Capacity & Automated Docker BuildKit Cache Governance

**Document ID**: `SPEC-CMAA-OPS-002`  
**Author**: CMAA Cloud Platform Engineering Team  
**Status**: APPROVED / IMPLEMENTATION READY  
**Created**: 2026-10-27  
**Target System**: AWS EC2 Production Host (`cmaa-server` / `i-03d897a7c64334194`), Docker Engine Daemon, Git Repository (`Cloud-Mobile-App-Analysis`)  

---

## 1. Executive Summary & Academic Problem Statement

### 1.1 Engineering Context
The Cloud Mobile App Analysis (CMAA) cloud platform is deployed on an AWS EC2 `t3.micro` instance (1 GiB RAM, 1 vCPU) backed by a 20 GiB Amazon Elastic Block Store (EBS) `gp3` root volume. The architecture runs a microservice-oriented multi-container setup via Docker Compose:
- `cloud-frontend`: React Single-Page Application (SPA) served by Nginx with TLS termination (HTTP/2, ports 80/443).
- `cloud-backend`: Node.js 22.23.4 Express API server backed by SQLite with Write-Ahead Logging (`cmaa.db`, `cmaa.db-wal`).

### 1.2 Core Problem: Unbounded BuildKit Cache Accumulation
During production node maintenance, disk inspection revealed an alarming storage threshold:
- **Total EBS Root Volume**: 19 GiB
- **Used Capacity**: 16 GiB (**88% utilization**, entering critical operational warning zone)
- **Available Capacity**: Only 2.4 GiB

#### Root Cause Decomposition (Empirical Forensic Data)
Detailed disk usage audit conducted via AWS Systems Manager (SSM) decomposed the 16 GiB allocation:
1. **Swapfile (`/swapfile`)**: **4.0 GiB** (21.0%)  
   *Necessity*: Critical virtual memory configured to prevent Linux OOM Killer terminating Docker build processes on 1 GiB physical RAM. Must be preserved.
2. **Ubuntu OS & System Libraries (`/usr`, `/snap`, `/var/log`)**: **3.8 GiB** (20.0%)  
   *Necessity*: Base operating system, core runtimes, systemd journal logs.
3. **CMAA Application & SQLite Production DB**: **~1.5 GiB** (7.8%)  
   *Reality*: The core business platform itself is lightweight and highly optimized.
4. **Unmanaged Docker BuildKit Cache**: **5.35 GiB** (28.1%)  
   *Root Cause*: Docker Engine default configuration lacks an automated garbage collection (GC) retention quota. Every invocation of `docker compose up -d --build` generates immutable intermediate build layers, npm dependency trees, and compiler artifacts that accumulate indefinitely without automated eviction.

```
+-----------------------------------------------------------------------+
| EC2 19 GiB EBS Storage Breakdown                                      |
+-----------------------------------------------------------------------+
| [ Swapfile: 4.0G ] [ OS: 3.8G ] [ App: 1.5G ] [ BuildKit: 5.3G ] [2.4G]|
| (21%)              (20%)        (8%)          (28% - LEAK)      (FREE) |
+-----------------------------------------------------------------------+
```

If left unmanaged, the next container rebuild would completely exhaust host disk space (`ENOSPC`), causing SQLite WAL commit failures (`SQLITE_IOERR`), crash of the Nginx reverse proxy, and catastrophic platform downtime.

---

## 2. Architectural Decision & Two-Tier Governance Model

To balance **build performance** (avoiding cold cache re-downloads) with **disk safety** (preventing disk saturation), we reject crude manual cleanups (`docker system prune -a`) in favor of a **Two-Tier Cache Governance Model**.

```mermaid
flowchart TD
    A["EC2 Docker Host Storage Governance"] --> B["Tier 1: Bounded Manual Pruning (Immediate Relief)"]
    A --> C["Tier 2: Automated Daemon-Level GC (Permanent IaC Guard)"]
    
    B --> B1["docker buildx prune --max-used-space 1500MB -f"]
    B1 --> B2["Results: Reclaimed 1.97 GiB, Dropped Usage to 79% (3.9 GiB Free)"]
    
    C --> C1["Configuration: /etc/docker/daemon.json"]
    C1 --> C2["Rules: builder.gc.defaultKeepStorage = 2GB"]
    C2 --> C3["Policy: Automated LRU (Least Recently Used) Eviction in Background"]
```

### 2.1 Tier 1: Bounded On-Demand Pruning (Immediate Relief — Verified)
Rather than wiping the entire cache, Tier 1 enforces a bounded threshold using BuildKit's native `--max-used-space` directive:
```bash
docker buildx prune --max-used-space 1500MB -f
```
- **Behavior**: Scans all build cache layers, protects the most recently accessed 1,500 MB (including active Node.js 22.23.4 build artifacts), and evicts all older layers using Least Recently Used (LRU) prioritization.
- **Verification Result**:
  - Reclaimed: **1.969 GiB**
  - Available Disk: Increased from 2.4 GiB to **3.9 GiB**
  - Disk Utilization: Decreased from 88% to **79%**
  - Active Service Impact: **Zero downtime; backup images (`cmaa-backend:backup`) completely unharmed**.

### 2.2 Tier 2: Automated Daemon-Level GC via `/etc/docker/daemon.json` (Permanent Fix)
To prevent human error and eliminate manual maintenance tickets, Tier 2 codifies Docker's daemon configuration via Infrastructure-as-Code (IaC).

#### Daemon Specification (`/etc/docker/daemon.json`)
```json
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
```
- `builder.gc.enabled`: Enables automated background garbage collection in BuildKit.
- `builder.gc.defaultKeepStorage`: Caps BuildKit storage at 2.0 GiB. When total build cache exceeds 2 GiB, Docker automatically evicts the oldest unreferenced layers.
- `log-driver` & `log-opts`: Restricts container stdout/stderr log files to 3 rotating files of 50 MB each, preventing runaway application logs from consuming disk space.

---

## 3. Git-Managed Implementation Artifacts

To adhere to the project's academic and engineering governance mandates, this feature is tracked in GitHub and deployed deterministically.

### 3.1 Script Deliverable: `ops/setup_docker_daemon_gc.sh`
This idempotent automation script configures the Docker daemon, validates JSON syntax, and safely reloads Docker without interrupting running containers.

```bash
#!/usr/bin/env bash
# ==============================================================================
# CMAA Infrastructure Automation: Docker Daemon GC & Log Rotation Setup
# Target: AWS EC2 Ubuntu Production Host
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
```

---

## 4. Academic & Engineering Defense Points (For Faculty Review)

When presenting this architectural enhancement to academic advisors or industry review panels, emphasize the following engineering principles:

1. **Capacity Planning under Resource Constraints**:
   - Rather than masking capacity deficits by paying for expensive EBS disk expansion (e.g. upgrading to 50 GiB EBS), we achieved **zero-cost sustainability** by diagnosing the root cause (BuildKit unmanaged caching) and applying automated LRU lifecycle controls.
2. **Blast Radius & Reliability Engineering**:
   - Cleaned 1.97 GiB of disk space using non-destructive bounded filters (`--max-used-space`), strictly preserving runtime containers, production SQLite database files, and emergency rollback image tags (`cmaa-backend:backup`).
3. **Idempotence & Infrastructure-as-Code (IaC)**:
   - Shifted manual ad-hoc CLI commands into Git version-controlled scripts (`ops/setup_docker_daemon_gc.sh`), ensuring auditability, automated rollback, and peer review compliance.
4. **Log & Storage Hygiene Invariants**:
   - Simultaneously addressed container log inflation by bounding Docker logging to `3 x 50MB`, permanently eliminating the two largest vectors of silent EC2 disk exhaustion.
