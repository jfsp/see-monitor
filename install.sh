#!/usr/bin/env bash
# SEE-Monitor: Installer
# =============================================================================
# Installs all components (system user, directories, Python venv, application
# code, configuration, and systemd units) on a Debian/Ubuntu-style host.
#
# SAFETY MODEL — this script is deliberately non-destructive:
#   * Instance state is NEVER overwritten: the secrets env file, config.yaml,
#     the SQLite database and the virtualenv are written only if absent.
#   * systemd units are backed up to <unit>.bak.<timestamp> before being
#     replaced, so previous content is always recoverable.
#   * Application code under the prefix is only overwritten on an explicit
#     --upgrade, and even then every replaced file is preserved in a
#     timestamped backup directory.
#   * --dry-run prints every action without touching the system.
#
# Usage:
#   sudo ./install.sh [OPTIONS]
#
# Options:
#   --prefix DIR       Install code here            (default: /opt/see-monitor)
#   --config-dir DIR   Secrets env file location    (default: /etc/see-monitor)
#   --data-dir DIR     Database / runtime state      (default: /var/lib/see-monitor)
#   --log-dir DIR      Log directory                 (default: /var/log/see-monitor)
#   --user NAME        Service user/group            (default: seemonitor)
#   --bind ADDR:PORT   Gunicorn bind for the env     (default: 127.0.0.1:5000)
#   --upgrade          Allow overwriting existing application code (with backup)
#   --no-venv          Skip virtualenv creation / pip install
#   --no-systemd       Skip installing systemd units
#   --start            Enable AND start services now (default: enable only)
#   --dry-run          Show what would happen, change nothing
#   -h, --help         This help
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 SEE-Monitor Contributors
# AI-assisted development: portions generated with Claude (Anthropic)

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/see-monitor"
CONFIG_DIR="/etc/see-monitor"
DATA_DIR="/var/lib/see-monitor"
LOG_DIR="/var/log/see-monitor"
SVC_USER="seemonitor"
BIND="127.0.0.1:5000"
UPGRADE=false
DO_VENV=true
DO_SYSTEMD=true
DO_START=false
DRY_RUN=false
TS="$(date +%Y%m%d-%H%M%S)"
MIN_PY_MINOR=10   # requires Python 3.10+ (type-union syntax in the codebase)

# ── Colours / logging ────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'
  CYN=$'\033[0;36m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; CYN=""; BLD=""; RST=""
fi
info(){ echo "${CYN}▸${RST} $*"; }
ok(){   echo "${GRN}✓${RST} $*"; }
warn(){ echo "${YEL}⚠${RST} $*" >&2; }
err(){  echo "${RED}✗${RST} $*" >&2; }
die(){  err "$*"; exit 1; }

# run CMD... — execute, or just print in dry-run mode
run(){
  if $DRY_RUN; then echo "   ${BLD}[dry-run]${RST} $*"; else "$@"; fi
}

usage(){ sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)     PREFIX="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    --data-dir)   DATA_DIR="$2"; shift 2;;
    --log-dir)    LOG_DIR="$2"; shift 2;;
    --user)       SVC_USER="$2"; shift 2;;
    --bind)       BIND="$2"; shift 2;;
    --upgrade)    UPGRADE=true; shift;;
    --no-venv)    DO_VENV=false; shift;;
    --no-systemd) DO_SYSTEMD=false; shift;;
    --start)      DO_START=true; shift;;
    --dry-run)    DRY_RUN=true; shift;;
    -h|--help)    usage;;
    *) die "Unknown option: $1 (try --help)";;
  esac
done

ENV_FILE="${CONFIG_DIR}/see-monitor.env"
CONFIG_FILE="${PREFIX}/config/config.yaml"
DB_FILE="${DATA_DIR}/see_monitor.db"
VENV="${PREFIX}/.venv"
PYBIN="${VENV}/bin/python"

echo "${BLD}SEE-Monitor installer${RST}"
echo "  source        : ${SRC_DIR}"
echo "  prefix        : ${PREFIX}"
echo "  config (env)  : ${ENV_FILE}"
echo "  config (yaml) : ${CONFIG_FILE}"
echo "  data / db     : ${DB_FILE}"
echo "  logs          : ${LOG_DIR}"
echo "  service user  : ${SVC_USER}"
echo "  bind          : ${BIND}"
$DRY_RUN && warn "DRY-RUN: no changes will be made"
echo

# ── Pre-flight checks ────────────────────────────────────────────────────────
info "Running pre-flight checks"

[[ -f "${SRC_DIR}/see_monitor.py" && -f "${SRC_DIR}/app_factory.py" ]] \
  || die "This does not look like the SEE-Monitor source tree (${SRC_DIR})."

if [[ ${EUID} -ne 0 ]] && ! $DRY_RUN; then
  die "Root privileges required (creates a system user, writes to ${PREFIX},
     ${CONFIG_DIR}, ${DATA_DIR} and installs systemd units). Re-run with sudo,
     or use --dry-run to preview."
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found."
PY_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])')"
if (( PY_MINOR < MIN_PY_MINOR )); then
  die "Python 3.${MIN_PY_MINOR}+ required (found 3.${PY_MINOR})."
fi
ok "Python 3.${PY_MINOR} detected"

if $DO_VENV; then
  python3 -c 'import venv' 2>/dev/null \
    || die "The python3 venv module is missing. Install it (e.g. apt-get
       install python3-venv) or re-run with --no-venv."
fi

SYSTEMCTL=""
if $DO_SYSTEMD; then
  if command -v systemctl >/dev/null 2>&1; then
    SYSTEMCTL="$(command -v systemctl)"
  else
    warn "systemctl not found; skipping systemd unit installation."
    DO_SYSTEMD=false
  fi
fi

# Warn (do not fail) if the chosen bind port is already in use.
BIND_PORT="${BIND##*:}"
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${BIND_PORT}$"; then
    warn "Something is already listening on port ${BIND_PORT}. If PQC-Monitor
     or another service owns it, choose a different --bind (e.g. 127.0.0.1:5001)
     and update systemd/nginx accordingly."
  fi
fi
ok "Pre-flight checks passed"
echo

# ── Helper: install a file only if the destination is ABSENT ─────────────────
# keep_file SRC DST MODE OWNER GROUP
keep_file(){
  local src="$1" dst="$2" mode="$3" owner="$4" group="$5"
  if [[ -e "$dst" ]]; then
    warn "Keeping existing ${dst} (not overwritten)"
    return 0
  fi
  run install -D -m "$mode" -o "$owner" -g "$group" "$src" "$dst"
  ok "Installed ${dst}"
}

# ── 1. Service user/group ────────────────────────────────────────────────────
info "Ensuring service user '${SVC_USER}'"
if id "${SVC_USER}" >/dev/null 2>&1; then
  ok "User '${SVC_USER}' already exists"
else
  run useradd --system --no-create-home --shell /usr/sbin/nologin \
      --home-dir "${PREFIX}" "${SVC_USER}"
  ok "Created system user '${SVC_USER}'"
fi
echo

# ── 2. Directories ───────────────────────────────────────────────────────────
info "Creating directories"
run install -d -m 0750 -o root            -g "${SVC_USER}" "${PREFIX}"
run install -d -m 0750 -o root            -g "${SVC_USER}" "${CONFIG_DIR}"
run install -d -m 0750 -o "${SVC_USER}"   -g "${SVC_USER}" "${DATA_DIR}"
run install -d -m 0750 -o "${SVC_USER}"   -g "${SVC_USER}" "${LOG_DIR}"
ok "Directories ready"
echo

# ── 3. Application code ──────────────────────────────────────────────────────
info "Installing application code to ${PREFIX}"
CODE_EXCLUDES=(
  --exclude ".git/"            --exclude "__pycache__/"
  --exclude "*.pyc"            --exclude "*.pyo"
  --exclude ".venv/"           --exclude ".pytest_cache/"
  --exclude "config/config.yaml"                # never touch instance config
  --exclude "*.db" --exclude "*.db-wal" --exclude "*.db-shm"
  --exclude ".env"
)
ALREADY_INSTALLED=false
[[ -f "${PREFIX}/app_factory.py" ]] && ALREADY_INSTALLED=true

if $ALREADY_INSTALLED && ! $UPGRADE; then
  warn "Existing installation detected at ${PREFIX}."
  warn "Code was NOT modified. Re-run with --upgrade to update code"
  warn "(replaced files are backed up), or use scripts/deploy.sh."
else
  if command -v rsync >/dev/null 2>&1; then
    BACKUP_ARGS=()
    if $ALREADY_INSTALLED; then
      local_backup="${PREFIX}.bak.${TS}"
      BACKUP_ARGS=(--backup --backup-dir "${local_backup}")
      warn "Upgrading: replaced files will be preserved in ${local_backup}"
    fi
    run rsync -a "${CODE_EXCLUDES[@]}" "${BACKUP_ARGS[@]}" \
        "${SRC_DIR}/" "${PREFIX}/"
  else
    # Fallback without rsync: back up the whole tree first if upgrading.
    if $ALREADY_INSTALLED; then
      run cp -a "${PREFIX}" "${PREFIX}.bak.${TS}"
      warn "Backed up existing install to ${PREFIX}.bak.${TS}"
    fi
    run cp -a "${SRC_DIR}/." "${PREFIX}/"
    run rm -rf "${PREFIX}/.git" "${PREFIX}/.venv" "${PREFIX}/.pytest_cache"
  fi
  # Ownership: code owned root, readable by the service group; no world access.
  run chown -R root:"${SVC_USER}" "${PREFIX}"
  # Re-assert service-writable paths that live under the prefix (none by
  # default) and protect the tree from other users.
  run chmod -R o-rwx "${PREFIX}"
  # Canonical permission normalisation (exec bits, CRLF, ownership). This is
  # the same script deployments should run after a git pull.
  if [[ -f "${PREFIX}/scripts/fix-permissions.sh" ]]; then
    run bash "${PREFIX}/scripts/fix-permissions.sh" \
        --prefix "${PREFIX}" --user "${SVC_USER}"
  fi
  ok "Application code installed"
fi
echo

# ── 4. Virtualenv + dependencies ─────────────────────────────────────────────
if $DO_VENV; then
  info "Setting up Python virtualenv"
  if [[ -x "${PYBIN}" ]]; then
    ok "Virtualenv already present at ${VENV} (left as-is)"
  else
    run python3 -m venv "${VENV}"
    ok "Created virtualenv"
  fi
  run "${VENV}/bin/pip" install --upgrade pip -q
  run "${VENV}/bin/pip" install -r "${PREFIX}/requirements.txt" -q
  run chown -R root:"${SVC_USER}" "${VENV}"
  ok "Dependencies installed"
else
  warn "Skipping virtualenv (--no-venv)"
fi
echo

# ── 5. Secrets env file (never overwritten) ──────────────────────────────────
info "Installing secrets env file"
if [[ -e "${ENV_FILE}" ]]; then
  warn "Keeping existing ${ENV_FILE} (secrets not overwritten)"
else
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  TMP_ENV="$(mktemp)"
  # Derive from the shipped template so it stays in sync, then fill in the
  # generated secret and the chosen bind address.
  sed -e "s|^SEE_SECRET_KEY=.*|SEE_SECRET_KEY=${SECRET}|" \
      -e "s|^SEE_CONFIG=.*|SEE_CONFIG=${PREFIX}/config/config.yaml|" \
      -e "s|^SEE_BIND=.*|SEE_BIND=${BIND}|" \
      "${SRC_DIR}/systemd/see-monitor.env" > "${TMP_ENV}"
  if $DRY_RUN; then
    echo "   ${BLD}[dry-run]${RST} write ${ENV_FILE} (mode 640, secret generated)"
    rm -f "${TMP_ENV}"
  else
    install -D -m 0640 -o root -g "${SVC_USER}" "${TMP_ENV}" "${ENV_FILE}"
    rm -f "${TMP_ENV}"
    ok "Wrote ${ENV_FILE} with a freshly generated SEE_SECRET_KEY"
  fi
fi
echo

# ── 6. config.yaml (never overwritten) ───────────────────────────────────────
info "Installing config.yaml"
if [[ -e "${CONFIG_FILE}" ]]; then
  warn "Keeping existing ${CONFIG_FILE} (not overwritten)"
else
  TMP_CFG="$(mktemp)"
  # Point db_path at the absolute data dir so the web app and scheduler agree.
  sed -e "s|^db_path:.*|db_path: ${DB_FILE}|" \
      "${SRC_DIR}/config/config.yaml.example" > "${TMP_CFG}"
  if $DRY_RUN; then
    echo "   ${BLD}[dry-run]${RST} write ${CONFIG_FILE} (db_path=${DB_FILE})"
    rm -f "${TMP_CFG}"
  else
    install -D -m 0640 -o root -g "${SVC_USER}" "${TMP_CFG}" "${CONFIG_FILE}"
    rm -f "${TMP_CFG}"
    ok "Wrote ${CONFIG_FILE} (db_path=${DB_FILE})"
  fi
fi
echo

# ── 7. Database schema + default admin (only if DB absent) ───────────────────
info "Initialising database"
if [[ -e "${DB_FILE}" ]]; then
  warn "Keeping existing database ${DB_FILE} (schema untouched)"
elif ! $DO_VENV; then
  warn "Skipping DB init (no venv). Run later:
     sudo -u ${SVC_USER} ${PYBIN} ${PREFIX}/see_monitor.py init-db"
else
  if $DRY_RUN; then
    echo "   ${BLD}[dry-run]${RST} sudo -u ${SVC_USER} ${PYBIN} see_monitor.py init-db"
  else
    ( cd "${PREFIX}" && \
      run_env="SEE_CONFIG=${PREFIX}/config/config.yaml" && \
      sudo -u "${SVC_USER}" env "${run_env}" "${PYBIN}" \
        "${PREFIX}/see_monitor.py" init-db )
    ok "Database created (default admin: admin / changeme123 — CHANGE IT)"
  fi
fi
echo

# ── 8. systemd units (backed up before replacing) ────────────────────────────
if $DO_SYSTEMD; then
  info "Installing systemd units"
  UNIT_DST="/etc/systemd/system"
  for unit in see-monitor-web.service see-monitor-scheduler.service \
              see-monitor.target; do
    src="${SRC_DIR}/systemd/${unit}"
    dst="${UNIT_DST}/${unit}"
    [[ -f "$src" ]] || { warn "Missing ${src}, skipping"; continue; }
    if [[ -e "$dst" ]] && ! cmp -s "$src" "$dst"; then
      run cp -a "$dst" "${dst}.bak.${TS}"
      warn "Backed up existing ${unit} to ${unit}.bak.${TS}"
    fi
    run install -m 0644 -o root -g root "$src" "$dst"
    ok "Installed ${unit}"
  done
  run "${SYSTEMCTL}" daemon-reload

  if $DO_START; then
    run "${SYSTEMCTL}" enable --now see-monitor.target
    ok "Enabled and started see-monitor.target"
  else
    run "${SYSTEMCTL}" enable see-monitor.target
    ok "Enabled see-monitor.target on boot (not started)"
  fi
else
  warn "Skipping systemd unit installation (--no-systemd)"
fi
echo

# ── Summary / next steps ─────────────────────────────────────────────────────
echo "${BLD}${GRN}Installation complete.${RST}"
echo
echo "Next steps:"
echo "  1. Review ${CONFIG_FILE} (scanning options, Shodan/Censys keys, scoring)."
echo "  2. Review ${ENV_FILE} (SEE_BIND, workers). Keep it mode 640, root:${SVC_USER}."
echo "  3. Put nginx in front for TLS (see systemd/nginx-see-monitor.conf) and"
echo "     set https_enabled: true in config.yaml once TLS terminates ahead of it."
if ! $DO_START; then
  echo "  4. Start the stack:  sudo systemctl start see-monitor.target"
fi
echo "  5. Log in and immediately change the default admin password."
echo
if command -v pgrep >/dev/null 2>&1 && pgrep -f "pqc[_-]monitor" >/dev/null 2>&1; then
  warn "PQC-Monitor appears to be running on this host. Make sure SEE_BIND"
  warn "(${BIND}) and the nginx server_name differ from PQC-Monitor's, and that"
  warn "the two tools do not share the same SEE_SECRET_KEY."
fi
$DRY_RUN && echo "${YEL}(dry-run: nothing was changed)${RST}"
