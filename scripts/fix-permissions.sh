#!/usr/bin/env bash
# SEE-Monitor: fix-permissions.sh
# =============================================================================
# Normalises ownership and modes across an installed SEE-Monitor tree. Safe to
# run after every deployment (git pull, zip extract, rsync) — it is idempotent
# and non-destructive: it never edits file *content* except to strip CRLF from
# shell scripts (which is required for them to run at all), and it never touches
# the database, the virtualenv's own binaries, secrets content, or .git.
#
# It exists because Git pushed from Windows loses the Unix execute bit, and zip
# extraction can too — leaving ExecStartPre and scripts/*.sh non-executable
# (systemd 203/EXEC). This restores a known-good scheme:
#
#     directories            0750  root:<group>
#     code / data files      0640  root:<group>
#     executables (*.sh,      0750  root:<group>
#       entrypoints, .py CLI)
#     config.yaml / *.env     0640  root:<group>   (content untouched)
#     *.db / *.db-wal/-shm    left as-is (never re-moded — would break writes)
#     .venv, .git, __pycache__ skipped entirely
#
# Usage:
#   sudo scripts/fix-permissions.sh [--prefix DIR] [--user NAME]
#                                   [--no-eol] [--dry-run]
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 SEE-Monitor Contributors
# AI-assisted development: portions generated with Claude (Anthropic)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$(cd "${SCRIPT_DIR}/.." && pwd)"      # default: parent of scripts/
SVC_USER="seemonitor"
FIX_EOL=true
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)  PREFIX="$2"; shift 2;;
    --user)    SVC_USER="$2"; shift 2;;
    --no-eol)  FIX_EOL=false; shift;;
    --dry-run) DRY_RUN=true; shift;;
    -h|--help)
      sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "Unknown option: $1" >&2; exit 1;;
  esac
done

info(){ echo "▸ $*"; }
run(){ if $DRY_RUN; then echo "   [dry-run] $*"; else "$@"; fi; }

[[ -f "${PREFIX}/see_monitor.py" ]] \
  || { echo "✗ ${PREFIX} is not a SEE-Monitor tree" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]] && ! $DRY_RUN; then
  echo "✗ Root required (chown/chmod). Re-run with sudo, or --dry-run." >&2
  exit 1
fi

# Resolve the group; fall back to the user's primary group if the named group
# does not exist yet.
GROUP="${SVC_USER}"
if ! getent group "${SVC_USER}" >/dev/null 2>&1; then
  GROUP="$(id -gn "${SVC_USER}" 2>/dev/null || echo root)"
fi

info "Normalising permissions under ${PREFIX} (owner root:${GROUP})"
$DRY_RUN && echo "   (dry-run: no changes)"

# Prune expression shared by the find passes: skip venv, git, pycache, DB files.
PRUNE=( -path "${PREFIX}/.venv" -o -path "${PREFIX}/.git"
        -o -name "__pycache__" -o -name "*.db" -o -name "*.db-wal"
        -o -name "*.db-shm" )

# 1) Ownership (excludes pruned paths).
run bash -c "find '${PREFIX}' \\( ${PRUNE[*]} \\) -prune -o \
  -print0 | xargs -0 -r chown -h root:'${GROUP}'"

# 2) Directories -> 0750.
run bash -c "find '${PREFIX}' \\( ${PRUNE[*]} \\) -prune -o \
  -type d -print0 | xargs -0 -r chmod 0750"

# 3) Regular files -> 0640.
run bash -c "find '${PREFIX}' \\( ${PRUNE[*]} \\) -prune -o \
  -type f -print0 | xargs -0 -r chmod 0640"

# 4) Executables -> 0750. Explicit entrypoints plus every *.sh, plus any file
#    under scripts/ that begins with a shebang.
declare -a EXECS=(
  "${PREFIX}/install.sh"
  "${PREFIX}/see_monitor.py"
)
while IFS= read -r -d '' f; do EXECS+=("$f"); done < <(
  find "${PREFIX}/scripts" -maxdepth 1 -type f \
       \( -name "*.sh" -o -name "*.py" \) -print0 2>/dev/null || true)

for f in "${EXECS[@]}"; do
  [[ -f "$f" ]] || continue
  run chmod 0750 "$f"
  ok_exec=true
done

# 5) Strip CRLF from shell scripts (fatal for '#!/bin/bash'). Content of other
#    files is never modified.
if $FIX_EOL; then
  while IFS= read -r -d '' f; do
    if grep -qU $'\r' "$f" 2>/dev/null; then
      info "Stripping CRLF from $(basename "$f")"
      run sed -i 's/\r$//' "$f"
    fi
  done < <(find "${PREFIX}" -maxdepth 2 -name "*.sh" -print0 2>/dev/null || true)
fi

# 6) Secrets: keep config.yaml tight if present (content untouched).
[[ -f "${PREFIX}/config/config.yaml" ]] && \
  run chmod 0640 "${PREFIX}/config/config.yaml"

echo "✓ Permissions normalised${DRY_RUN:+ (dry-run)}"
