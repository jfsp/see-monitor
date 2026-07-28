# SEE-Monitor: shared systemd restart helpers
# ============================================================================
# Sourced by scripts/deploy.sh and scripts/sync-tree.sh.
#
# Provides a race-free restart of interdependent units. The scheduler unit
# declares `Requires=see-monitor-web.service`, so restarting the web unit makes
# systemd stop-and-restart the scheduler too. A naive `is-active` check taken
# *after* restarting web therefore races that propagation and can report a
# running scheduler as stopped. The helpers below avoid this by snapshotting
# unit state BEFORE any restart and polling for each unit to settle afterwards.
#
# This file is meant to be *sourced*, not executed, and needs no execute bit.
# It depends on ok()/warn()/err() from the caller and defines safe fallbacks so
# it can also be sourced standalone (e.g. in tests).
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 SEE-Monitor Contributors
# AI-assisted development: portions generated with Claude (Anthropic)

# Fallback loggers — only defined if the caller has not already provided them.
declare -F ok   >/dev/null 2>&1 || ok()   { echo "* $*"; }
declare -F warn >/dev/null 2>&1 || warn() { echo "! $*"; }
declare -F err  >/dev/null 2>&1 || err()  { echo "x $*" >&2; }

# Tunables (callers may override before sourcing or before the call):
#   RESTART_SETTLE_TIMEOUT  seconds to wait for a unit to become active again.
#   RESTART_CTX             noun used in the skip message ("... before <ctx>").
: "${RESTART_SETTLE_TIMEOUT:=15}"
: "${RESTART_CTX:=restart}"

# svc_up UNIT
# Succeeds while the unit is up or on its way up. `systemctl is-active` prints a
# single word; active/activating/reloading all count as "up" so a unit caught
# mid-transition is not misread as stopped.
svc_up() {
    local st
    st="$(systemctl is-active "$1" 2>/dev/null || true)"
    [[ "${st}" == "active" || "${st}" == "activating" || "${st}" == "reloading" ]]
}

# restart_units UNIT [UNIT...]
# Restart the given units, in the order supplied — list a unit before any other
# unit that Requires= it (e.g. web before scheduler). A unit that was not
# running before the call is left alone. Returns 0 if every unit that was
# restarted came back up, or 1 if any failed to restart or to settle.
restart_units() {
    local units=("$@") u i failures=0
    local -A was_up=()

    # Snapshot BEFORE restarting anything: restarting one unit can bounce
    # another via Requires=, so a live check afterwards would race against the
    # restart this very function triggers.
    for u in "${units[@]}"; do
        if svc_up "${u}"; then was_up["${u}"]=1; else was_up["${u}"]=0; fi
    done

    for u in "${units[@]}"; do
        if [[ "${was_up[${u}]}" != "1" ]]; then
            warn "${u} was not running before ${RESTART_CTX} — skipping restart."
            continue
        fi
        if ! systemctl restart "${u}"; then
            err "Failed to restart ${u}"
            failures=$((failures + 1))
            continue
        fi
        # Dependency-propagated restarts take a moment to converge; poll rather
        # than reading a single instant.
        for (( i = 0; i < RESTART_SETTLE_TIMEOUT; i++ )); do
            svc_up "${u}" && break
            sleep 1
        done
        if svc_up "${u}"; then
            ok "Restarted ${u}"
        else
            err "${u} did not return to active after restart (check: systemctl status ${u})"
            failures=$((failures + 1))
        fi
    done

    (( failures == 0 ))
}
