#!/bin/bash
#
# rfxn-defense-update.sh
#   4-hourly responsive auto-update wrapper, driven by
#   /etc/cron.d/rfxn-defense-update.
#
# Behavior:
#   - EL7-EL10 compatible (uses /usr/bin/flock, /usr/bin/timeout,
#     dnf-or-yum auto-detect)
#   - Single-runner via flock -n (skips if a prior run is still active)
#   - Random jitter 0-600s before work (spreads mirror load on fleets)
#   - 600s total timeout cap on the upgrade transaction
#   - Targeted dnf upgrade of rfxn-defense* from the rfxn-defense repo
#     only (--disablerepo='*' --enablerepo='rfxn-defense')
#   - All output piped to journald via 'logger -t rfxn-defense-update'
#   - Opt-out: touch /etc/rfxn-defense/auto-update.disabled
#   - Dry-run for tests: CFD_AUTOUPDATE_DRY_RUN=1 exits 0 before dnf
#     fires (used by packaging/test-repo.sh container assertions)

set -euo pipefail

DISABLE_FILE=/etc/rfxn-defense/auto-update.disabled
LOCK_FILE=/run/lock/rfxn-defense-update.lock
LOG_TAG=rfxn-defense-update
JITTER_MAX_SECONDS=600
UPGRADE_TIMEOUT_SECONDS=600
REPO_ID=rfxn-defense

log() {
    logger -t "${LOG_TAG}" -- "$*" || true
}

if [ -f "${DISABLE_FILE}" ]; then
    log "skip: ${DISABLE_FILE} present (operator opt-out)"
    exit 0
fi

# Single-runner via flock -n. Non-blocking: if a prior 4-hour run is
# still active (slow mirrors, network stall), skip this tick rather
# than queue. Lock fd 9 stays open for the wrapper's lifetime.
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    log "skip: prior run still active (lock held on ${LOCK_FILE})"
    exit 0
fi

# Jitter 0..JITTER_MAX_SECONDS to spread mirror load. Seed mixes
# hostname so time-synced hosts diverge on the same cron tick.
host_cksum=$(hostname | cksum | cut -d' ' -f1)
seed_num=$(( $(date +%s) * 1000000 + $$ * 10000 + host_cksum % 10000 ))
jitter=$(awk -v seed="$seed_num" \
    'BEGIN{srand(seed); print int(rand()*'"${JITTER_MAX_SECONDS}"')}')
log "jitter: sleeping ${jitter}s before upgrade"
sleep "${jitter}"

# Auto-detect dnf vs yum. EL7 stock ships yum; dnf is available via
# EPEL but not in the minimal base. Both honor --disablerepo / --enablerepo.
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR=dnf
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR=yum
else
    log "error: neither dnf nor yum available; cannot upgrade"
    exit 1
fi

if [ "${CFD_AUTOUPDATE_DRY_RUN:-0}" = "1" ]; then
    log "dry-run: would invoke ${PKG_MGR} upgrade rfxn-defense*"
    exit 0
fi

log "begin: ${PKG_MGR} upgrade rfxn-defense* (timeout=${UPGRADE_TIMEOUT_SECONDS}s)"
# shellcheck disable=SC2024
if timeout "${UPGRADE_TIMEOUT_SECONDS}s" "${PKG_MGR}" -y \
        --disablerepo='*' --enablerepo="${REPO_ID}" \
        upgrade 'rfxn-defense*' 2>&1 \
        | logger -t "${LOG_TAG}"; then
    log "end: ${PKG_MGR} upgrade succeeded"
    exit 0
fi
rc=$?
if [ "${rc}" = "124" ]; then
    log "error: upgrade timed out after ${UPGRADE_TIMEOUT_SECONDS}s"
else
    log "error: upgrade failed (rc=${rc})"
fi
exit "${rc}"
