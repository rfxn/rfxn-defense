#!/bin/bash
#
# rfxn-defense-detect.sh
#   Detect IPsec / AFS / rootless-container workloads on the host
#   and decide which rfxn-defense conditional drop-ins to apply.
#
# Invoked from %posttrans of rfxn-defense-modprobe and
# rfxn-defense-systemd, and from /usr/sbin/rfxn-redetect.
#
# Modes:
#   apply  - decide, mutate /etc/, write auto-detect.json
set -euo pipefail

STATE_DIR="/var/lib/rfxn-defense"
STATE_FILE="${STATE_DIR}/auto-detect.json"
TEMPLATE_DIR="/usr/share/rfxn-defense/conditional"
ETC_MODPROBE="/etc/modprobe.d"
ETC_SYSTEMD="/etc/systemd/system"
ETC_SYSCTL="/etc/sysctl.d"
FORCE_FULL="/etc/rfxn-defense/force-full"
TOOL_VERSION="3.0.0"

# Active tenant units (must match SPEC §4.2 and v2.0.0 CF_CLASS_TENANT_UNITS)
TENANT_UNITS=("user@" "sshd" "cron" "crond" "atd")

# Logging tag matches v2.0.0 spec line 369 convention
LOGGER_TAG="rfxn-defense-detect"

log() {
    logger -t "${LOGGER_TAG}" -p authpriv.info "$*" 2>/dev/null || true
}

IPSEC_PRESENT="false"
IPSEC_SIGNALS=()

detect_ipsec() {
    local unit
    # D-51: strongswan-starter is the legacy ipsec daemon entry on
    # Fedora/EPEL strongswan packaging (verified against
    # repoquery --list strongswan: ships both strongswan.service AND
    # strongswan-starter.service in /usr/lib/systemd/system/).
    # pluto.service covers some libreswan downstream rebuilds.
    # frr REMOVED: BGP-only deployments dominate; FP > FN.
    for unit in strongswan strongswan-starter strongswan-swanctl \
                ipsec libreswan openswan pluto; do
        if systemctl is-enabled "${unit}.service" 2>/dev/null \
           | grep -qx 'enabled'; then
            IPSEC_PRESENT="true"
            IPSEC_SIGNALS+=("systemctl: ${unit}.service enabled")
        fi
    done
    if [ -f /etc/ipsec.conf ] && \
       grep -qE '^[[:space:]]*conn[[:space:]]+[^[:space:]]' /etc/ipsec.conf 2>/dev/null; then
        IPSEC_PRESENT="true"
        IPSEC_SIGNALS+=("/etc/ipsec.conf: contains conn stanza")
    fi
    local d
    for d in /etc/swanctl/conf.d /etc/ipsec.d /etc/strongswan/conf.d /etc/strongswan.d; do
        [ -d "${d}" ] || continue
        if find "${d}" -maxdepth 1 -name '*.conf' -type f \
           -not -empty 2>/dev/null | grep -q .; then
            IPSEC_PRESENT="true"
            IPSEC_SIGNALS+=("${d}: non-empty *.conf present")
        fi
    done
}

AFS_PRESENT="false"
AFS_SIGNALS=()

detect_afs() {
    local unit
    for unit in openafs-client openafs-server kafs afsd; do
        if systemctl is-enabled "${unit}.service" 2>/dev/null \
           | grep -qx 'enabled'; then
            AFS_PRESENT="true"
            AFS_SIGNALS+=("systemctl: ${unit}.service enabled")
        fi
    done
    local f
    for f in /etc/openafs/CellServDB /etc/openafs/ThisCell; do
        if [ -f "${f}" ]; then
            AFS_PRESENT="true"
            AFS_SIGNALS+=("${f}: present")
        fi
    done
    if find /etc/krb5.conf.d -maxdepth 1 -name 'openafs*' -type f \
       2>/dev/null | grep -q .; then
        AFS_PRESENT="true"
        AFS_SIGNALS+=("/etc/krb5.conf.d/openafs*: present")
    fi
    if [ -d /proc/fs/afs ]; then
        AFS_PRESENT="true"
        AFS_SIGNALS+=("/proc/fs/afs: kernel kafs filesystem registered")
    fi
}

ROOTLESS_PRESENT="false"
ROOTLESS_SIGNALS=()

detect_rootless_containers() {
    # Signal 1: per-user rootless podman storage tree (canonical
    # marker). Per containers/storage upstream defaults the rootless
    # storage path is $HOME/.local/share/containers/storage; the
    # overlay-containers subdirectory is created by podman on first
    # successful rootless container run. Bound the find traversal
    # to maxdepth 6 with -mtime -180 to avoid pathological /home
    # walks (M-5 deferred).
    if find /home -maxdepth 6 -type d \
            -name overlay-containers \
            -path '*/.local/share/containers/storage/overlay-containers' \
            -mtime -180 2>/dev/null | grep -q .; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("/home/*/.local/share/containers/storage/overlay-containers: present")
    fi

    # Signal 2: rootful container storage tree with recent activity.
    # Rejects long-stale podman installs (operator may have purged
    # rootless workflows but left the directory). 90-day mtime gate.
    if [ -d /var/lib/containers/storage ] && \
       find /var/lib/containers/storage -mindepth 1 -maxdepth 1 \
            -mtime -90 2>/dev/null | grep -q .; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("/var/lib/containers/storage: non-empty + mtime<90d")
    fi

    # Signal 3: per-user runtime tmpfs (live or recent rootless
    # podman activity). /run/user/<UID>/containers is podman's
    # XDG_RUNTIME_DIR child for rootless state. Tmpfs clears on
    # logout, so this is a strong "live use" signal.
    local rud
    for rud in /run/user/*/containers; do
        [ -d "${rud}" ] || continue
        local uid
        uid=$(printf '%s\n' "${rud}" | cut -d/ -f4)
        if [ -n "${uid}" ] && [ "${uid}" -ge 1000 ] 2>/dev/null; then
            ROOTLESS_PRESENT="true"
            ROOTLESS_SIGNALS+=("/run/user/${uid}/containers: present")
            break
        fi
    done

    # Signal 4: podman.socket enabled (system or any per-user instance).
    # System-wide check first (works in mock chroots that lack a session bus).
    if systemctl is-enabled podman.socket 2>/dev/null | grep -qx 'enabled'; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("systemctl: podman.socket enabled")
    fi
    # Per-user enumeration via loginctl (best-effort; failures are silent
    # in mock or on hosts without active sessions). The `|| true` is
    # required: pipefail + a failing loginctl (no D-Bus / no PID 1
    # systemd) would otherwise propagate rc=1 through the cmd-sub
    # and trip set -e on the assignment.
    if command -v loginctl >/dev/null 2>&1; then
        local lusers user
        lusers=$(loginctl list-users --no-legend 2>/dev/null \
                     | awk '{print $2}' || true)
        for user in ${lusers}; do
            [ -n "${user}" ] || continue
            if systemctl --user --machine="${user}@.host" \
                         is-enabled podman.socket 2>/dev/null \
                | grep -qx 'enabled'; then
                ROOTLESS_PRESENT="true"
                ROOTLESS_SIGNALS+=("systemctl --user (${user}): podman.socket enabled")
                break
            fi
        done
    fi
    return 0
}

USERNS_CONSUMERS_PRESENT="false"
USERNS_CONSUMERS_SIGNALS=()

# v2.0.2: distinct signal set from rootless containers. Catches userns
# consumers that the cf-class host-wide sysctl drop-in would break but
# that don't show up in the rootless-podman detector: Flatpak runtime
# (uses bwrap which needs CLONE_NEWUSER), firejail (explicit userns
# sandboxer), and desktop browsers (Chromium/Chrome/Firefox use
# unprivileged userns for their renderer sandbox on Linux).
#
# Triggers suppression of /etc/sysctl.d/99-rfxn-defense-userns.conf
# only - the per-unit systemd RestrictNamespaces=~user drop-in is
# unaffected (it scopes to the five tenant units).
detect_userns_consumers() {
    # Signal 1: Flatpak installed apps or runtimes (system-wide install).
    # /var/lib/flatpak is the canonical system path; per-user installs
    # live under /home/*/.local/share/flatpak/ - both walked here.
    local d
    for d in /var/lib/flatpak/app /var/lib/flatpak/runtime; do
        if [ -d "${d}" ] && \
           find "${d}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
               | grep -q .; then
            USERNS_CONSUMERS_PRESENT="true"
            USERNS_CONSUMERS_SIGNALS+=("${d}: non-empty (Flatpak install)")
        fi
    done
    if find /home -maxdepth 6 -type d \
            -path '*/.local/share/flatpak/app' \
            -mtime -180 2>/dev/null | grep -q .; then
        USERNS_CONSUMERS_PRESENT="true"
        USERNS_CONSUMERS_SIGNALS+=("/home/*/.local/share/flatpak/app: per-user Flatpak install")
    fi

    # Signal 2: firejail userns sandbox installed. Unlike bubblewrap
    # (which is a Flatpak dep on every workstation), firejail is only
    # installed when explicitly used - presence ~= active use.
    if [ -x /usr/bin/firejail ]; then
        USERNS_CONSUMERS_PRESENT="true"
        USERNS_CONSUMERS_SIGNALS+=("/usr/bin/firejail: installed")
    fi

    # Signal 3: desktop browser binaries. Chromium / Chrome / Firefox
    # default to unprivileged-userns renderer sandbox on Linux; with
    # user.max_user_namespaces=0 they fall back to setuid-sandbox where
    # available, but on hosts without that helper they hard-fail.
    # Presence on a server is unusual - if any of these exist, the host
    # is plausibly a workstation and we should not host-wide block userns.
    local b
    for b in /usr/bin/chromium /usr/bin/chromium-browser \
             /usr/bin/google-chrome /usr/bin/firefox \
             /usr/bin/firefox-esr; do
        if [ -x "${b}" ]; then
            USERNS_CONSUMERS_PRESENT="true"
            USERNS_CONSUMERS_SIGNALS+=("${b}: desktop browser present")
            break
        fi
    done
    return 0
}

RDS_WORKLOAD_PRESENT="false"
RDS_WORKLOAD_SIGNALS=()

IO_URING_WORKLOAD_PRESENT="false"
IO_URING_WORKLOAD_SIGNALS=()

# v2.1.0: PinTheft mitigation gate. RDS modprobe blacklist is suppressed
# when an Oracle Grid / clusterware / HPC workload is detected. Stock
# RHEL/Alma/Rocky/Oracle UEK kernels do not ship CONFIG_RDS=m, so the
# blacklist is a no-op there - we ship it anyway for defense in depth
# against ELRepo kernel-ml swaps, but suppress on Oracle hosts where
# rds.ko might be needed.
detect_rds_workload() {
    # Signal 1: /etc/oratab with non-comment, non-blank entries.
    # Canonical marker for any Oracle product install (Grid, RAC, DB).
    if [ -f /etc/oratab ] && \
       grep -qE '^[[:space:]]*[^#[:space:]]' /etc/oratab 2>/dev/null; then
        RDS_WORKLOAD_PRESENT="true"
        RDS_WORKLOAD_SIGNALS+=("/etc/oratab: non-comment entry present")
    fi

    # Signal 2: Oracle Clusterware control binary. Path conventional but
    # version-dependent; bounded find catches /u01/app/.../grid/bin/crsctl.
    if find /u01/app /opt/oracle -maxdepth 6 -type f \
            -name crsctl -path '*/grid/bin/crsctl' 2>/dev/null | grep -q .; then
        RDS_WORKLOAD_PRESENT="true"
        RDS_WORKLOAD_SIGNALS+=("oracle crsctl present (Grid Infrastructure)")
    fi

    # Signal 3: RDS module already loaded in running kernel - workload
    # in active use. Strong signal regardless of distro.
    local m
    for m in rds rds_tcp rds_rdma; do
        if [ -d "/sys/module/$m" ]; then
            RDS_WORKLOAD_PRESENT="true"
            RDS_WORKLOAD_SIGNALS+=("/sys/module/$m: loaded in running kernel")
        fi
    done

    return 0
}

# v2.1.1: PinTheft secondary mitigation gate. The io_uring sysctl
# is suppressed when ANY of these fires -- see spec §3.2.
detect_io_uring_workload() {
    # Signal 1: liburing.so in any /proc/<pid>/maps. Canonical signal
    # for an actively running io_uring consumer. Bounded glob to
    # /proc/[0-9]*/maps; silent on permission denied (non-root
    # mounts under containers). grep -l only needs one hit; head -1
    # bounds the result list so a huge process table doesn't fan out.
    local m
    for m in /proc/[0-9]*/maps; do
        [ -r "${m}" ] || continue
        if grep -ql 'liburing\.so' "${m}" 2>/dev/null; then
            IO_URING_WORKLOAD_PRESENT="true"
            IO_URING_WORKLOAD_SIGNALS+=("${m}: liburing.so mapped")
            break
        fi
    done

    # Signal 2: known consumer binary present and executable.
    # NOT a runtime check -- operator may have installed but not
    # started the service. False-positive cost is low (we keep
    # io_uring enabled on a host that doesn't actively need it).
    local b
    for b in /usr/bin/postgres /usr/pgsql-*/bin/postgres \
             /usr/bin/scylla /usr/bin/mariadbd \
             /usr/bin/mariadbd-ge /usr/bin/dockerd \
             /usr/bin/redis-server /usr/sbin/nginx \
             /usr/bin/envoy /usr/sbin/rabbitmq-server; do
        # Glob expansion when no match leaves the literal pattern; -x test fails.
        [ -x "${b}" ] || continue
        IO_URING_WORKLOAD_PRESENT="true"
        IO_URING_WORKLOAD_SIGNALS+=("${b}: known io_uring consumer present")
        break
    done

    # Signal 3: io_uring-named systemd unit enabled. Catches custom
    # operator deployments where the unit is named with the substring.
    if command -v systemctl >/dev/null 2>&1; then
        local unit
        unit=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
                   | awk '{print $1}' | grep -i io.uring | head -1 || true)
        if [ -n "${unit}" ]; then
            IO_URING_WORKLOAD_PRESENT="true"
            IO_URING_WORKLOAD_SIGNALS+=("systemd unit: ${unit}")
        fi
    fi

    # Signal 4: /proc/sys/kernel/io_uring_disabled already non-zero.
    # Operator explicitly tuned this -- respect their intent.
    if [ -r /proc/sys/kernel/io_uring_disabled ]; then
        local cur
        cur=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0)
        if [ "${cur}" != "0" ] && [ "${cur}" != "" ]; then
            IO_URING_WORKLOAD_PRESENT="false"  # already disabled; not a workload
            # No-op: we don't fire workload signal here, but we also
            # have nothing to apply. The kernel gate or operator-set
            # value already does what we want.
            :
        fi
    fi

    # Signal 5: CONFIG_IO_URING absent from /boot/config-$(uname -r).
    # Kernel built without io_uring; the sysctl key is non-existent.
    # NOT a workload signal -- we just want JSON to record it.
    # Implementation: the kernel-version gate already covers the
    # common case (kernel < 6.6); CONFIG_IO_URING=n on a recent
    # kernel is rare. Skip for simplicity -- relying on `-` prefix in
    # the sysctl drop-in to silently no-op.
    return 0
}

# SUPPRESS_*: true if mitigation is suppressed; false if applied.
SUPPRESS_MODPROBE_CF2_XFRM="false"
SUPPRESS_MODPROBE_RXRPC="false"
SUPPRESS_SYSTEMD_RXRPC_AF="false"
SUPPRESS_SYSTEMD_USERNS_USER_AT="false"
SUPPRESS_SYSCTL_USERNS="false"
SUPPRESS_MODPROBE_RDS="false"
SUPPRESS_SYSCTL_IOURING="false"
# Carrier for the reason io_uring suppression decided: one of
# rootless | userns_consumers | io_uring_workload | kernel_too_old |
# env_suppress | none. Reported in JSON state for operator triage.
IO_URING_SUPPRESS_REASON="none"

# force-full sentinel resolver: returns 0 (active) only for a regular
# file. Logs WARN if path exists as directory, broken symlink, etc -
# operator likely intended sentinel but staged the wrong shape.
check_force_full() {
    if [ -f "${FORCE_FULL}" ]; then
        return 0
    fi
    if [ -h "${FORCE_FULL}" ] && [ ! -e "${FORCE_FULL}" ]; then
        printf 'rfxn-defense: WARN: %s is a symlink to a missing target; force-full sentinel IGNORED\n' \
            "${FORCE_FULL}" \
          | tee /dev/stderr \
          | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null \
          || true
    elif [ -e "${FORCE_FULL}" ]; then
        printf 'rfxn-defense: WARN: %s exists but is not a regular file; force-full sentinel IGNORED\n' \
            "${FORCE_FULL}" \
          | tee /dev/stderr \
          | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null \
          || true
    fi
    return 1
}

# io_uring sysctl key (kernel.io_uring_disabled) requires Linux 6.6+.
# Returns 0 (supported) / 1 (too old) / 0 (cannot determine; assume
# supported and let `-` prefix in the sysctl file silently skip if
# the kernel ignores it).
_kernel_supports_iouring_sysctl() {
    local rel major minor
    rel=$(uname -r 2>/dev/null || echo "0.0")
    major="${rel%%.*}"
    minor="${rel#*.}"; minor="${minor%%.*}"
    # Validate numeric; default-allow on unparseable.
    [[ "${major}" =~ ^[0-9]+$ ]] || return 0
    [[ "${minor}" =~ ^[0-9]+$ ]] || return 0
    if [ "${major}" -gt 6 ] || \
       { [ "${major}" -eq 6 ] && [ "${minor}" -ge 6 ]; }; then
        return 0
    fi
    return 1
}

decide_suppressions() {
    if check_force_full; then
        # Operator override - apply everything regardless of detection.
        # v2.1.1: stamp the io_uring reason carrier so JSON state
        # reflects the source of the apply decision.
        IO_URING_SUPPRESS_REASON="force_full"
        return 0
    fi
    [ "${IPSEC_PRESENT}" = "true" ]    && SUPPRESS_MODPROBE_CF2_XFRM="true"
    [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_MODPROBE_RXRPC="true"
    [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_SYSTEMD_RXRPC_AF="true"
    [ "${ROOTLESS_PRESENT}" = "true" ] && SUPPRESS_SYSTEMD_USERNS_USER_AT="true"
    # v2.0.2 sysctl userns drop-in: host-wide userns sysctl is suppressed
    # by EITHER rootless containers (existing signal) OR Flatpak / firejail
    # / desktop browsers (new userns-consumers signal). Per-unit systemd
    # RestrictNamespaces is unaffected (still applies to the five tenant
    # units regardless of userns-consumer detection).
    if [ "${ROOTLESS_PRESENT}" = "true" ] || \
       [ "${USERNS_CONSUMERS_PRESENT}" = "true" ]; then
        SUPPRESS_SYSCTL_USERNS="true"
    fi
    [ "${RDS_WORKLOAD_PRESENT}" = "true" ] && SUPPRESS_MODPROBE_RDS="true"
    # v2.1.1: io_uring sysctl key -- layered suppression.
    # detect_io_uring_workload() populates IO_URING_WORKLOAD_PRESENT.
    # This block runs ONLY when force-full is not active (the
    # check_force_full early-return at the top of this function
    # already handled that case and stamped reason=force_full).
    # Order:
    #   1. CFD_FORCE_IOURING_DISABLE=1   -> apply
    #   2. CFD_SUPPRESS_IOURING_DISABLE=1 -> suppress
    #   3. kernel < 6.6                  -> suppress (key non-existent)
    #   4. io_uring workload signal      -> suppress
    #   5. rootless containers           -> suppress
    #   6. userns consumers              -> suppress
    #   else                              -> apply
    if [ "${CFD_FORCE_IOURING_DISABLE:-}" = "1" ]; then
        SUPPRESS_SYSCTL_IOURING="false"
        IO_URING_SUPPRESS_REASON="env_force"
    elif [ "${CFD_SUPPRESS_IOURING_DISABLE:-}" = "1" ]; then
        SUPPRESS_SYSCTL_IOURING="true"
        IO_URING_SUPPRESS_REASON="env_suppress"
    elif ! _kernel_supports_iouring_sysctl; then
        SUPPRESS_SYSCTL_IOURING="true"
        IO_URING_SUPPRESS_REASON="kernel_too_old"
    elif [ "${IO_URING_WORKLOAD_PRESENT}" = "true" ]; then
        SUPPRESS_SYSCTL_IOURING="true"
        IO_URING_SUPPRESS_REASON=io_uring_workload
    elif [ "${ROOTLESS_PRESENT}" = "true" ]; then
        SUPPRESS_SYSCTL_IOURING="true"
        IO_URING_SUPPRESS_REASON="rootless_containers"
    elif [ "${USERNS_CONSUMERS_PRESENT}" = "true" ]; then
        SUPPRESS_SYSCTL_IOURING="true"
        IO_URING_SUPPRESS_REASON="userns_consumers"
    else
        SUPPRESS_SYSCTL_IOURING="false"
        IO_URING_SUPPRESS_REASON="none"
    fi
    # Explicit success: the chained `[ x ] && SUP=...` returns 1 when
    # the final test is false (clean host, nothing detected). Under
    # the script's `set -e` that would abort main() before
    # write_state_json runs, leaving no auto-detect.json on disk.
    return 0
}

# cmp-and-skip helper: install src to dst only if dst doesn't
# exist OR matches src exactly. If dst differs from src, log
# WARN and skip the install (preserves operator hand-edits per D-57).
# Returns 0 on success/skip, non-zero on filesystem error.
cmp_and_install() {
    local src="$1" dst="$2" tag="$3"
    if [ ! -f "${dst}" ]; then
        install -d -m 0755 "$(dirname "${dst}")"
        install -m 0644 -o root -g root "${src}" "${dst}"
        log "${tag}: applied (new install)"
        return 0
    fi
    if cmp -s "${src}" "${dst}"; then
        # Same content - nothing to do.
        return 0
    fi
    # Different content - operator hand-edit. Skip overwrite.
    # tee to stderr so dnf surfaces the warning (D-55).
    printf 'rfxn-defense: WARN: %s diverged from template; preserving operator edits (cmp-and-skip per D-57)\n' \
        "${dst}" | tee /dev/stderr | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null || true
    return 0
}

apply_modprobe() {
    local src dst
    # cf2-xfrm: cmp-and-install or remove
    src="${TEMPLATE_DIR}/modprobe/99-rfxn-defense-cf2-xfrm.conf"
    dst="${ETC_MODPROBE}/99-rfxn-defense-cf2-xfrm.conf"
    if [ "${SUPPRESS_MODPROBE_CF2_XFRM}" = "true" ]; then
        rm -f "${dst}"
        log "modprobe cf2-xfrm: suppressed (IPsec detected)"
    elif [ -f "${src}" ]; then
        cmp_and_install "${src}" "${dst}" "modprobe cf2-xfrm"
    fi
    # rxrpc: cmp-and-install or remove
    src="${TEMPLATE_DIR}/modprobe/99-rfxn-defense-rxrpc.conf"
    dst="${ETC_MODPROBE}/99-rfxn-defense-rxrpc.conf"
    if [ "${SUPPRESS_MODPROBE_RXRPC}" = "true" ]; then
        rm -f "${dst}"
        log "modprobe rxrpc: suppressed (AFS detected)"
    elif [ -f "${src}" ]; then
        cmp_and_install "${src}" "${dst}" "modprobe rxrpc"
    fi
    apply_rds_modprobe
    return 0
}

apply_rds_modprobe() {
    local src dst
    src="${TEMPLATE_DIR}/modprobe/99-rfxn-defense-rds.conf"
    dst="${ETC_MODPROBE}/99-rfxn-defense-rds.conf"
    if [ ! -f "${src}" ]; then
        # Subpackage -modprobe not installed; nothing to do.
        return 0
    fi
    if [ "${SUPPRESS_MODPROBE_RDS}" = "true" ]; then
        rm -f "${dst}"
        log "modprobe rds: suppressed (Oracle/RDS workload detected)"
    else
        cmp_and_install "${src}" "${dst}" "modprobe rds"
    fi
    return 0
}

apply_systemd() {
    local src dst unit suppress
    # 12-* AF_RXRPC drop-in (suppressed on AFS hosts; applies to all 5 units)
    src="${TEMPLATE_DIR}/systemd/12-rfxn-defense-rxrpc-af.conf"
    if [ -f "${src}" ]; then
        for unit in "${TENANT_UNITS[@]}"; do
            dst="${ETC_SYSTEMD}/${unit}.service.d/12-rfxn-defense-rxrpc-af.conf"
            if [ "${SUPPRESS_SYSTEMD_RXRPC_AF}" = "true" ]; then
                rm -f "${dst}"
                log "systemd rxrpc-af ${unit}: suppressed (AFS detected)"
            else
                cmp_and_install "${src}" "${dst}" "systemd rxrpc-af ${unit}"
            fi
        done
    fi
    # 15-* userns drop-in (suppressed on user@ only when rootless detected)
    src="${TEMPLATE_DIR}/systemd/15-rfxn-defense-userns.conf"
    if [ -f "${src}" ]; then
        for unit in "${TENANT_UNITS[@]}"; do
            dst="${ETC_SYSTEMD}/${unit}.service.d/15-rfxn-defense-userns.conf"
            suppress="false"
            if [ "${unit}" = "user@" ] && \
               [ "${SUPPRESS_SYSTEMD_USERNS_USER_AT}" = "true" ]; then
                suppress="true"
            fi
            if [ "${suppress}" = "true" ]; then
                rm -f "${dst}"
                log "systemd userns ${unit}: suppressed (rootless detected)"
            else
                cmp_and_install "${src}" "${dst}" "systemd userns ${unit}"
            fi
        done
    fi
}

apply_sysctl() {
    local src dst
    src="${TEMPLATE_DIR}/sysctl/99-rfxn-defense-userns.conf"
    dst="${ETC_SYSCTL}/99-rfxn-defense-userns.conf"
    if [ ! -f "${src}" ]; then
        # Subpackage -sysctl not installed; nothing to do.
        return 0
    fi
    if [ "${SUPPRESS_SYSCTL_USERNS}" = "true" ]; then
        rm -f "${dst}"
        log "sysctl userns: suppressed (rootless containers or userns-consumer detected)"
    else
        cmp_and_install "${src}" "${dst}" "sysctl userns"
    fi
    apply_sysctl_iouring
    return 0
}

apply_sysctl_iouring() {
    local src dst
    src="${TEMPLATE_DIR}/sysctl/99-rfxn-defense-iouring.conf"
    dst="${ETC_SYSCTL}/99-rfxn-defense-iouring.conf"
    if [ ! -f "${src}" ]; then
        # Template missing (older subpackage, race). Nothing to do.
        return 0
    fi
    if [ "${SUPPRESS_SYSCTL_IOURING}" = "true" ]; then
        rm -f "${dst}"
        log "sysctl iouring: suppressed (reason=${IO_URING_SUPPRESS_REASON})"
    else
        cmp_and_install "${src}" "${dst}" "sysctl iouring"
    fi
    return 0
}

teardown_sysctl_iouring() {
    rm -f "${ETC_SYSCTL}/99-rfxn-defense-iouring.conf"
    log "sysctl iouring teardown: removed /etc/sysctl.d/99-rfxn-defense-iouring.conf"
    return 0
}

teardown_modprobe() {
    rm -f "${ETC_MODPROBE}/99-rfxn-defense-cf2-xfrm.conf"
    rm -f "${ETC_MODPROBE}/99-rfxn-defense-rxrpc.conf"
    rm -f "${ETC_MODPROBE}/99-rfxn-defense-rds.conf"
    log "modprobe teardown: removed conditional /etc/modprobe.d/* files"
}

teardown_rds_modprobe() {
    rm -f "${ETC_MODPROBE}/99-rfxn-defense-rds.conf"
    log "modprobe rds teardown: removed /etc/modprobe.d/99-rfxn-defense-rds.conf"
    return 0
}

teardown_sysctl() {
    rm -f "${ETC_SYSCTL}/99-rfxn-defense-userns.conf"
    teardown_sysctl_iouring
    log "sysctl teardown: removed /etc/sysctl.d/99-rfxn-defense-{userns,iouring}.conf"
    return 0
}

teardown_systemd() {
    local unit
    for unit in "${TENANT_UNITS[@]}"; do
        rm -f "${ETC_SYSTEMD}/${unit}.service.d/12-rfxn-defense-rxrpc-af.conf"
        rm -f "${ETC_SYSTEMD}/${unit}.service.d/15-rfxn-defense-userns.conf"
    done
    log "systemd teardown: removed conditional /etc/systemd/system/*.d/12-* and 15-*"
}

write_state_json() {
    local target="$1"   # final path
    local force_full="false"
    [ -f "${FORCE_FULL}" ] && force_full="true"

    install -d -m 0755 -o root -g root "$(dirname "${target}")"
    local tmp="${target}.tmp.$$"

    # v2.0.2 sentinel fix: applied.sysctl_userns must reflect on-disk
    # truth, not just !suppressed. When -sysctl is uninstalled but
    # -modprobe / -systemd are still around, detect.sh runs from their
    # %posttrans but apply_sysctl() early-returns (template missing).
    # JSON should show applied=false in that case, even though
    # suppressed=false.
    local sysctl_template_present="false"
    if [ -f "${TEMPLATE_DIR}/sysctl/99-rfxn-defense-userns.conf" ]; then
        sysctl_template_present="true"
    fi

    local modprobe_rds_template_present="false"
    if [ -f "${TEMPLATE_DIR}/modprobe/99-rfxn-defense-rds.conf" ]; then
        modprobe_rds_template_present="true"
    fi

    local sysctl_iouring_template_present="false"
    if [ -f "${TEMPLATE_DIR}/sysctl/99-rfxn-defense-iouring.conf" ]; then
        sysctl_iouring_template_present="true"
    fi

    # Marshall signal arrays as NUL-delimited bytes via stdin.
    # Bash command substitution silently strips NUL bytes from a captured
    # string, so an env-var carrier collapses signal1\0signal2\0 into
    # signal1signal2 - a single concatenated string. Piping printf's
    # output straight into python avoids the bash variable round-trip
    # entirely. End-of-list markers separate the four arrays.
    {
        printf '%s\0' "${IPSEC_SIGNALS[@]+${IPSEC_SIGNALS[@]}}"
        printf 'CFD_END_IPSEC\0'
        printf '%s\0' "${AFS_SIGNALS[@]+${AFS_SIGNALS[@]}}"
        printf 'CFD_END_AFS\0'
        printf '%s\0' "${ROOTLESS_SIGNALS[@]+${ROOTLESS_SIGNALS[@]}}"
        printf 'CFD_END_ROOTLESS\0'
        printf '%s\0' "${USERNS_CONSUMERS_SIGNALS[@]+${USERNS_CONSUMERS_SIGNALS[@]}}"
        printf 'CFD_END_USERNS_CONSUMERS\0'
        printf '%s\0' "${RDS_WORKLOAD_SIGNALS[@]+${RDS_WORKLOAD_SIGNALS[@]}}"
        printf 'CFD_END_RDS_WORKLOAD\0'
        printf '%s\0' "${IO_URING_WORKLOAD_SIGNALS[@]+${IO_URING_WORKLOAD_SIGNALS[@]}}"
        printf 'CFD_END_IO_URING_WORKLOAD\0'
    } | env \
        CFD_TOOL_VERSION="${TOOL_VERSION}" \
        CFD_TIMESTAMP="$(date +%s)" \
        CFD_HOSTNAME="$(hostname 2>/dev/null || echo unknown)" \
        CFD_FORCE_FULL="${force_full}" \
        CFD_IPSEC_PRESENT="${IPSEC_PRESENT}" \
        CFD_AFS_PRESENT="${AFS_PRESENT}" \
        CFD_ROOTLESS_PRESENT="${ROOTLESS_PRESENT}" \
        CFD_USERNS_CONSUMERS_PRESENT="${USERNS_CONSUMERS_PRESENT}" \
        CFD_RDS_WORKLOAD_PRESENT="${RDS_WORKLOAD_PRESENT}" \
        CFD_SUP_MODPROBE_CF2_XFRM="${SUPPRESS_MODPROBE_CF2_XFRM}" \
        CFD_SUP_MODPROBE_RXRPC="${SUPPRESS_MODPROBE_RXRPC}" \
        CFD_SUP_SYSTEMD_RXRPC_AF="${SUPPRESS_SYSTEMD_RXRPC_AF}" \
        CFD_SUP_SYSTEMD_USERNS_USER_AT="${SUPPRESS_SYSTEMD_USERNS_USER_AT}" \
        CFD_SUP_SYSCTL_USERNS="${SUPPRESS_SYSCTL_USERNS}" \
        CFD_SUP_MODPROBE_RDS="${SUPPRESS_MODPROBE_RDS}" \
        CFD_IO_URING_WORKLOAD_PRESENT="${IO_URING_WORKLOAD_PRESENT}" \
        CFD_SUP_SYSCTL_IOURING="${SUPPRESS_SYSCTL_IOURING}" \
        CFD_IOURING_SUPPRESS_REASON="${IO_URING_SUPPRESS_REASON}" \
        CFD_SYSCTL_TEMPLATE_PRESENT="${sysctl_template_present}" \
        CFD_MODPROBE_RDS_TEMPLATE_PRESENT="${modprobe_rds_template_present}" \
        CFD_SYSCTL_IOURING_TEMPLATE_PRESENT="${sysctl_iouring_template_present}" \
        python3 -c '
import json, os, sys

def b(name):
    return os.environ.get(name, "false") == "true"

raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
parts = raw.split("\0")

def take_until(marker):
    out = []
    while parts:
        item = parts.pop(0)
        if item == marker:
            return out
        if item:
            out.append(item)
    return out

ipsec_signals      = take_until("CFD_END_IPSEC")
afs_signals        = take_until("CFD_END_AFS")
rootless_signals   = take_until("CFD_END_ROOTLESS")
consumers_signals  = take_until("CFD_END_USERNS_CONSUMERS")
rds_workload_signals = take_until("CFD_END_RDS_WORKLOAD")
io_uring_signals  = take_until("CFD_END_IO_URING_WORKLOAD")

sup_xfrm       = b("CFD_SUP_MODPROBE_CF2_XFRM")
sup_rxrpc      = b("CFD_SUP_MODPROBE_RXRPC")
sup_rxaf       = b("CFD_SUP_SYSTEMD_RXRPC_AF")
sup_userns     = b("CFD_SUP_SYSTEMD_USERNS_USER_AT")
sup_sysctl     = b("CFD_SUP_SYSCTL_USERNS")
sup_rds        = b("CFD_SUP_MODPROBE_RDS")
sup_iouring         = b("CFD_SUP_SYSCTL_IOURING")
iouring_reason      = os.environ.get("CFD_IOURING_SUPPRESS_REASON", "none")
iouring_workload    = b("CFD_IO_URING_WORKLOAD_PRESENT")
sysctl_present = b("CFD_SYSCTL_TEMPLATE_PRESENT")
modprobe_rds_template_present = b("CFD_MODPROBE_RDS_TEMPLATE_PRESENT")
sysctl_iouring_template_present = b("CFD_SYSCTL_IOURING_TEMPLATE_PRESENT")

doc = {
    "schema_version": "2",
    "tool": "rfxn-defense-detect",
    "tool_version": os.environ["CFD_TOOL_VERSION"],
    "timestamp": int(os.environ["CFD_TIMESTAMP"]),
    "hostname": os.environ["CFD_HOSTNAME"],
    "force_full": b("CFD_FORCE_FULL"),
    "detected": {
        "ipsec":               {"present": b("CFD_IPSEC_PRESENT"),             "signals": ipsec_signals},
        "afs":                 {"present": b("CFD_AFS_PRESENT"),               "signals": afs_signals},
        "rootless_containers": {"present": b("CFD_ROOTLESS_PRESENT"),          "signals": rootless_signals},
        "userns_consumers":    {"present": b("CFD_USERNS_CONSUMERS_PRESENT"),  "signals": consumers_signals},
        "rds_workload":        {"present": b("CFD_RDS_WORKLOAD_PRESENT"),      "signals": rds_workload_signals},
        "io_uring_workload":   {"present": iouring_workload,                  "signals": io_uring_signals},
    },
    "suppressed": {
        "modprobe_cf2_xfrm":      sup_xfrm,
        "modprobe_rxrpc":         sup_rxrpc,
        "systemd_rxrpc_af":       sup_rxaf,
        "systemd_userns_user_at": sup_userns,
        "sysctl_userns":          sup_sysctl,
        "modprobe_rds":           sup_rds,
        "sysctl_iouring":     {"suppressed": sup_iouring, "reason": iouring_reason},
    },
    "applied": {
        "modprobe_cf1":              True,
        "modprobe_cf2_xfrm":         not sup_xfrm,
        "modprobe_rxrpc":            not sup_rxrpc,
        "systemd_always":            True,
        "systemd_rxrpc_af_user_at":  not sup_rxaf,
        "systemd_rxrpc_af_sshd":     not sup_rxaf,
        "systemd_rxrpc_af_cron":     not sup_rxaf,
        "systemd_rxrpc_af_crond":    not sup_rxaf,
        "systemd_rxrpc_af_atd":      not sup_rxaf,
        "systemd_userns_user_at":    not sup_userns,
        "systemd_userns_sshd":       True,
        "systemd_userns_cron":       True,
        "systemd_userns_crond":      True,
        "systemd_userns_atd":        True,
        # applied.sysctl_userns: true only when NOT suppressed AND
        # the -sysctl subpackage template exists on disk (proxy for
        # subpackage installed). Otherwise the JSON would misreport
        # apply state on hosts where -sysctl is excluded from install.
        "sysctl_userns":             (not sup_sysctl) and sysctl_present,
        "modprobe_rds":              (not sup_rds) and modprobe_rds_template_present,
        "sysctl_iouring":            (not sup_iouring) and sysctl_iouring_template_present,
    },
}
with open(sys.argv[1], "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
' "${tmp}"

    mv -f "${tmp}" "${target}"
}

usage() {
    cat <<USAGE >&2
USAGE: $0 apply (modprobe|systemd|sysctl|both|all)
       $0 teardown (modprobe|systemd|sysctl|both|all)
       'both' = modprobe+systemd (back-compat with v2.0.1 callers).
       'all'  = modprobe+systemd+sysctl.
USAGE
    exit 1
}

main() {
    local action="${1:-}" scope="${2:-}"
    case "${action}" in
        apply)
            case "${scope}" in
                modprobe|systemd|sysctl|both|all) ;;
                *) usage ;;
            esac
            detect_ipsec
            detect_afs
            detect_rootless_containers
            detect_userns_consumers
            detect_rds_workload
            detect_io_uring_workload
            decide_suppressions
            if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                apply_modprobe
            fi
            if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                apply_systemd
            fi
            if [ "${scope}" = "sysctl" ] || [ "${scope}" = "all" ]; then
                apply_sysctl
            fi
            write_state_json "${STATE_FILE}"
            log "apply ${scope} complete: ipsec=${IPSEC_PRESENT} afs=${AFS_PRESENT} rootless=${ROOTLESS_PRESENT} userns_consumers=${USERNS_CONSUMERS_PRESENT} rds_workload=${RDS_WORKLOAD_PRESENT} io_uring_workload=${IO_URING_WORKLOAD_PRESENT} iouring_supp=${IO_URING_SUPPRESS_REASON}"
            ;;
        teardown)
            case "${scope}" in
                modprobe|systemd|sysctl|both|all) ;;
                *) usage ;;
            esac
            if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                teardown_modprobe
            fi
            if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                teardown_systemd
            fi
            if [ "${scope}" = "sysctl" ] || [ "${scope}" = "all" ]; then
                teardown_sysctl
            fi
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
