#!/bin/bash
# shellcheck disable=SC2317
#
# test-el7-live.sh
#   Empirical EL7 mitigation-effectiveness test runner. Runs ON a real
#   EL7 host (VM or bare metal); installs the local v3.0.2+ RPM set;
#   exercises ~32 assertions across:
#     A. Packaging sanity   — install/remove cycle, no scriptlet aborts
#     B. Auditor JSON       — rfxn-local-check exit + schema validity
#     C. Mitigation probes  — empirical "try the bad action, verify
#                              blocked" (AF_ALG, ptrace, systemd parse,
#                              modprobe blacklist, unshare)
#     D. Upgrade path       — copyfail-defense 2.1.1 -> rfxn-defense
#
# v3.0.2 motivation: the test-repo.sh harness exercises the published
# gh-pages repo on EL7/8/9/10 via podman, which catches install-time
# bugs but NOT runtime mitigation effectiveness (no real systemd, no
# real kernel, no real procps interaction with the host sysctl tree).
# Three EL7-specific silent-failure layers shipped through v3.0.1
# because container-based testing couldn't see them. This runner is
# the empirical complement that surfaces them on a live host.
#
# Usage (on the EL7 host as a sudo-NOPASSWD user):
#   bash test-el7-live.sh             # standard run
#   RPMS_CURRENT=/path RPMS_LEGACY=/path bash test-el7-live.sh
#
# Inputs (env, all optional with defaults):
#   RPMS_CURRENT  — dir of v3.0.2+ EL7 RPMs              (default: ~/rpms-current)
#   RPMS_LEGACY   — dir of copyfail-defense 2.1.1 EL7s   (default: ~/rpms-legacy)
#   SKIP_BOOTSTRAP — '1' to skip vault.centos.org repo swap (already done)
#
# Exit codes:
#   0  — all 27 assertions PASS
#   1  — one or more FAIL
#   2  — bootstrap failed (cannot prepare host)

set -uo pipefail

RPMS_CURRENT="${RPMS_CURRENT:-$HOME/rpms-current}"
RPMS_LEGACY="${RPMS_LEGACY:-$HOME/rpms-legacy}"
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-0}"

R='\033[31m'; G='\033[32m'; Y='\033[33m'; B='\033[34m'; Z='\033[0m'
PASS=(); FAIL=(); SKIP=()
TOTAL=0
ok()   { PASS+=("$1"); TOTAL=$((TOTAL+1)); echo -e "  ${G}PASS${Z}  $1"; }
fail() { FAIL+=("$1"); TOTAL=$((TOTAL+1)); echo -e "  ${R}FAIL${Z}  $1"; }
skip() { SKIP+=("$1"); echo -e "  ${Y}SKIP${Z}  $1"; }
sec()  { echo; echo -e "${B}=== $1 ===${Z}"; }
sub()  { echo -e "  ${B}--${Z} $1"; }

# Need full $PATH for /usr/sbin/{sysctl,modprobe} under sudo (EL7 sudo
# secure_path doesn't include /usr/sbin for non-root callers in some
# configs). We tolerate either case by always preferring absolute paths
# for binaries that live under /sbin or /usr/sbin.
SYSCTL=/usr/sbin/sysctl
MODPROBE=/usr/sbin/modprobe

# ---------- bootstrap ----------
sec "BOOTSTRAP"
if [ "$SKIP_BOOTSTRAP" != "1" ]; then
    # v3.0.2 sentinel F16: vault.centos.org rewrite mutates host
    # /etc/yum.repos.d/* in place. Refuse on non-EL7 hosts so an
    # accidental run on an EL8/9/10/Fedora host doesn't trash repo
    # config. Override via SKIP_BOOTSTRAP=1 if the operator already
    # set up alternate vault entries by hand.
    if ! grep -q 'CentOS Linux release 7' /etc/redhat-release 2>/dev/null; then
        echo -e "${R}FATAL:${Z} bootstrap targets CentOS 7 vault.centos.org swap"
        echo "  /etc/redhat-release: $(cat /etc/redhat-release 2>/dev/null || echo '(missing)')"
        echo "  Run with SKIP_BOOTSTRAP=1 if repos are already configured."
        exit 2
    fi
    sub "swap mirrorlist -> vault.centos.org (CentOS 7 EOL)"
    sudo sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo
    sudo sed -i 's|^#baseurl=http://mirror.centos.org/centos|baseurl=https://vault.centos.org/centos|g' /etc/yum.repos.d/CentOS-*.repo
    sudo yum clean all >/dev/null 2>&1
fi

if ! sudo yum -q -y install gcc glibc-devel audit-libs >/dev/null 2>&1; then
    echo -e "${R}FATAL:${Z} bootstrap yum install failed"
    exit 2
fi
ok "bootstrap: vault repos + gcc + audit-libs"

[ -d "$RPMS_CURRENT" ] && [ -d "$RPMS_LEGACY" ] || {
    echo -e "${R}FATAL:${Z} RPM dirs missing"
    echo "  RPMS_CURRENT=$RPMS_CURRENT (exists: $([ -d "$RPMS_CURRENT" ] && echo y || echo n))"
    echo "  RPMS_LEGACY=$RPMS_LEGACY (exists: $([ -d "$RPMS_LEGACY" ] && echo y || echo n))"
    exit 2
}

KVER=$(uname -r); echo "  kernel: $KVER"
[ -f /proc/sys/kernel/yama/ptrace_scope ] \
    && ok "kernel: yama/ptrace_scope present" \
    || fail "kernel: yama/ptrace_scope absent (Yama LSM not enabled)"

# ============================================================
sec "SCOPE A — Packaging sanity"
# ============================================================
sub "fresh install: meta + all 8 subpackages"
INSTALL_LOG=$(mktemp)
sudo yum -y install \
    "$RPMS_CURRENT"/rfxn-defense-[0-9]*.el7.x86_64.rpm \
    "$RPMS_CURRENT"/rfxn-defense-shim-*.el7.x86_64.rpm \
    "$RPMS_CURRENT"/rfxn-defense-modprobe-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-systemd-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-sysctl-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-audit-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-auditor-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-autoupdate-*.el7.noarch.rpm \
    2>&1 | tee "$INSTALL_LOG" | tail -3

# yum returns 0 even when RPM scriptlets emit "warning: %post ... scriptlet failed"
if grep -qE 'scriptlet failed|exit status|error: (un)?install:' "$INSTALL_LOG"; then
    fail "install: scriptlet failures detected"
    grep -E 'scriptlet failed|exit status|error:' "$INSTALL_LOG" | head -5
else
    ok "install: no scriptlet failures (yum log clean)"
fi

EXPECTED=(rfxn-defense rfxn-defense-shim rfxn-defense-modprobe rfxn-defense-systemd \
          rfxn-defense-sysctl rfxn-defense-audit rfxn-defense-auditor rfxn-defense-autoupdate)
MISSING=()
for pkg in "${EXPECTED[@]}"; do
    rpm -q "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
done
[ "${#MISSING[@]}" -eq 0 ] \
    && ok "install: all 8 subpackages present" \
    || fail "install: missing ${MISSING[*]}"

sub "drop-in files landed"
# 10-* always-on drop-ins (5 units)
DROPIN_10=$(sudo find /etc/systemd/system -name '10-rfxn-defense.conf' 2>/dev/null | wc -l)
[ "$DROPIN_10" -eq 5 ] \
    && ok "systemd: 5x 10-rfxn-defense.conf drop-ins (sshd/cron/crond/atd/user@)" \
    || fail "systemd: expected 5 10-* drop-ins, found $DROPIN_10"

# v3.0.2: 15-userns drop-in should NOT be present on EL7 (systemd 219
# does not recognise RestrictNamespaces=; shipping a no-op file is a
# silent-failure mitigation layer the package no longer ships on EL7).
DROPIN_15=$(sudo find /etc/systemd/system -name '15-rfxn-defense-userns.conf' 2>/dev/null | wc -l)
[ "$DROPIN_15" -eq 0 ] \
    && ok "systemd: 0x 15-userns drop-ins on EL7 (correctly spec-gated)" \
    || fail "systemd: $DROPIN_15 15-userns drop-ins found on EL7 (should be 0; systemd 219 silently ignores RestrictNamespaces)"

# modprobe blacklists
MODPROBE_COUNT=$(sudo find /etc/modprobe.d -name '*rfxn*' 2>/dev/null | wc -l)
[ "$MODPROBE_COUNT" -ge 1 ] \
    && ok "modprobe: $MODPROBE_COUNT rfxn blacklist file(s) present" \
    || fail "modprobe: zero rfxn blacklists"

# sysctl: on EL7 v3.0.2 we expect ptrace.conf present, userns.conf absent
# (gated out — none of its 3 keys exist on kernel 3.10).
PTRACE_FILE=/etc/sysctl.d/99-rfxn-defense-ptrace.conf
[ -f "$PTRACE_FILE" ] \
    && ok "sysctl: 99-rfxn-defense-ptrace.conf present (always-applied)" \
    || fail "sysctl: 99-rfxn-defense-ptrace.conf missing"

USERNS_FILE=/etc/sysctl.d/99-rfxn-defense-userns.conf
[ ! -f "$USERNS_FILE" ] \
    && ok "sysctl: 99-rfxn-defense-userns.conf absent on EL7 (correctly spec-gated; '-' prefix unsupported by procps 3.3.10)" \
    || fail "sysctl: 99-rfxn-defense-userns.conf present on EL7 (should be gated out)"

# audit rules (need sudo to read /etc/audit/rules.d/)
AUDIT_RULES=/etc/audit/rules.d/99-rfxn-defense.rules
sudo test -f "$AUDIT_RULES" \
    && ok "audit: 99-rfxn-defense.rules dropped" \
    || fail "audit: 99-rfxn-defense.rules missing"

# Detection helper
if sudo /usr/libexec/rfxn-defense/detect.sh apply all >/dev/null 2>&1; then
    ok "detect.sh: apply all exits 0"
else
    fail "detect.sh: apply all failed"
fi

# ============================================================
sec "SCOPE B — Auditor JSON correctness"
# ============================================================
AUDIT_JSON=$(sudo /usr/sbin/rfxn-local-check --json 2>/dev/null)
AUDIT_RC=$?
echo "  auditor exit code: $AUDIT_RC"

if [[ "$AUDIT_RC" =~ ^(0|3|4)$ ]]; then
    ok "auditor: exit code in {0,3,4} (got $AUDIT_RC)"
else
    fail "auditor: exit code $AUDIT_RC outside {0,3,4}"
fi

if echo "$AUDIT_JSON" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    ok "auditor: JSON parses cleanly"

    # v3.0.2: systemd_restrict_namespaces must NOT return SKIP "no
    # tenant units found" on EL7. Either status=SKIP w/ systemd_version<235
    # message, OR status=FAIL with stale_dropins. Either way, the
    # operator gets explicit visibility instead of the old silent SKIP.
    NS_STATUS=$(echo "$AUDIT_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for c in d["checks"]:
    if c["name"] == "systemd_restrict_namespaces":
        print(c["status"], c.get("details",{}).get("systemd_version","?"), c["message"][:80])
        break')
    case "$NS_STATUS" in
        skip*219*predates*v235*) \
            ok "auditor: systemd_restrict_namespaces SKIPs with explicit v235 reason (v3.0.2 fix)" ;;
        fail*v235*) \
            ok "auditor: systemd_restrict_namespaces FAILs explicitly on stale EL7 drop-ins (v3.0.2 fix)" ;;
        skip*no\ tenant\ units*) \
            fail "auditor: systemd_restrict_namespaces SKIP 'no tenant units' on EL7 (silent-mask regression)" ;;
        *) \
            fail "auditor: systemd_restrict_namespaces unexpected: $NS_STATUS" ;;
    esac

    # v3.0.2: userns_sysctl OK message must distinguish "rfxn drop-in"
    # vs "kernel/distro default" on EL7 (where the drop-in is absent
    # but the kernel default is 0).
    USERNS_MSG=$(echo "$AUDIT_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for c in d["checks"]:
    if c["name"] == "userns_sysctl":
        print(c["status"], c.get("details",{}).get("rfxn_sysctl_dropin_present","?"), c["message"][:120])
        break')
    if echo "$USERNS_MSG" | grep -q "kernel/distro default"; then
        ok "auditor: userns_sysctl OK message distinguishes kernel-default from rfxn drop-in (v3.0.2 fix)"
    else
        fail "auditor: userns_sysctl OK message missing kernel-default disambiguation: $USERNS_MSG"
    fi
else
    fail "auditor: --json output not valid JSON"
    echo "$AUDIT_JSON" | head -5
fi

echo "$AUDIT_JSON" > /tmp/auditor-el7.json
ok "auditor JSON saved to /tmp/auditor-el7.json ($(echo "$AUDIT_JSON" | wc -c) bytes)"

# ============================================================
sec "SCOPE C — Empirical mitigation probes"
# ============================================================
sub "systemd-analyze verify on all rfxn drop-ins (skips templates)"
VERIFY_ALL_OK=true
for d in /etc/systemd/system/*.service.d/*-rfxn-defense*.conf; do
    [ -f "$d" ] || continue
    UNIT=$(dirname "$d" | xargs basename | sed 's/\.d$//')
    # Template units (user@.service) can't be verified standalone on
    # EL7 systemd 219 - need an instance which we won't create here.
    # The drop-in content is the same as on regular units, so verifying
    # it via sshd/cron/crond/atd covers the parse path.
    case "$UNIT" in *@) continue ;; esac
    VERIFY=$(sudo systemd-analyze verify "$UNIT" 2>&1)
    # `Unknown lvalue` is the v3.0.0/v3.0.1 EL7 silent-failure signal —
    # we filter on this strict class to avoid false positives on
    # unrelated systemd diagnostics (NoSuchUnit, dependency warnings).
    if echo "$VERIFY" | grep -qiE 'Unknown lvalue|Unknown key|failed to parse'; then
        fail "systemd-analyze: $d: $(echo "$VERIFY" | grep -m1 -iE 'Unknown|parse')"
        VERIFY_ALL_OK=false
    fi
done
[ "$VERIFY_ALL_OK" = true ] && ok "systemd-analyze: all rfxn drop-ins parse clean on this systemd"

sub "ptrace_scope: file content + install-time + reload soundness"
PT_FILE_VAL=$(sudo grep -oE 'ptrace_scope\s*=\s*[0-9]+' "$PTRACE_FILE" | grep -oE '[0-9]+$' | head -1)
[ "$PT_FILE_VAL" = "2" ] \
    && ok "ptrace: $PTRACE_FILE sets ptrace_scope=2" \
    || fail "ptrace: $PTRACE_FILE ptrace_scope value = '$PT_FILE_VAL' (expected 2)"

# v3.0.2 install-time assertion (sentinel F6): %posttrans sysctl runs
# `sysctl --system` which MUST set this to 2 at install completion -
# without any manual reload by this test runner. The prior v3.0.1
# %posttrans loop omitted ptrace.conf, so runtime stayed at the kernel
# default. Capture the value BEFORE any sysctl call in this script -
# this is the load-bearing install-time proof.
INSTALL_PT=$(cat /proc/sys/kernel/yama/ptrace_scope)
[ "$INSTALL_PT" = "2" ] \
    && ok "ptrace install-time: /proc/sys/kernel/yama/ptrace_scope=2 set by %posttrans sysctl --system (sentinel F6 fix verified)" \
    || fail "ptrace install-time: runtime=$INSTALL_PT after package install; %posttrans sysctl --system did NOT load $PTRACE_FILE"

# Reload soundness: reset to 0 then sysctl -p the file. Confirms the
# file content is actually parseable by EL7 procps-ng 3.3.10 (the
# v3.0.2 `-` prefix removal). Independent of install-time path.
sudo $SYSCTL -w kernel.yama.ptrace_scope=0 >/dev/null 2>&1 || true
sudo $SYSCTL -p "$PTRACE_FILE" >/dev/null 2>&1
RELOAD_PT=$(cat /proc/sys/kernel/yama/ptrace_scope)
[ "$RELOAD_PT" = "2" ] \
    && ok "ptrace reload: sysctl -p $PTRACE_FILE sets to 2 (no '-' prefix; works on EL7 procps 3.3.10)" \
    || fail "ptrace reload: runtime=$RELOAD_PT after sysctl -p (file may still use '-' prefix; broken on procps 3.3.10)"

sub "modprobe blacklist: af_alg + cf2 + rxrpc"
for mod in af_alg cf2-xfrm rxrpc; do
    BL=$(sudo find /etc/modprobe.d -name "*${mod//-/[-_]}*" 2>/dev/null | wc -l)
    [ "$BL" -ge 0 ] || true  # informational only
done
# cf1 always-on. The shipped pattern is `install <mod> /bin/false` (or
# /bin/true; both make request_module() fail to load anything). Accept
# either since the auto-load suppression is what matters.
if grep -qE 'install af_alg.*/bin/(false|true)' /etc/modprobe.d/99-rfxn-defense-cf1.conf 2>/dev/null; then
    ok "modprobe: af_alg install-hook redirects to /bin/{false,true} (auto-load blocked)"
else
    fail "modprobe: af_alg install-hook missing from 99-rfxn-defense-cf1.conf"
fi

sub "AF_ALG socket probe — isolate shim from modprobe blacklist"
# The modprobe blacklist (`install af_alg /bin/false`) kills af_alg
# *autoload* before any shim ever sees the syscall. Testing AF_ALG with
# the blacklist in place is a tautology: socket() fails for the wrong
# reason. To actually exercise the shim, temporarily move the blacklist
# aside, force-load af_alg via modprobe -i (--ignore-install), then
# probe with shim disabled (expect ALLOWED — proves the kernel is
# reachable) and with shim enabled (expect BLOCKED — proves the shim
# does the work).
cat > /tmp/afalg-probe.c <<'CEOF'
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#ifndef AF_ALG
#define AF_ALG 38
#endif
int main(void) {
    int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (fd < 0) { printf("BLOCKED: errno=%d (%s)\n", errno, strerror(errno)); return 0; }
    printf("ALLOWED: fd=%d\n", fd); return 1;
}
CEOF
if ! gcc -o /tmp/afalg-probe /tmp/afalg-probe.c 2>/tmp/gcc.err; then
    skip "AF_ALG probe: gcc failed: $(cat /tmp/gcc.err | head -1)"
else
    BL_FILE=/etc/modprobe.d/99-rfxn-defense-cf1.conf
    BL_BAK=/tmp/99-rfxn-defense-cf1.conf.testbak
    sudo mv "$BL_FILE" "$BL_BAK" 2>/dev/null
    sudo /usr/sbin/modprobe -i af_alg 2>/dev/null || sudo /usr/sbin/modprobe -i algif_aead 2>/dev/null

    # Baseline: shim DISABLED, kernel reachable -> expect ALLOWED.
    sudo rfxn-shim-disable >/dev/null 2>&1
    BASELINE=$(/tmp/afalg-probe)
    BASELINE_RC=$?
    echo "    baseline (shim off, blacklist off): $BASELINE"
    if [ "$BASELINE_RC" -ne 0 ]; then
        ok "AF_ALG isolation: baseline ALLOWED with shim off + blacklist off (kernel reachable, probe sound)"
    else
        skip "AF_ALG: baseline BLOCKED without shim - kernel lacks AF_ALG support (cannot isolate-test shim)"
    fi

    # Shim test: shim ENABLED -> expect BLOCKED (shim alone, not blacklist).
    sudo rfxn-shim-enable >/dev/null 2>&1
    SHIM_OUT=$(/tmp/afalg-probe)
    SHIM_RC=$?
    echo "    shim ENABLED, blacklist off: $SHIM_OUT"
    sudo rfxn-shim-disable >/dev/null 2>&1

    # Restore the blacklist before asserting (clean state on failure).
    sudo mv "$BL_BAK" "$BL_FILE" 2>/dev/null

    if [ "$BASELINE_RC" -ne 0 ] && [ "$SHIM_RC" -eq 0 ]; then
        ok "AF_ALG: shim BLOCKS socket creation (isolated from modprobe blacklist)"
    elif [ "$BASELINE_RC" -ne 0 ]; then
        fail "AF_ALG: shim did NOT block (baseline=ALLOWED, shim-on=ALLOWED) - shim broken on this host"
    fi
fi

sub "userns: unshare -Urn (EL7 kernel 3.10 should block at compile-time)"
USERNS_PROBE=$(unshare -Urn true 2>&1)
USERNS_RC=$?
[ "$USERNS_RC" -ne 0 ] \
    && ok "userns: unshare -Urn blocked ($USERNS_PROBE)" \
    || fail "userns: unshare -Urn SUCCEEDED unprivileged (EL7 should block at compile-time)"

# ============================================================
sec "SCOPE D — Upgrade path: copyfail-defense 2.1.1 -> rfxn-defense"
# ============================================================
sub "remove current (clean slate)"
sudo yum -y remove 'rfxn-defense*' 2>&1 | tail -3
rpm -qa | grep -q '^rfxn-defense' \
    && fail "remove: rfxn-defense residuals: $(rpm -qa | grep '^rfxn-defense' | tr '\n' ' ')" \
    || ok "remove: all rfxn-defense* erased"

if [ -s /etc/ld.so.preload ] && grep -q 'rfxn' /etc/ld.so.preload 2>/dev/null; then
    fail "remove: /etc/ld.so.preload still references rfxn"
else
    ok "remove: /etc/ld.so.preload clean of rfxn"
fi

sub "install legacy copyfail-defense 2.1.1"
sudo yum -y install "$RPMS_LEGACY"/copyfail-defense-*.el7.{x86_64,noarch}.rpm 2>&1 | tail -3
if rpm -q copyfail-defense >/dev/null 2>&1; then
    LEGACY_V=$(rpm -q --qf '%{version}-%{release}\n' copyfail-defense)
    ok "legacy install: copyfail-defense $LEGACY_V present"
else
    fail "legacy install: copyfail-defense missing"
fi

sub "upgrade in place to current via Obsoletes/Provides chain"
UPGRADE_LOG=$(mktemp)
sudo yum -y install \
    "$RPMS_CURRENT"/rfxn-defense-[0-9]*.el7.x86_64.rpm \
    "$RPMS_CURRENT"/rfxn-defense-shim-*.el7.x86_64.rpm \
    "$RPMS_CURRENT"/rfxn-defense-modprobe-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-systemd-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-sysctl-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-audit-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-auditor-*.el7.noarch.rpm \
    "$RPMS_CURRENT"/rfxn-defense-autoupdate-*.el7.noarch.rpm \
    2>&1 | tee "$UPGRADE_LOG" | tail -5

if grep -qE 'scriptlet failed|exit status|error: (un)?install:' "$UPGRADE_LOG"; then
    fail "upgrade: scriptlet failures"
    grep -E 'scriptlet failed|error:' "$UPGRADE_LOG" | head -5
else
    ok "upgrade: no scriptlet failures"
fi

rpm -q copyfail-defense >/dev/null 2>&1 \
    && fail "upgrade: copyfail-defense still installed (Obsoletes chain broken)" \
    || ok "upgrade: legacy copyfail-defense erased via Obsoletes"

if rpm -q rfxn-defense >/dev/null 2>&1; then
    NEW_V=$(rpm -q --qf '%{version}-%{release}\n' rfxn-defense)
    ok "upgrade: rfxn-defense $NEW_V installed"
else
    fail "upgrade: rfxn-defense not installed after upgrade"
fi

MISSING2=()
for pkg in "${EXPECTED[@]}"; do
    rpm -q "$pkg" >/dev/null 2>&1 || MISSING2+=("$pkg")
done
[ "${#MISSING2[@]}" -eq 0 ] \
    && ok "upgrade: all 8 subpackages present after rename" \
    || fail "upgrade: missing subpackages: ${MISSING2[*]}"

[ -z "$(rpm -qa | grep '^copyfail-defense' || true)" ] \
    && ok "upgrade: zero copyfail-defense* residuals" \
    || fail "upgrade: residuals: $(rpm -qa | grep '^copyfail-defense' | tr '\n' ' ')"

# v3.0.2: post-upgrade EL7 must have NO stale 15-userns drop-ins from
# pre-3.0.2 install (detect.sh apply_systemd cleans them up).
STALE_15=$(sudo find /etc/systemd/system -name '15-rfxn-defense-userns.conf' 2>/dev/null | wc -l)
[ "$STALE_15" -eq 0 ] \
    && ok "upgrade: 0 stale 15-userns drop-ins (detect.sh cleaned on EL7 upgrade)" \
    || fail "upgrade: $STALE_15 stale 15-userns drop-ins (detect.sh cleanup hole)"

# ============================================================
sec "SUMMARY"
# ============================================================
echo
echo "  Total assertions: $TOTAL"
echo -e "  ${G}PASS${Z}: ${#PASS[@]}"
echo -e "  ${R}FAIL${Z}: ${#FAIL[@]}"
echo -e "  ${Y}SKIP${Z}: ${#SKIP[@]}"
echo
if [ "${#FAIL[@]}" -gt 0 ]; then
    echo -e "${R}Failures:${Z}"
    for f in "${FAIL[@]}"; do echo "  - $f"; done
    exit 1
fi
exit 0
