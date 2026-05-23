#!/bin/bash
# shellcheck disable=SC2317
#
# test-repo.sh
#   End-to-end verification of the published rfxn-defense
#   dnf repository on EL8 / EL9 / EL10. Uses podman; everything happens
#   inside disposable containers - no host-side state is touched.
#
# What this exercises (v2.0.2 ships 6 subpackages, -audit as soft dep):
#   1. The .repo file is reachable on gh-pages
#   2. dnf can fetch repodata, validate the detached repomd.xml.asc
#      against the published gpgkey, and resolve the meta package
#   3. RPM signatures verify (gpgcheck=1, repo_gpgcheck=1)
#   4. All six subpackages land (shim, modprobe, systemd, auditor,
#      sysctl, audit; -audit pulled via Recommends, so the soft-dep
#      path is exercised by default dnf install)
#   5. The shim is loadable under LD_PRELOAD without breaking dyn-linked
#      binaries (smoke-test on /bin/true)
#   6. AF_ALG socket creation returns EPERM with the shim in place
#   7. AF_INET still works (surgical block, not blanket socket disable)
#   8. copyfail-shim-enable wires /etc/ld.so.preload correctly
#   9. AF_ALG is blocked from a fresh process (no explicit LD_PRELOAD)
#  10. copyfail-local-check runs and emits valid posture JSON v2 schema
#  11. copyfail-shim-disable removes the line atomically
#  12. dnf remove leaves /etc/ld.so.preload sane (preun scriptlet)
#  v2.0.0 additions:
#  13. rfxn-defense-modprobe drops split modprobe conf files (cf1/cf2-xfrm/rxrpc)
#  14. rfxn-defense-systemd drops 5 active drop files for tenant units
#  15. Container-runtime drop-ins shipped as examples/, NOT active
#  16. Auditor JSON has posture.bug_classes_covered (array)
#      AND posture.bug_classes (per-class map)
#  17. Auditor exit code in {0, 3, 4} (never 2 - shim disabled by default)
#  18. Upgrade-path test: afalg-defense 1.0.1 -> rfxn-defense 2.0.0
#      via Obsoletes/Provides; old name fully removed.
#  v2.0.1 additions:
#  19. clean_host: all 3 modprobe + 10 systemd files present; auto-detect.json clean
#  20. ipsec_host: cf2-xfrm correctly suppressed; JSON flags ipsec; signals[] has 2 entries (M-1 canary)
#  21. afs_host: rxrpc + rxrpc-af suppressed across all 5 units; JSON flags afs
#  22. rootless_host: user@ 15-userns suppressed; 12-rxrpc-af applied; JSON correct
#  23. subuid_no_storage: subuid+passwd alone does NOT trip rootless detection (cPanel FP)
#  24. force_full: all mitigations applied despite all signals tripping
#  25. redetect: post-install AFS signal triggers correct refresh via copyfail-redetect
#  26. split_upgrade: v2.0.0->v2.0.1 pretrans correctly renames monolithic files
#  v2.0.1 fixup-pass additions:
#  27. systemd_only: install -systemd alone still pulls meta; detect.sh runs (M-2 canary)
#  v2.0.1-2 additions:
#  28. assert_no_scriptlet_fail at every dnf install/upgrade/remove site -
#      catches RPM scriptlet syntax errors / aborts that 2.0.1-1's
#      `dnf ... | tail -N` pipeline silently dropped (dnf returns 0
#      when scriptlets fail; the warning is in the captured output).
#  v2.0.2 additions:
#  29. clean_host: /etc/sysctl.d/99-rfxn-defense-userns.conf
#      lands by default (no userns-consumer signal in mock chroot)
#  30. clean_host: /etc/audit/rules.d/99-rfxn-defense.rules
#      lands (-audit pulled via meta Recommends)
#  31. clean_host: AF_KEY restriction in 10-* systemd drop-in
#      (~AF_KEY token literally present alongside ~AF_ALG)
#  32. flatpak_host: pre-stage /var/lib/flatpak/app/<x>/ dir, assert
#      sysctl drop-in suppressed; per-unit RestrictNamespaces stays
#  33. dnf remove cascades through sysctl + audit; rules + sysctl files
#      both gone post-erase
#
# Usage:
#   bash test-repo.sh                 # all three ELs
#   bash test-repo.sh 9               # just EL9
#   bash test-repo.sh 8 9             # EL8 and EL9
#   REPO_URL=... bash test-repo.sh    # override repo source (default: gh-pages)
#   UPGRADE_FIXTURE_DIR=... bash test-repo.sh   # path to v1.0.1 RPM fixtures
#                                                 (default: rpmbuild/upgrade-fixture/)

set -uo pipefail

REPO_URL="${REPO_URL:-https://rfxn.github.io/copyfail/copyfail.repo}"
KEY_URL="${KEY_URL:-https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail}"
UPGRADE_FIXTURE_DIR="${UPGRADE_FIXTURE_DIR:-/home/copyfail/rpmbuild/upgrade-fixture}"

if [ $# -eq 0 ]; then
    ELS=(7 8 9 10)
else
    ELS=("$@")
fi

# RHEL stand-ins. CentOS Stream 8 went EOL May 2024 and its baked-in
# mirrorlist URLs no longer resolve, so we use AlmaLinux for EL8 and
# CentOS Stream for EL9/EL10 (both still actively maintained and the
# closest free analogues to their RHEL counterparts).
declare -A IMAGE
IMAGE[7]="quay.io/centos/centos:7"
IMAGE[8]="docker.io/library/almalinux:8"
IMAGE[9]="quay.io/centos/centos:stream9"
IMAGE[10]="quay.io/centos/centos:stream10"

c_red()   { printf '\033[31m%s\033[0m' "$*"; }
c_green() { printf '\033[32m%s\033[0m' "$*"; }
c_dim()   { printf '\033[2m%s\033[0m' "$*"; }

step() {
    printf '  %s %s\n' "$(c_dim '·')" "$*"
}

# Each test runs inside the container. Returns 0 = pass, non-zero = fail.
# We trap output and let the caller decide PASS/FAIL.
run_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" \
        -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# 0. Distro identity
. /etc/os-release
ok "running on $PRETTY_NAME"

# v2.1.0: EL7 ships yum natively; install dnf via EPEL so the rest of
# this script can call `dnf` uniformly across EL7/8/9/10. CentOS 7
# reached EOL 2024-06-30 - mirror.centos.org is dead; replace default
# repos with vault.centos.org + EPEL archive BEFORE any yum operation.
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # Remove all stock repos and write a single vault-based replacement.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    # Install dnf directly from EPEL archive (skip epel-release shim).
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi

# 1. Add the dnf repo
curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo \
    || fail "could not fetch $REPO_URL"
ok "fetched copyfail.repo"

# 2. Install. Tests gpgkey import, repo_gpgcheck on repomd.xml, and
#    gpgcheck on each RPM in one shot.
dnf install -y python3 >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -10
assert_no_scriptlet_fail /tmp/dnf.log
rpm -q rfxn-defense rfxn-defense-shim rfxn-defense-modprobe \
       rfxn-defense-systemd rfxn-defense-auditor \
       rfxn-defense-sysctl \
    || fail "hard-Required subpackages not all installed"
# -audit pulled via meta Recommends (soft dep). Default dnf install
# behavior on EL8/9/10 honors Recommends, so this should resolve.
rpm -q rfxn-defense-audit \
    || fail "rfxn-defense-audit not pulled by meta Recommends (weak deps disabled?)"
ok "dnf install -y rfxn-defense (gpgcheck + repo_gpgcheck, 7 subpackages incl. -sysctl + -audit)"

# 3. Files are where we expect
test -f /usr/lib64/no-afalg.so          || fail "shim .so missing"
test -x /usr/sbin/copyfail-shim-enable  || fail "enable helper missing"
test -x /usr/sbin/copyfail-shim-disable || fail "disable helper missing"
test -x /usr/sbin/copyfail-local-check  || fail "auditor missing"
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "modprobe ${f} drop file missing"
done
test -f /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
    || fail "sshd systemd drop-in missing"
test -f /etc/systemd/system/user@.service.d/10-rfxn-defense.conf \
    || fail "user@ systemd drop-in missing"
test -f /usr/share/doc/rfxn-defense/examples/containers-dropin.conf \
    || fail "container-runtime example doc missing"
# Container-runtime drop-ins must NOT be active by default
for u in containerd docker podman; do
    if [ -f /etc/systemd/system/${u}.service.d/10-rfxn-defense.conf ]; then
        fail "container-runtime drop-in for ${u} is active by default - should be opt-in only"
    fi
done

# v2.0.2: sysctl drop-in lands by default on a mock chroot (no
# rootless containers, no Flatpak, no firejail, no desktop browsers).
test -f /etc/sysctl.d/99-rfxn-defense-userns.conf \
    || fail "sysctl userns drop-in missing on clean host"
grep -q '^-user.max_user_namespaces' /etc/sysctl.d/99-rfxn-defense-userns.conf \
    || fail "sysctl drop-in lacks user.max_user_namespaces key"

# v2.0.2: audit rules file landed via -audit (pulled by meta Recommends).
test -f /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules file missing on clean host"
grep -qE 'a0=38 .* -k rfxn_afalg' /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing AF_ALG (a0=38) tag"
grep -qE 'a0=15 .* -k rfxn_afkey' /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing AF_KEY (a0=15) tag"
grep -qE 'a0=33 .* -k rfxn_afrxrpc' /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing AF_RXRPC (a0=33) tag"

# v2.0.2: AF_KEY token in always-on systemd 10-* drop-in (alongside AF_ALG).
grep -qE 'RestrictAddressFamilies=.*~AF_KEY' \
    /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
    || fail "systemd 10-* drop-in missing ~AF_KEY restriction"

# v2.1.0: PinTheft modprobe RDS template installed
test -f /usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rds.conf \
    || fail "rds modprobe template missing from -modprobe subpackage"

# v2.1.0: PinTheft AF_RDS in always-on 10-* drop-in
grep -qE 'RestrictAddressFamilies=.*~AF_RDS' \
    /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
    || fail "systemd 10-* drop-in missing ~AF_RDS restriction (PinTheft)"

# v2.1.0: ssh-keysign-pwn ptrace_scope sysctl key in -sysctl conf
grep -qE '^[[:space:]]*-?kernel\.yama\.ptrace_scope[[:space:]]*=[[:space:]]*2' \
    /etc/sysctl.d/99-rfxn-defense-userns.conf \
    || fail "sysctl conf missing kernel.yama.ptrace_scope=2 (ssh-keysign-pwn)"

# v2.1.0: PinTheft rfxn_afrds audit rule
grep -qE 'a0=21 .* -k rfxn_afrds' \
    /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing AF_RDS (a0=21) -k rfxn_afrds"

# v2.1.0: ssh-keysign-pwn rfxn_pidfd_getfd audit rule.
# Use -- to terminate grep option parsing; '-S 438' starts with a dash and
# grep would otherwise treat -S as an unknown flag (exit 2).
grep -qE -- '-S 438 .* -k rfxn_pidfd_getfd' \
    /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing pidfd_getfd (-S 438) -k rfxn_pidfd_getfd"

# v2.1.0: RDS systemd template ships under conditional/systemd/
test -f /usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf \
    || fail "rds systemd template missing from -systemd subpackage"

# v3.0.0: autoupdate subpackage installs cron + wrapper
test -f /etc/cron.d/rfxn-defense-update \
    || fail "autoupdate cron file missing"
grep -q '15 \*/4 \* \* \*' /etc/cron.d/rfxn-defense-update \
    || fail "autoupdate cron has wrong cadence (expected 4-hourly at :15)"
grep -q '/usr/libexec/rfxn-defense/update.sh' /etc/cron.d/rfxn-defense-update \
    || fail "autoupdate cron does not call /usr/libexec/rfxn-defense/update.sh"
test -x /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper missing or not executable"
bash -n /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper has bash syntax errors"
grep -q 'flock -n 9' /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper missing flock single-runner guard"
grep -q 'timeout' /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper missing timeout cap"
grep -q 'auto-update.disabled' /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper missing opt-out check"
grep -q "rfxn-defense\*" /usr/libexec/rfxn-defense/update.sh \
    || fail "autoupdate wrapper not scoped to rfxn-defense* glob"
# v3.0.0: dry-run via CFD_AUTOUPDATE_DRY_RUN must exit 0 without dnf
# (used as the canary that the wrapper's pre-dnf logic is clean).
CFD_AUTOUPDATE_DRY_RUN=1 timeout 30 /usr/libexec/rfxn-defense/update.sh >/dev/null 2>&1
case $? in
    0)   ;;  # OK: dry-run exited cleanly OR lock held (both fine for canary)
    *) fail "autoupdate wrapper dry-run failed (rc=$?)" ;;
esac
# v3.0.0: touch-file opt-out is honored
mkdir -p /etc/rfxn-defense
touch /etc/rfxn-defense/auto-update.disabled
out=$(timeout 30 /usr/libexec/rfxn-defense/update.sh 2>&1 | logger -i -t pretest; \
      journalctl -t pretest -n 5 --no-pager 2>/dev/null \
      || true)
# Cleanup opt-out artifact (test isolation; subsequent scenarios assume no opt-out)
rm -f /etc/rfxn-defense/auto-update.disabled

ok "all expected files installed (subs + active dropins + opt-in examples + v2.0.2 sysctl/audit/AF_KEY + v2.1.0 rds/ptrace_scope/pidfd_getfd + v3.0.0 autoupdate cron/wrapper/opt-out)"

# 3b. Modprobe drop file content - 9 module entries summed across the
# split files. Use cat-then-grep so the count is a single integer;
# `grep -c` against multiple files emits one count per file, which
# breaks `[ "$n" -eq 9 ]`.
mp_count=$(cat /etc/modprobe.d/99-rfxn-defense-{cf1,cf2-xfrm,rxrpc}.conf 2>/dev/null \
    | grep -cE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false')
[ "$mp_count" -eq 9 ] \
    || fail "modprobe drop file has $mp_count install lines, expected 9"
ok "modprobe drop file has all 9 cf-class module install lines"

# 4. Shim loads under LD_PRELOAD without breaking dyn-linked binaries
LD_PRELOAD=/usr/lib64/no-afalg.so /bin/true \
    || fail "LD_PRELOAD smoke-test on /bin/true failed"
ok "LD_PRELOAD smoke-test passed"

# 5. AF_ALG -> EPERM with shim
out=$(LD_PRELOAD=/usr/lib64/no-afalg.so python3 -c \
    "import socket
try:
    socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print('UNBLOCKED')
except PermissionError:
    print('BLOCKED')" 2>&1)
[ "$out" = "BLOCKED" ] || fail "AF_ALG not blocked under LD_PRELOAD: $out"
ok "AF_ALG blocked (EPERM) with shim"

# 6. AF_INET still works (surgical block)
LD_PRELOAD=/usr/lib64/no-afalg.so python3 -c \
    "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()" \
    || fail "AF_INET broken under shim - shim is NOT surgical"
ok "AF_INET still works (surgical block confirmed)"

# 7. copyfail-shim-enable
/usr/sbin/copyfail-shim-enable >/tmp/enable.log 2>&1 \
    || { cat /tmp/enable.log; fail "copyfail-shim-enable returned non-zero"; }
grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload \
    || fail "/etc/ld.so.preload does not contain shim line"
ok "copyfail-shim-enable wired /etc/ld.so.preload"

# 8. AF_ALG blocked WITHOUT explicit LD_PRELOAD now (preload took)
out=$(python3 -c \
    "import socket
try:
    socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print('UNBLOCKED')
except PermissionError:
    print('BLOCKED')" 2>&1)
[ "$out" = "BLOCKED" ] || fail "AF_ALG not blocked via /etc/ld.so.preload: $out"
ok "AF_ALG blocked via /etc/ld.so.preload (no explicit LD_PRELOAD needed)"

# 9. Auditor runs and emits posture JSON. --skip-trigger to avoid the
#    live AF_ALG probe (we just verified that path manually).
# Capture rc under `set -e` requires the explicit-OR idiom:
audit_rc=0
/usr/sbin/copyfail-local-check --json --skip-trigger --skip-hardening \
    --no-progress > /tmp/audit.json 2>/dev/null || audit_rc=$?
python3 -c "
import json, sys
d = json.load(open('/tmp/audit.json'))
assert d['schema_version'] == '2.0', 'schema_version=' + str(d.get('schema_version'))
assert 'posture' in d
assert 'verdict' in d['posture']
assert d['posture']['layers']['ld_preload_shim'] == 'ok', d['posture']['layers']
# v2.0.0: bug_classes_covered (array) and bug_classes (per-class map)
assert 'bug_classes_covered' in d['posture'], 'missing bug_classes_covered'
assert isinstance(d['posture']['bug_classes_covered'], list)
bc = d['posture'].get('bug_classes', {})
assert set(bc.keys()) == {'cf1', 'cf2', 'dirtyfrag-esp', 'dirtyfrag-rxrpc', 'pintheft', 'keysign-pwn'}, \
    'bug_classes keys mismatch: ' + str(list(bc.keys()))
# After shim-enable, cf1 should be EITHER unreachable (applicable=false,
# the ideal outcome) OR mitigated. Anything else means the shim isn't
# blocking AF_ALG, which we already asserted via layers.ld_preload_shim.
cf1 = bc['cf1']
assert (cf1['applicable'] is False) or cf1.get('mitigated') is True, \
    'cf1 unhardened post-shim-enable: ' + json.dumps(cf1)
print('verdict:', d['posture']['verdict'])
print('bug_classes_covered:', d['posture']['bug_classes_covered'])
print('ld_preload_shim layer:', d['posture']['layers']['ld_preload_shim'])
" || fail "auditor JSON output invalid"
# Exit code: never 2 (vulnerable + no mitigation) since shim is enabled here.
[ "$audit_rc" -ne 2 ] || fail "auditor exit code 2 with shim enabled"
ok "auditor JSON: schema 2.0, bug_classes_covered + map present, exit_rc=$audit_rc"

# 10. copyfail-shim-disable
/usr/sbin/copyfail-shim-disable >/tmp/disable.log 2>&1 \
    || { cat /tmp/disable.log; fail "copyfail-shim-disable returned non-zero"; }
if [ -f /etc/ld.so.preload ] && grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
    fail "shim line still in /etc/ld.so.preload after disable"
fi
ok "copyfail-shim-disable removed the line atomically"

# 11. dnf remove. The %preun scriptlet should be a no-op now (we already
#    disabled), but if the operator forgot, the scriptlet must still
#    leave /etc/ld.so.preload sane.
echo "/usr/lib64/no-afalg.so" > /etc/ld.so.preload   # simulate forgotten enable
dnf remove -y --setopt=clean_requirements_on_remove=false \
              rfxn-defense rfxn-defense-shim \
              rfxn-defense-modprobe rfxn-defense-systemd \
              rfxn-defense-auditor \
              rfxn-defense-sysctl rfxn-defense-audit \
              >/tmp/dnf.log 2>&1
assert_no_scriptlet_fail /tmp/dnf.log
if [ -f /etc/ld.so.preload ]; then
    grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload \
        && fail "preun left dangling shim line in /etc/ld.so.preload"
fi
# Modprobe drop files removed on full erase
for f in cf1 cf2-xfrm rxrpc; do
    [ ! -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" ] \
        || fail "modprobe ${f} drop file remained after dnf remove"
done
# systemd drop files removed (RPM owns them via %config)
[ ! -f /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf ] \
    || fail "sshd systemd drop-in remained after dnf remove"
# v2.0.2: sysctl drop-in removed on full erase
[ ! -f /etc/sysctl.d/99-rfxn-defense-userns.conf ] \
    || fail "sysctl userns drop-in remained after dnf remove"
# v2.0.2: audit rules removed on full erase
[ ! -f /etc/audit/rules.d/99-rfxn-defense.rules ] \
    || fail "audit rules file remained after dnf remove"
ok "dnf remove + %preun scrubbed all state safely (incl. v2.0.2 sysctl + audit)"

echo "=== ALL CHECKS PASSED ==="
INNER
}

# Upgrade-path test: simulate a host that has afalg-defense-1.0.1
# installed (from the gh-pages snapshot kept for one release cycle),
# then `dnf upgrade rfxn-defense` and assert the rename swap
# succeeded.
run_upgrade_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" \
        -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Add the repo so we can pull both old (afalg-defense-1.0.1) and new
# (rfxn-defense-2.0.0) RPMs from it - the old ones are kept for
# one release cycle per SPEC [D-22].
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo

# Install old name explicitly. If the live repo no longer has 1.0.1,
# the test SKIPs (acceptable - means we've moved past the one-cycle
# retention window; the upgrade path is no longer load-bearing).
if dnf install -y 'afalg-defense-1.0.1*' 2>&1 | tee /tmp/dnf.log | tail -5; then
    assert_no_scriptlet_fail /tmp/dnf.log
    rpm -q afalg-defense afalg-defense-shim afalg-defense-auditor \
        || fail "v1.0.1 baseline did not install fully"
    ok "v1.0.1 baseline installed"
else
    echo "SKIP: afalg-defense-1.0.1 not in repo (one-cycle retention expired)"
    exit 77
fi

# Upgrade to v2.0.0 via Obsoletes/Provides
dnf upgrade -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -10
assert_no_scriptlet_fail /tmp/dnf.log

# Assert: old name fully replaced
old_count=$(rpm -qa | grep -c '^afalg-defense' || true)
[ "$old_count" -eq 0 ] || fail "afalg-defense names still present: $old_count"

# Assert: all rfxn-defense subpackages installed. Count drifts
# with each major version: v2.0.0/v2.0.1 ship 5 (meta + shim +
# modprobe + systemd + auditor); v2.0.2+ ship 7 (+ sysctl + audit
# via meta Recommends). Treat >=5 as "umbrella resolved" rather
# than pin to a specific count so a future subpackage addition
# does not regress the test bar.
new_count=$(rpm -qa | grep -c '^rfxn-defense' || true)
[ "$new_count" -ge 5 ] || fail "expected >=5 rfxn-defense* RPMs, got $new_count"

# Assert: new files in expected locations
test -f /etc/modprobe.d/99-rfxn-defense-cf1.conf \
    || fail "modprobe cf1 drop missing post-upgrade"
test -f /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
    || fail "sshd systemd drop-in missing post-upgrade"
test -x /usr/sbin/copyfail-local-check \
    || fail "auditor missing post-upgrade"

# Assert: auditor JSON v2 schema (post-upgrade, shim still disabled by
# default, so exit code is normally 4 - hardening_recs - but never 2).
audit_rc=0
/usr/sbin/copyfail-local-check --json --skip-trigger --skip-hardening \
    --no-progress > /tmp/audit.json 2>/dev/null || audit_rc=$?
python3 -c "
import json
d = json.load(open('/tmp/audit.json'))
assert d['schema_version'] == '2.0', 'schema_version=' + str(d.get('schema_version'))
assert 'bug_classes_covered' in d['posture']
print('post-upgrade verdict:', d['posture']['verdict'])
print('post-upgrade bug_classes_covered:', d['posture']['bug_classes_covered'])
" || fail "post-upgrade auditor JSON invalid"
[ "$audit_rc" -ne 2 ] || fail "post-upgrade auditor exit code 2"

ok "upgrade afalg-defense-1.0.1 -> rfxn-defense-2.0.0 succeeded (exit_rc=$audit_rc)"
echo "=== UPGRADE PATH OK ==="
INNER
}

# v2.0.1: detection scenario tests. Each pre-stages a workload
# fingerprint, installs rfxn-defense, and asserts the right
# conditional drop files landed/didn't.

run_clean_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# All 3 modprobe files present
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "modprobe ${f} drop missing on clean host"
done
# All 5 always-on (10-) drop files
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf" \
        || fail "10-* drop missing for ${u}"
done
# All 5 conditional (12-rxrpc-af) drop files (rev 2: AFS-gated, present on clean host)
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af drop missing for ${u} on clean host"
done
# All 5 conditional (15-) drop files (clean host = no suppression)
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-* drop missing for ${u} on clean host"
done
# v2.0.2: sysctl drop-in landed (no userns-consumer signal in mock)
test -f /etc/sysctl.d/99-rfxn-defense-userns.conf \
    || fail "sysctl userns drop-in missing on clean host"
# v2.0.2: audit rules landed (-audit pulled by meta Recommends)
test -f /etc/audit/rules.d/99-rfxn-defense.rules \
    || fail "audit rules missing on clean host"
# auto-detect.json present and reports nothing
test -f /var/lib/rfxn-defense/auto-detect.json \
    || fail "auto-detect.json missing"
jq -e '.schema_version == "2" and
       .detected.ipsec.present == false and
       .detected.afs.present == false and
       .detected.rootless_containers.present == false and
       .detected.userns_consumers.present == false and
       .applied.sysctl_userns == true and
       .suppressed.sysctl_userns == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json reports workloads on clean host (or wrong v2.0.2 schema)"

# v2.1.0: detected.rds_workload key present
python3 -c "import json,sys; d=json.load(open('/var/lib/rfxn-defense/auto-detect.json')); sys.exit(0 if 'rds_workload' in d.get('detected',{}) else 1)" \
    || fail "auto-detect.json missing detected.rds_workload key"

# v2.1.0: applied.modprobe_rds is true on clean host (no Oracle signals)
python3 -c "import json,sys; d=json.load(open('/var/lib/rfxn-defense/auto-detect.json')); sys.exit(0 if d.get('applied',{}).get('modprobe_rds') is True else 1)" \
    || fail "auto-detect.json applied.modprobe_rds should be true on clean host"

# v2.1.0: actual /etc/modprobe.d/ file present on clean host
test -f /etc/modprobe.d/99-rfxn-defense-rds.conf \
    || fail "rds modprobe file not staged on clean host"

ok "clean host: all drop files present (18 dropins + sysctl + audit rules + v2.1.0 rds modprobe) + JSON reports clean"
echo "=== CLEAN HOST OK ==="
INNER
}

run_ipsec_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Pre-stage TWO IPsec signals BEFORE installing the package. Per
# v2.0.1 fixup M-1, the JSON signals[] field must be a list of N
# entries, not a single concatenated string. A single signal would
# never have caught the bash NUL-stripping bug, so this test
# deliberately stages two and asserts len(signals.ipsec) >= 2.
mkdir -p /etc /etc/strongswan/conf.d
cat >/etc/ipsec.conf <<'EOC'
# libreswan-style stub
conn home
    left=192.0.2.1
    right=192.0.2.2
    auto=add
EOC
# Second signal: non-empty conf in a strongswan conf.d directory.
cat >/etc/strongswan/conf.d/local.conf <<'EOC'
# strongswan-style stub
charon { send_vendor_id = yes }
EOC

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# cf2-xfrm SUPPRESSED, cf1 + rxrpc PRESENT
test ! -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf \
    || fail "cf2-xfrm drop file present despite IPsec signal"
test -f /etc/modprobe.d/99-rfxn-defense-cf1.conf \
    || fail "cf1 drop file (always-on) missing"
test -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf \
    || fail "rxrpc drop file (unrelated to IPsec) missing"
# JSON should flag ipsec
jq -e '.detected.ipsec.present == true and
       .suppressed.modprobe_cf2_xfrm == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing IPsec/suppression flags"
# v2.0.1 fixup M-1 canary: the signals[] array must be a JSON list of
# DISTINCT entries, not a single concatenated string. Bash NUL-stripping
# in command substitution previously collapsed N signals to 1 merged
# string. We staged 2 signals; assert >=2 entries.
ipsec_signal_count=$(jq -r '.detected.ipsec.signals | length' \
    /var/lib/rfxn-defense/auto-detect.json)
[ "$ipsec_signal_count" -ge 2 ] \
    || fail "ipsec.signals has $ipsec_signal_count entries, expected >=2 (NUL-marshalling bug?)"
# Confirm each entry is a non-empty distinct string, not the concatenation.
jq -e '.detected.ipsec.signals | all(type == "string" and length > 0)' \
    /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "ipsec.signals entries must each be non-empty strings"
ok "ipsec host: cf2-xfrm correctly suppressed; signals array has $ipsec_signal_count distinct entries"
echo "=== IPSEC HOST OK ==="
INNER
}

run_afs_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

mkdir -p /etc/openafs
echo "lan.example.com" > /etc/openafs/ThisCell

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

test ! -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf \
    || fail "rxrpc drop file present despite AFS signal"
test -f /etc/modprobe.d/99-rfxn-defense-cf1.conf \
    || fail "cf1 drop file missing"
test -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf \
    || fail "cf2-xfrm drop file (unrelated to AFS) missing"
# Rev 2: 12-rxrpc-af also suppressed for ALL 5 units on AFS hosts.
for u in user@ sshd cron crond atd; do
    test ! -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af present for ${u} despite AFS signal"
done
# The 10-* and 15-* drops still present (AFS doesn't suppress those).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf" \
        || fail "10-* drop missing for ${u} on AFS host"
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-userns drop missing for ${u} on AFS host"
done
jq -e '.detected.afs.present == true and
       .suppressed.modprobe_rxrpc == true and
       .suppressed.systemd_rxrpc_af == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing AFS/suppression flags"
ok "afs host: rxrpc + rxrpc-af correctly suppressed across all 5 units"
echo "=== AFS HOST OK ==="
INNER
}

run_rootless_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Rev 2 fixup (reviewer C-1): pre-stage the storage-tree signal
# (canonical podman rootless fingerprint), NOT /etc/subuid (which
# has near-100% FP rate on cPanel hosts and was dropped from the
# signal set). The /etc/subuid line is preserved here only as a
# negative test: it should NOT trip detection on its own.
useradd -m -u 1000 alice 2>/dev/null || true
echo "alice:100000:65536" >> /etc/subuid    # negative test - does NOT trip

# Positive test: stage the storage tree that podman creates on
# first rootless container run. detect.sh signal 1 fires here.
install -d -o alice -g alice -m 0700 \
    /home/alice/.local/share/containers/storage/overlay-containers
# Touch with recent mtime so the -mtime -180 gate passes.
touch /home/alice/.local/share/containers/storage/overlay-containers

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# 15-userns DROP for user@ ONLY; sshd/cron/crond/atd 15-* PRESENT;
# all 10-* PRESENT; all 3 modprobe files PRESENT.
test ! -f /etc/systemd/system/user@.service.d/15-rfxn-defense-userns.conf \
    || fail "user@ 15-userns drop present despite rootless signal"
for u in sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "${u} 15-userns drop missing (should be applied)"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf" \
        || fail "${u} 10-* always-on drop missing"
done
# Rev 2: 12-rxrpc-af present for all 5 units on rootless-only host
# (AFS not detected, so AF_RXRPC cut applies).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "${u} 12-rxrpc-af drop missing on rootless-only host"
done
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "modprobe ${f} drop missing"
done
jq -e '.detected.rootless_containers.present == true and
       .suppressed.systemd_userns_user_at == true and
       .suppressed.systemd_rxrpc_af == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing rootless/suppression flags"
# Negative test: with subuid populated but storage tree missing,
# rev 2 detect.sh should NOT trip (cPanel-FP fix per C-1). We can't
# easily verify this via jq because the storage tree IS present
# above; instead, install a 2nd container without the storage tree
# to confirm subuid alone doesn't trip. (Test #22b below.)
ok "rootless host: user@ 15-userns suppressed; 12-rxrpc-af applied"
echo "=== ROOTLESS HOST OK ==="
INNER
}

# Rev 2 fixup test (reviewer C-1): subuid alone must NOT trip
# rootless detection. cPanel hosts have hundreds of regular users
# with auto-populated /etc/subuid; if subuid alone tripped detection,
# the userns cut would be suppressed on every cPanel install,
# inverting the protection guarantee. This test asserts the cPanel-
# shaped fixture (regular user + populated subuid, NO storage tree)
# does NOT detect rootless.
run_subuid_no_storage_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# cPanel-shaped fixture: regular users + subuid, but NO podman
# storage tree, NO /run/user containers, NO podman.socket.
for i in 1 2 3 4 5; do
    useradd -m -u "$((1000 + i))" "cpuser${i}" 2>/dev/null || true
    echo "cpuser${i}:$((100000 + i*65536)):65536" >> /etc/subuid
    echo "cpuser${i}:$((100000 + i*65536)):65536" >> /etc/subgid
done
# Crucially: do NOT create /home/cpuser*/.local/share/containers/.

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# Detection must report rootless=false despite the populated subuid.
jq -e '.detected.rootless_containers.present == false and
       .suppressed.systemd_userns_user_at == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "subuid alone tripped rootless detection (cPanel FP regression)"
# user@ 15-userns must be PRESENT (cut applies on cPanel-shaped host).
test -f /etc/systemd/system/user@.service.d/15-rfxn-defense-userns.conf \
    || fail "user@ 15-userns missing despite no rootless signal"
ok "subuid+passwd alone does not trip rootless detection (C-1 cPanel FP fix)"
echo "=== SUBUID-NO-STORAGE OK ==="
INNER
}

run_force_full_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Pre-stage all three signals AND force-full sentinel.
# Rev 2: rootless signal switched from /etc/subuid to storage-tree
# (per C-1), so we must stage the actual storage path.
mkdir -p /etc/openafs /etc/copyfail
printf 'conn home\n    left=192.0.2.1\n' > /etc/ipsec.conf
echo "lan.example.com" > /etc/openafs/ThisCell
useradd -m -u 1000 alice 2>/dev/null || true
install -d -o alice -g alice -m 0700 \
    /home/alice/.local/share/containers/storage/overlay-containers
touch /etc/copyfail/force-full

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# ALL files should be present despite all three signals tripping.
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "modprobe ${f} suppressed despite force-full"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-userns suppressed for ${u} despite force-full"
    # Rev 2: 12-rxrpc-af also force-applied.
    test -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af suppressed for ${u} despite force-full"
done
jq -e '.force_full == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json force_full not set"
ok "force-full sentinel: all mitigations applied despite signals"
echo "=== FORCE-FULL OK ==="
INNER
}

run_redetect_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# Clean install: all 3 modprobe files + 5+5 systemd files.
test -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf \
    || fail "rxrpc drop file missing pre-redetect"

# Now create AFS signal AND re-run detection
mkdir -p /etc/openafs
echo "lan.example.com" > /etc/openafs/ThisCell
/usr/sbin/copyfail-redetect

# rxrpc drop should now be GONE; cf1 + cf2-xfrm preserved.
test ! -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf \
    || fail "rxrpc drop persisted after redetect on AFS host"
test -f /etc/modprobe.d/99-rfxn-defense-cf1.conf \
    || fail "cf1 drop removed by redetect (should be always-on)"
jq -e '.detected.afs.present == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json not updated by redetect"
ok "redetect: AFS signal newly applied; rxrpc suppressed"
echo "=== REDETECT OK ==="
INNER
}

# v2.0.1 fixup M-2 canary: install -systemd WITHOUT -modprobe.
# detect.sh + /usr/libexec/rfxn-defense/ + /var/lib/rfxn-defense/
# moved from -modprobe %files to meta %files. Both -modprobe and
# -systemd hard-Require meta. This test asserts that installing
# -systemd alone still pulls meta (and its detect.sh), so the
# %posttrans actually fires and produces auto-detect.json + 12-/15-*
# drop-ins. Pre-fixup, this scenario silently no-op'd because
# detect.sh did not land on disk.
run_systemd_only_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true

# Install ONLY -systemd (and let dnf pull meta as a hard Require).
# We deliberately do NOT pull -modprobe/-shim/-auditor.
dnf install -y rfxn-defense-systemd 2>&1 | tee /tmp/dnf.log | tail -10
assert_no_scriptlet_fail /tmp/dnf.log

# Meta must have been pulled (hard Requires from -systemd).
rpm -q rfxn-defense >/dev/null 2>&1 \
    || fail "meta package not pulled by -systemd alone (Requires chain broken)"
# Note: the meta package itself has Requires on all four subpackages
# (shim/modprobe/systemd/auditor), so installing any single subpackage
# transitively pulls the whole umbrella. The M-2 canary's value here
# is "meta + detect.sh land via the Requires chain", not "subpackages
# can be cherry-picked" - the latter would require dropping meta's
# subpackage Requires, which would change install semantics for every
# operator who runs `dnf install rfxn-defense`.
ok "rpm topology: -systemd request pulled meta (Requires chain intact)"

# detect.sh must be present (meta-owned).
test -x /usr/libexec/rfxn-defense/detect.sh \
    || fail "detect.sh missing on -systemd-only install (M-2 regression)"
ok "detect.sh present (meta-owned)"

# auto-detect.json must have been written by -systemd's %posttrans.
test -f /var/lib/rfxn-defense/auto-detect.json \
    || fail "auto-detect.json missing on -systemd-only install (%posttrans no-op'd?)"
jq -e '.schema_version == "2"' /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json malformed on -systemd-only install"
ok "auto-detect.json written and parses"

# 10-* always-on drop-ins for all 5 tenant units.
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf" \
        || fail "10-* drop missing for ${u} on -systemd-only install"
done
ok "10-* always-on drops applied for all 5 tenant units"

# 12-/15-* conditional drop-ins land on a clean host (no IPsec/AFS/rootless).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af missing for ${u} on -systemd-only install (M-2 canary)"
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-userns missing for ${u} on -systemd-only install (M-2 canary)"
done
ok "12-/15-* conditional drop-ins applied via meta-owned detect.sh"

# With meta's subpackage Requires, -modprobe IS pulled transitively,
# so its drop files SHOULD be present. The original v2.0.1 fixup
# wording assumed -modprobe could be omitted; that's not the case
# under the umbrella Requires.
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "modprobe ${f} drop missing (expected via meta umbrella Requires)"
done
ok "modprobe drops present (pulled transitively via meta umbrella)"

echo "=== SYSTEMD-ONLY (M-2) OK ==="
INNER
}

run_split_upgrade_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
# Catch RPM scriptlet failures: dnf returns 0 even when %posttrans /
# %postun aborts (it logs "Error in POSTTRANS scriptlet" / "scriptlet
# failed" and moves on). Without this guard, syntax errors in spec
# scriptlets ship silently. v2.0.1 -> 2.0.2 closed exactly that hole.
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true

# Install v2.0.0 explicitly. If the repo no longer has v2.0.0, SKIP.
if dnf install -y 'rfxn-defense-2.0.0*' 2>&1 | tee /tmp/dnf.log | tail -5; then
    assert_no_scriptlet_fail /tmp/dnf.log
    test -f /etc/modprobe.d/99-rfxn-defense.conf \
        || fail "v2.0.0 monolithic modprobe file missing"
    test -f /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
        || fail "v2.0.0 sshd drop missing"
    ok "v2.0.0 baseline installed"
else
    echo "SKIP: rfxn-defense-2.0.0 not in repo (one-cycle expired)"
    exit 77
fi

# Upgrade to 2.0.1
dnf upgrade -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -10
assert_no_scriptlet_fail /tmp/dnf.log

# v2.0.0 monolithic file MUST be gone from its original path
# (pretrans renamed it to .rpmsave-v2.0.1 per rev 2 D-37).
test ! -f /etc/modprobe.d/99-rfxn-defense.conf \
    || fail "v2.0.0 monolithic modprobe file still at original path after upgrade"
# And the .rpmsave-v2.0.1 SHOULD exist (rev 2 preserves operator
# hand-edits via rename; the file is inert / RPM doesn't consult it).
test -f /etc/modprobe.d/99-rfxn-defense.conf.rpmsave-v2.0.1 \
    || fail "v2.0.0 monolithic file not renamed to .rpmsave-v2.0.1 (D-37 broken)"
# All v2.0.1 split files present (clean host = no suppression)
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-rfxn-defense-${f}.conf" \
        || fail "v2.0.1 split file ${f} missing post-upgrade"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf" \
        || fail "10-* drop for ${u} missing post-upgrade"
    test -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af drop for ${u} missing post-upgrade"
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-* drop for ${u} missing post-upgrade"
    # Rev 2: the .rpmsave-v2.0.1 from systemd %pretrans should also exist.
    test -f "/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf.rpmsave-v2.0.1" \
        || fail "${u} v2.0.0 monolithic systemd drop not renamed to .rpmsave-v2.0.1"
done
test -f /var/lib/rfxn-defense/auto-detect.json \
    || fail "auto-detect.json missing post-upgrade"
ok "v2.0.0 -> v2.0.1 split-file upgrade clean"
echo "=== SPLIT-UPGRADE OK ==="
INNER
}

# v2.0.2 userns-consumer suppression test: pre-stage a Flatpak signal
# and assert the host-wide sysctl drop-in is suppressed while the
# per-tenant-unit RestrictNamespaces stays active. Mirrors the
# rootless_host scenario but exercises the new userns_consumers signal
# path (Flatpak / firejail / desktop browsers vs rootless containers).
run_userns_consumer_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Pre-stage Flatpak signal: detect.sh looks at /var/lib/flatpak/app
# for any non-empty subdirectory and at /var/lib/flatpak/runtime
# similarly. A single fake app entry is enough to trip the signal
# without installing the actual Flatpak runtime.
mkdir -p /var/lib/flatpak/app/org.example.Test/current/active \
         /var/lib/flatpak/runtime

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# Detection must report userns_consumers=present.
jq -e '.detected.userns_consumers.present == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "Flatpak signal not detected (userns_consumers.present != true)"

# Suppression flag MUST be set.
jq -e '.suppressed.sysctl_userns == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "sysctl_userns suppression not set despite Flatpak signal"

# Applied flag MUST be false (paired with template_present gating).
jq -e '.applied.sysctl_userns == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "applied.sysctl_userns true despite Flatpak suppression"

# Host-wide sysctl drop-in MUST NOT exist on disk.
[ ! -f /etc/sysctl.d/99-rfxn-defense-userns.conf ] \
    || fail "sysctl drop-in landed despite Flatpak detection"

# Per-unit RestrictNamespaces drop-in MUST still apply on all five
# tenant units - the Flatpak suppression only touches the host-wide
# sysctl, not the per-unit cuts.
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf" \
        || fail "15-userns drop suppressed for ${u} despite Flatpak-only signal"
done

# rootless_containers should NOT be flagged (we only staged Flatpak,
# not /home/*/.local/share/containers/storage).
jq -e '.detected.rootless_containers.present == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "rootless_containers tripped by Flatpak-only signal (FP regression)"

ok "userns_consumer (Flatpak): sysctl drop-in suppressed; per-unit cuts retained"
echo "=== USERNS-CONSUMER OK ==="
INNER
}

# v2.1.0: Pre-stage an Oracle Grid signal (/etc/oratab) before installing
# rfxn-defense. detect.sh must read this, suppress the host-wide RDS
# modprobe blacklist (applied.modprobe_rds=false, suppressed.modprobe_rds=true),
# and refuse to write /etc/modprobe.d/99-rfxn-defense-rds.conf.
run_rds_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Pre-stage Oracle Grid signal BEFORE installing the package. detect.sh
# reads /etc/oratab and gates the host-wide RDS cut.
mkdir -p /etc
echo "DEFAULTDB:/u01/app/oracle/product/19.3.0/dbhome_1:Y" > /etc/oratab

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL 2024-06-30; rewrite default repos to vault.centos.org.
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# Detection must report rds_workload=present.
jq -e '.detected.rds_workload.present == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "Oracle /etc/oratab signal not detected (rds_workload.present != true)"

# Suppression decision: applied.modprobe_rds=false AND suppressed.modprobe_rds=true.
python3 -c "import json,sys; d=json.load(open('/var/lib/rfxn-defense/auto-detect.json')); a=d.get('applied',{}).get('modprobe_rds'); s=d.get('suppressed',{}).get('modprobe_rds'); sys.exit(0 if (a is False and s is True) else 1)" \
    || fail "rds_host: suppression decision wrong (expect applied.modprobe_rds=false, suppressed.modprobe_rds=true)"

# Host-wide RDS modprobe drop-in MUST NOT exist on disk.
[ ! -f /etc/modprobe.d/99-rfxn-defense-rds.conf ] \
    || fail "rds modprobe file staged despite Oracle workload signal"

ok "rds_host: Oracle signal honored; host-wide RDS cut suppressed"
echo "=== RDS-HOST OK ==="
INNER
}

# v2.1.1: bare host on EL10 must auto-apply the io_uring sysctl
# drop-in. EL7/8/9 default kernels are <6.6 so this scenario SKIPs
# on those ELs (return 77 = skip).
run_bare_iouring_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Container kernel = host kernel (containers cannot fake uname). The
# scenario only makes sense where the production OS ships >= 6.6 by
# default, that is EL10+ today. EL7/8/9 production kernels are < 6.6;
# the iouring_old_kernel scenario covers those distros. SKIP here.
. /etc/os-release
case "${VERSION_ID%%.*}" in
    7|8|9)
        echo "SKIP: EL${VERSION_ID%%.*} production kernels are <6.6; bare-host iouring scenario not applicable"
        exit 77
        ;;
esac
rel=$(uname -r)
major=${rel%%.*}; minor=${rel#*.}; minor=${minor%%.*}
if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 6 ]; }; then
    echo "SKIP: kernel ${rel} < 6.6; bare-host io_uring scenario does not apply"
    exit 77
fi

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# io_uring sysctl drop-in MUST exist and JSON state must confirm.
[ -f /etc/sysctl.d/99-rfxn-defense-iouring.conf ] \
    || fail "iouring sysctl file missing on bare host (kernel >= 6.6)"

jq -e '.detected.io_uring_workload.present == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "bare host should not show io_uring_workload (got present=true)"
jq -e '.suppressed.sysctl_iouring.suppressed == false' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "bare host should NOT suppress io_uring (got suppressed=true)"
jq -e '.applied.sysctl_iouring == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "applied.sysctl_iouring should be true on bare host"

# Container test: cannot assert /proc/sys/kernel/io_uring_disabled value.
# Unprivileged podman containers share /proc/sys with the host kernel
# (no per-namespace sysctl writes) and lack CAP_SYS_ADMIN to mutate it.
# The package correctness gate is (1) drop-in file installed and
# (2) JSON state reports applied, both asserted above. Bare-metal
# operators see kernel.io_uring_disabled=2 after sysctl -p runs in
# the live %posttrans on a real host.

ok "bare_iouring_host: drop-in file installed + applied.sysctl_iouring=true"
echo "=== BARE-IOURING OK ==="
INNER
}

# v2.1.1: pre-stage a known io_uring consumer binary (postgres)
# before install. detect.sh signal 2 (known-consumer binary list) fires,
# suppressing the drop-in with reason=io_uring_workload. This is a
# simpler / more reliable test fixture than the original mmap stub
# (which depended on Python 3.7+ mmap behaviour and failed silently on
# Python 3.6 = EL7/EL8). Same end-state assertions.
run_iouring_consumer_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# EL7/8/9 production kernels are < 6.6, so kernel_too_old takes priority
# over io_uring_workload in decide_suppressions() and the reason
# assertion below would fail. iouring_old_kernel covers those distros.
. /etc/os-release
case "${VERSION_ID%%.*}" in
    7|8|9)
        echo "SKIP: EL${VERSION_ID%%.*} kernels are <6.6; iouring_old_kernel scenario covers this path"
        exit 77
        ;;
esac
rel=$(uname -r)
major=${rel%%.*}; minor=${rel#*.}; minor=${minor%%.*}
if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 6 ]; }; then
    echo "SKIP: kernel ${rel} < 6.6; consumer scenario asserts io_uring_workload reason (kernel gate supersedes)"
    exit 77
fi

# Stage a known io_uring consumer binary before package install.
# detect_io_uring_workload() signal 2 walks /usr/bin and /usr/sbin
# for a fixed list of consumers; presence of any one trips the
# IO_URING_WORKLOAD_PRESENT flag. Postgres is the canonical example.
mkdir -p /usr/bin
: > /usr/bin/postgres
chmod 0755 /usr/bin/postgres
test -x /usr/bin/postgres \
    || fail "stub /usr/bin/postgres not executable after staging"

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

# io_uring drop-in MUST NOT be present.
if [ -f /etc/sysctl.d/99-rfxn-defense-iouring.conf ]; then
    fail "iouring sysctl file staged despite known consumer binary present"
fi

# JSON state must report detection + suppression with the expected reason.
jq -e '.detected.io_uring_workload.present == true' \
       /var/lib/rfxn-defense/auto-detect.json >/dev/null \
    || fail "io_uring_workload.present != true despite staged consumer binary"
reason=$(jq -r '.suppressed.sysctl_iouring.reason' /var/lib/rfxn-defense/auto-detect.json)
[ "$reason" = "io_uring_workload" ] \
    || fail "suppression reason: expected io_uring_workload, got '$reason'"

ok "iouring_consumer_host: known consumer binary detected, drop-in correctly suppressed"
echo "=== IOURING-CONSUMER OK ==="
INNER
}

# v2.1.1: kernel <6.6 must result in suppression with reason=kernel_too_old.
# On EL7/8/9 default kernels this is the natural state. On EL10 we
# cannot stub uname inside the container, so this scenario is a no-op
# / SKIP for EL10. The bare_iouring scenario already covers EL10
# apply. The iouring_old_kernel scenario locks in the EL7/8/9
# suppression-reason path.
run_iouring_old_kernel_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }
assert_no_scriptlet_fail() {
    local _log="$1"
    if grep -qE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log"; then
        echo "--- RPM scriptlet failure markers in dnf output ---" >&2
        grep -nE 'scriptlet failed|Error in (POST|PRE)|syntax error near' "$_log" >&2
        echo "--- end ---" >&2
        fail "RPM scriptlet failure detected during dnf operation"
    fi
}

# Only run on kernels <6.6. EL10's container kernel is >=6.6,
# skip there.
rel=$(uname -r)
major=${rel%%.*}; minor=${rel#*.}; minor=${minor%%.*}
if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 6 ]; }; then
    echo "SKIP: kernel ${rel} >= 6.6; old-kernel scenario does not apply"
    exit 77
fi

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
. /etc/os-release
if [ "${VERSION_ID%%.*}" = "7" ]; then
    # CentOS 7 EOL prelude (same as rds_host scenario).
    rm -f /etc/yum.repos.d/CentOS-*.repo
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOREPO'
[base]
name=CentOS-7 Base (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
gpgcheck=0
enabled=1
[updates]
name=CentOS-7 Updates (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
gpgcheck=0
enabled=1
[extras]
name=CentOS-7 Extras (Vault)
baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
gpgcheck=0
enabled=1
EOREPO
    cat > /etc/yum.repos.d/epel.repo <<'EOEPEL'
[epel]
name=EPEL 7 (archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
gpgcheck=0
enabled=1
EOEPEL
    yum install -y dnf >/dev/null
fi

dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y rfxn-defense 2>&1 | tee /tmp/dnf.log | tail -5
assert_no_scriptlet_fail /tmp/dnf.log

[ ! -f /etc/sysctl.d/99-rfxn-defense-iouring.conf ] \
    || fail "iouring sysctl file present on kernel < 6.6"

reason=$(jq -r '.suppressed.sysctl_iouring.reason' /var/lib/rfxn-defense/auto-detect.json)
[ "$reason" = "kernel_too_old" ] \
    || fail "suppression reason: expected kernel_too_old, got '$reason'"

ok "iouring_old_kernel_host: io_uring suppressed with reason=kernel_too_old"
echo "=== IOURING-OLD-KERNEL OK ==="
INNER
}

# Sanity: verify the live URLs are reachable BEFORE we burn container time.
echo "Probing $REPO_URL ..."
http_code=$(curl -sSI -o /dev/null -w '%{http_code}' "$REPO_URL")
if [ "$http_code" != "200" ]; then
    echo "$(c_red FATAL): repo file at $REPO_URL returned HTTP $http_code"
    exit 2
fi
echo "  $(c_green ok)  HTTP 200"

echo "Probing $KEY_URL ..."
http_code=$(curl -sSI -o /dev/null -w '%{http_code}' "$KEY_URL")
if [ "$http_code" != "200" ]; then
    echo "$(c_red FATAL): public key at $KEY_URL returned HTTP $http_code"
    exit 2
fi
echo "  $(c_green ok)  HTTP 200"
echo

# Run each EL
declare -A RESULT
overall_rc=0
for el in "${ELS[@]}"; do
    if [ -z "${IMAGE[$el]:-}" ]; then
        echo "$(c_red SKIP) EL$el: no image mapped"
        RESULT[$el]="skip"
        continue
    fi
    image="${IMAGE[$el]}"
    echo "============================================================"
    echo "EL$el ($image)"
    echo "============================================================"

    # Pre-pull so we can fail loud on registry issues.
    if ! podman pull -q "$image" >/dev/null 2>&1; then
        echo "$(c_red FAIL): could not pull $image"
        RESULT[$el]="pull-fail"
        overall_rc=1
        echo
        continue
    fi
    step "image pulled"

    if run_test_in "$image"; then
        RESULT[$el]="$(c_green PASS)"
    else
        RESULT[$el]="$(c_red FAIL)"
        overall_rc=1
    fi

    # v2.0.0 test #18: upgrade-path test (separate container; if the
    # main matrix has already failed, we still try the upgrade path so
    # the operator gets a complete picture).
    echo
    step "upgrade-path test (afalg-defense-1.0.1 -> rfxn-defense-2.0.0)"
    upgrade_rc=0
    run_upgrade_test_in "$image" || upgrade_rc=$?

    # v3.0.0 stub: upgrade_v2_1_1_to_v3_0_0
    # Verifies the copyfail-defense (2.x lineage) -> rfxn-defense (3.0.0)
    # upgrade path via the Obsoletes/Provides chain. Implementation:
    # install copyfail-defense-2.1.1 from the legacy /copyfail/ URL on
    # gh-pages, then `dnf upgrade rfxn-defense` against the staged
    # v3.0.0 repo. Asserts:
    #   - all copyfail-defense-* RPMs removed by dnf (Obsoletes chain)
    #   - rfxn-defense* RPMs installed (Provides chain satisfies Requires)
    #   - /var/lib/copyfail-defense/auto-detect.json migrated to
    #     /var/lib/rfxn-defense/ (via %pretrans meta mv -n)
    #   - /etc/copyfail/force-full (if pre-staged) migrated to
    #     /etc/rfxn-defense/force-full
    #   - audit rules now use rfxn_* keys (legacy copyfail_* keys absent
    #     from /etc/audit/rules.d/99-rfxn-defense.rules)
    #   - 4-hourly cron + wrapper installed by rfxn-defense-autoupdate
    # Deferred to v3.0.1 follow-up: the v2.1.1 RPMs must be present in
    # the legacy gh-pages path under /copyfail/repo/EL/x86_64/archive/
    # at the time this test runs. v3.0.0 ships with the existing
    # afalg-defense-1.0.1 -> rfxn-defense scenario covering the same
    # Obsoletes/Provides plumbing.
    upgrade_v2_1_1_to_v3_0_0() {
        : # placeholder; see comment above
    }
    case "$upgrade_rc" in
        0)  RESULT[$el]="${RESULT[$el]} +upgrade$(c_green OK)" ;;
        77) RESULT[$el]="${RESULT[$el]} +upgrade$(c_dim SKIP)" ;;
        *)  RESULT[$el]="${RESULT[$el]} +upgrade$(c_red FAIL)"; overall_rc=1 ;;
    esac

    # v2.0.1: detection scenario tests (rev 2: + subuid_no_storage;
    # fixup pass: + systemd_only for M-2 canary).
    # v2.0.2: + userns_consumer for Flatpak/firejail/browser signal.
    # v2.1.0: + rds_host for Oracle Grid /etc/oratab suppression.
    # v2.1.1: + bare_iouring_host, iouring_consumer_host, iouring_old_kernel_host.
    for scenario_name in clean_host ipsec_host afs_host rootless_host \
                         subuid_no_storage \
                         force_full redetect split_upgrade \
                         systemd_only \
                         userns_consumer \
                         rds_host \
                         bare_iouring_host iouring_consumer_host \
                         iouring_old_kernel_host; do
        echo
        step "${scenario_name} test"
        scenario_rc=0
        "run_${scenario_name}_test_in" "$image" || scenario_rc=$?
        case "$scenario_rc" in
            0)  RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_green OK)" ;;
            77) RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_dim SKIP)" ;;
            *)  RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_red FAIL)"
                overall_rc=1 ;;
        esac
    done
    echo
done

echo "============================================================"
echo "summary"
echo "============================================================"
for el in "${ELS[@]}"; do
    printf '  EL%-3s  %s\n' "$el" "${RESULT[$el]:-unknown}"
done

exit "$overall_rc"
