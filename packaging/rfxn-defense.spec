%global         _hardened_build         1
%global         debug_package           %{nil}
# annobin is metadata-only (records build flags into ELF notes); not a
# hardening primitive. Disabling avoids EL9 chroot plugin-path drift
# where redhat-rpm-config expects /usr/lib/gcc/.../plugin/annobin.so but
# gcc-plugin-annobin ships /usr/lib/gcc/.../plugin/gcc-annobin.so.
%undefine       _annotated_build

# We deliberately do NOT byte-compile or strip the python script - it is
# distributed as plain text so an operator can read it before running.
%global         __os_install_post       %{nil}

# Upstream project tarball is named rfxn-defense-VERSION.tar.gz - that is
# the project name in README/source as of v3.0.0. Prior tarball names:
# afalg-VERSION.tar.gz (1.0.x), copyfail-VERSION.tar.gz (2.0.x-2.1.x).
# The RPM family rename chain is afalg-defense -> copyfail-defense (2.0.0)
# -> rfxn-defense (3.0.0) for kernel-LPE umbrella coverage spanning
# cf1 (CVE-2026-31431), cf2/DF-ESP, DF-RxRPC, Fragnesia, PinTheft,
# ssh-keysign-pwn, DirtyDecrypt.
%global         upstream_name           rfxn-defense

Name:           rfxn-defense
Epoch:          1
Version:        3.0.2
Release:        1%{?dist}
Summary:        Defense-in-depth toolkit for the Copy Fail bug class

License:        GPLv2
URL:            https://www.rfxn.com/
Source0:        %{upstream_name}-%{version}.tar.gz
# Auxiliary files maintained alongside the spec rather than in the upstream
# tarball - declaring them as Source1..N is what gets them into the SRPM
# (only declared Source* entries make it past `rpmbuild -bs`).
Source1:        rfxn-shim-enable
Source2:        rfxn-shim-disable
Source3:        rfxn-modprobe-cf1.conf
Source4:        rfxn-systemd-dropin.conf
Source5:        rfxn-systemd-dropin-containers.conf
Source6:        rfxn-modprobe-cf2-xfrm.conf
Source7:        rfxn-modprobe-rxrpc.conf
Source8:        rfxn-systemd-dropin-userns.conf
Source9:        rfxn-defense-detect.sh
Source10:       rfxn-redetect
Source11:       rfxn-systemd-dropin-rxrpc-af.conf
Source12:       rfxn-sysctl-userns.conf
Source13:       rfxn-defense-audit.rules
Source14:       rfxn-modprobe-rds.conf
Source15:       rfxn-systemd-dropin-rds.conf
Source16:       rfxn-sysctl-iouring.conf
# v3.0.0: 4-hourly responsive auto-update cron + wrapper. The wrapper
# delivers the "responsive defense layer" pitch by ensuring new
# mitigations land on hosts within 4 hours of the release tag.
Source17:       rfxn-defense-autoupdate.cron
Source18:       rfxn-defense-update.sh
# v3.0.1: ptrace_scope split into its own drop-in (was bundled inside
# rfxn-sysctl-userns.conf in v3.0.0; suppressed for rootless workloads
# even though keysign-pwn coverage is orthogonal to userns concerns).
Source19:       rfxn-sysctl-ptrace.conf

# x86_64 only: no-afalg.c has an explicit #error for non-x86_64. The auditor
# is portable, but the shim is a load-bearing primitive of this package
# family and we do not ship a half-package.
ExclusiveArch:  x86_64

BuildRequires:  gcc
BuildRequires:  glibc-devel
# EL8+ redhat-rpm-config injects -specs=.../redhat-annobin-cc1 into CFLAGS;
# the plugin lives in gcc-plugin-annobin and is not always pulled transitively
# by gcc (observed: EL9 chroot lacks plugin/annobin.so unless requested).
%if 0%{?rhel} >= 8
BuildRequires:  gcc-plugin-annobin
%endif
# The auditor is plain Python 3 stdlib at runtime, but %build runs a
# py_compile syntax check against it as a build-time gate (catches mismerged
# patches before they reach a server). EL8/EL10 minimal buildroots do not
# include python3 by default - hence BuildRequires.
BuildRequires:  python3

# Meta package ties the six subpackages together. Most operators install
# `rfxn-defense` and get the full set (with -audit as a soft dep so
# minimal hosts without auditd installed don't pull it in by default).
Requires:       %{name}-shim       = %{epoch}:%{version}-%{release}
Requires:       %{name}-modprobe   = %{epoch}:%{version}-%{release}
Requires:       %{name}-systemd    = %{epoch}:%{version}-%{release}
Requires:       %{name}-auditor    = %{epoch}:%{version}-%{release}
Requires:       %{name}-sysctl     = %{epoch}:%{version}-%{release}
# v3.0.0: 4-hourly auto-update cron is hard-Required by the meta. The
# delivery cadence is core to the responsive-defense-layer pitch; an
# operator who wants to opt out without removing the package touches
# /etc/rfxn-defense/auto-update.disabled (handled by the wrapper). Hard
# Requires also avoids minimal-host install_weak_deps=false silently
# dropping the delivery mechanism.
Requires:       %{name}-autoupdate = %{epoch}:%{version}-%{release}
# Soft dep: -audit pulls auditd transitively; minimal hosts can skip it
# via `--setopt=install_weak_deps=false` or `dnf install <subpackages>`
# selectively. `Recommends:` is rpm-4.13+; EL7's rpm-4.11 errors on it,
# so EL7 gets a hard Requires (no weak-dep mechanism available there).
%if 0%{?rhel} == 7
Requires:       %{name}-audit      = %{epoch}:%{version}-%{release}
%else
Recommends:     %{name}-audit      = %{epoch}:%{version}-%{release}
%endif

# Double rename chain: afalg-defense (1.0.x) -> copyfail-defense (2.0.x-2.1.x)
# -> rfxn-defense (3.0.0). Both predecessors are obsoleted so dnf upgrade
# handles either lineage cleanly. Compat names retained through the 3.0.x
# release line; dropped in 3.1.0.
Obsoletes:      copyfail-defense < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense = %{epoch}:%{version}-%{release}
Obsoletes:      afalg-defense    < %{epoch}:%{version}-%{release}
Provides:       afalg-defense    = %{epoch}:%{version}-%{release}

%description
Defense-in-depth toolkit covering the Copy Fail bug class:
  - cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
  - cf2 (CVE-2026-43284) - xfrm-ESP skip_cow path / Dirty Frag-ESP
  - Dirty Frag-RxRPC (CVE-2026-43500) - rxrpc pcbc(fcrypt) on splice'd frag
  - Fragnesia (no CVE yet, same surface as CVE-2026-43284) - ESP-in-TCP

This metapackage installs six subpackages:
  - rfxn-defense-shim      - LD_PRELOAD AF_ALG block
  - rfxn-defense-modprobe  - kernel-module entry-point cuts
  - rfxn-defense-systemd   - per-unit RestrictAddressFamilies/Namespaces
  - rfxn-defense-auditor   - read-only host posture auditor
  - rfxn-defense-sysctl    - host-wide unprivileged userns sysctl (v2.0.2)
  - rfxn-defense-audit     - auditd tripwire rules (v2.0.2; soft-dep)

The shim is INSTALLED but NOT enabled by this package. To enable it
system-wide:

    /usr/sbin/rfxn-shim-enable

To disable:

    /usr/sbin/rfxn-shim-disable

v2.0.1 introduced auto-detection of IPsec / AFS / rootless-container
workloads at install time, suppressing the conflicting drop-ins.
v2.0.2 extends auto-detection to userns consumers (Flatpak, firejail,
desktop browsers) for the new host-wide sysctl drop-in. The detection
report at /var/lib/rfxn-defense/auto-detect.json shows what ran
and what was suppressed; /usr/sbin/rfxn-redetect re-runs detection
on demand. Override the auto-detection by creating
/etc/rfxn-defense/force-full before install.

v2.1.0 adds PinTheft (RDS) and ssh-keysign-pwn (CVE-2026-46333) coverage:
rds*/AF_RDS cuts (modprobe + systemd + auditd) plus
kernel.yama.ptrace_scope=2 sysctl and a pidfd_getfd auditd tripwire.

# ---------------------------------------------------------------------------
%package shim
Summary:        LD_PRELOAD shim that blocks AF_ALG socket creation
Obsoletes:      copyfail-defense-shim < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-shim = %{epoch}:%{version}-%{release}
Obsoletes:      afalg-defense-shim < %{epoch}:%{version}-%{release}
Provides:       afalg-defense-shim = %{epoch}:%{version}-%{release}

%description shim
no-afalg.so: small libdl-based interposer that wraps libc socket(2) and
socketpair(2), denying AF_ALG (domain=38) with EPERM and logging the
attempt to LOG_AUTHPRIV. Intended for /etc/ld.so.preload.

The shim DOES NOT prevent direct-syscall bypass (syscall(SYS_socket,
AF_ALG, ...) or inline asm). Pair with the systemd subpackage's
RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RXRPC drop-ins for
kernel-enforced coverage, and with the kernel patch for full coverage.

THIS SUBPACKAGE INSTALLS no-afalg.so BUT DOES NOT WIRE IT INTO
/etc/ld.so.preload. To activate:

    /usr/sbin/rfxn-shim-enable

The activation helper smoke-tests the .so against /bin/true before
modifying /etc/ld.so.preload, refusing to brick the system if the .so
is broken.

# ---------------------------------------------------------------------------
%package modprobe
Summary:        Modprobe blacklist for cf-class kernel sinks
BuildArch:      noarch
Obsoletes:      copyfail-defense-modprobe < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-modprobe = %{epoch}:%{version}-%{release}
Requires(post): kmod
Requires(post): util-linux
Requires:       /usr/bin/python3
# Meta package owns detect.sh under /usr/libexec/rfxn-defense/
# (called from this subpackage's %posttrans), so -modprobe must pull
# meta even when the operator installs -modprobe alone. Hard Require
# (not Recommends) so --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description modprobe
Modprobe blacklist + install-redirect for kernel modules used by the
Copy Fail bug-class entry points:
  - cf1 (CVE-2026-31431):           algif_aead, authenc, authencesn, af_alg
  - cf2 / Dirty Frag-ESP (CVE-2026-43284):
                                    esp4, esp6, xfrm_user, xfrm_algo
  - Dirty Frag-RxRPC (CVE-2026-43500):
                                    rxrpc
  - Fragnesia (no CVE yet, same surface as CVE-2026-43284):
                                    covered by the esp4/esp6 blacklist

Drops /etc/modprobe.d/99-rfxn-defense-cf1.conf (always-on, config
noreplace, operator-override safe) plus conditional drop files for
cf2-xfrm and rxrpc managed by /usr/libexec/rfxn-defense/detect.sh.

NOTE: on RHEL-family kernels algif_aead is built-in
(CRYPTO_USER_API_AEAD=y), so the cf1 modprobe drop is a no-op there;
the LD_PRELOAD shim and systemd RestrictAddressFamilies=~AF_ALG are
the real cf1 cuts on those kernels. The supported escape is the
kernel command line: `grubby --update-kernel ALL --args
"initcall_blacklist=algif_aead_init"` followed by a reboot. The
auditor reports this state under MITIGATION.

WILL BREAK workloads that legitimately use IPsec (strongSwan, libreswan,
FRRouting), AFS (openafs, kafs), or kernel crypto via AF_ALG (some QEMU
configs, dm-crypt-via-AF_ALG userspace). Auto-detection suppresses the
conflicting drop file on detected hosts; confirm posture before
installing on hosts that run any of these.

v2.1.0 adds rds/rds_tcp/rds_rdma blacklist for PinTheft mitigation
(suppressed on Oracle Grid / HPC hosts via detect.sh).

# ---------------------------------------------------------------------------
%package systemd
Summary:        systemd drop-ins blocking cf-class primitives on tenant units
BuildArch:      noarch
Obsoletes:      copyfail-defense-systemd < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-systemd = %{epoch}:%{version}-%{release}
Requires:       systemd
Requires(post): systemd
Requires:       /usr/bin/python3
# Meta package owns detect.sh under /usr/libexec/rfxn-defense/
# (called from this subpackage's %posttrans), so -systemd must pull
# meta even when the operator installs -systemd alone (the case the
# v2.0.1 hotfix's M-2 review caught). Hard Require so
# --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description systemd
systemd unit drop-ins applying RestrictAddressFamilies=~AF_ALG ~AF_KEY
~AF_RXRPC, RestrictNamespaces=~user ~net, SystemCallFilter=~@swap, and
SystemCallArchitectures=native to: user@.service, sshd.service,
cron.service, crond.service, atd.service.

v2.0.2 adds ~AF_KEY to RestrictAddressFamilies: the legacy PF_KEYv2
socket is one of the two SA-config paths used by the Dirty Frag /
Fragnesia chain (the other, XFRM netlink, still requires
CAP_NET_ADMIN). Modern userland uses XFRM netlink; AF_KEY is legacy
with negligible compatibility risk on the five tenant units.

These cuts block the userspace prerequisites for cf2 / Dirty Frag-ESP
(unprivileged user namespace creation, AF_KEY SA install) and the
AF_RXRPC socket required by Dirty Frag-RxRPC, kernel-enforced at the
unit level (uncircumventable from userspace).

Container-runtime drop-ins (containerd, docker, podman) are shipped
as examples under /usr/share/doc/rfxn-defense/examples/ for
operators who do NOT run rootless or userns-remapped containers and
want to extend coverage. The default install does NOT activate
container-runtime drop-ins.

May break rootless podman/buildah running under user@.service.
Override: drop a 20-*.conf with empty directive values per unit;
see README.

v2.1.0 adds ~AF_RDS to the always-on 10-* drop-in (PinTheft coverage).

# ---------------------------------------------------------------------------
%package auditor
Summary:        kernel-LPE host posture auditor (cf-class, FD-theft, read-only)
BuildArch:      noarch
Requires:       python3
Obsoletes:      copyfail-defense-auditor < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-auditor = %{epoch}:%{version}-%{release}
Obsoletes:      afalg-defense-auditor < %{epoch}:%{version}-%{release}
Provides:       afalg-defense-auditor = %{epoch}:%{version}-%{release}
# The following are used opportunistically by the auditor and degrade
# gracefully when missing (every external command is wrapped in
# run_cmd which returns rc=-1 on FileNotFoundError). We list them as
# Recommends so a minimal install still gets the auditor working even
# when the recommendations cannot be satisfied (e.g. EL8 minimal).
%if 0%{?rhel} != 7
Recommends:     coreutils
Recommends:     systemd
Recommends:     audit
Recommends:     libcap
%endif

%description auditor
rfxn-local-check: comprehensive read-only auditor that scores the host
across five attack-chain layers (ENV, KERNEL, MITIGATION, HARDENING,
DETECTION) for the Copy Fail bug class:
  - cf1 (CVE-2026-31431) - algif_aead
  - cf2 (CVE-2026-43284) - xfrm-ESP skip_cow / Dirty Frag-ESP
  - Dirty Frag-RxRPC (CVE-2026-43500) - rxrpc pcbc(fcrypt) on splice'd frag
  - Fragnesia (no CVE yet) - ESP-in-TCP, same surface as CVE-2026-43284

SAFE BY DESIGN: writes only to mkdtemp() sentinel files, never modifies
/usr/bin or /etc, runs unprivileged (some checks degrade gracefully
without root). The optional trigger probe targets a freshly-created
sentinel file - it does not corrupt /usr/bin/su or anything else.

JSON output (--json) is fleet-rollout friendly; consume the
posture.verdict, posture.bug_classes_covered (array), and
posture.bug_classes (per-class map) fields, not the human report.

v2.1.0 adds 4 new checks (ptrace_scope, pidfd_getfd auditd rule, rds
modprobe, AF_RDS restrict) and 2 new bug-class entries (pintheft,
keysign-pwn).

# ---------------------------------------------------------------------------
%package sysctl
Summary:        Host-wide sysctl drop-in disabling unprivileged user namespaces
BuildArch:      noarch
Obsoletes:      copyfail-defense-sysctl < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-sysctl = %{epoch}:%{version}-%{release}
Requires:       procps-ng
# Meta package owns detect.sh under /usr/libexec/rfxn-defense/
# (called from this subpackage's %posttrans); hard Requires so
# --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description sysctl
Host-wide sysctl drop-ins under /etc/sysctl.d/:

  99-rfxn-defense-userns.conf (EL8+ only — see note below)
      - user.max_user_namespaces                     = 0
      - kernel.unprivileged_userns_clone             = 0
      - kernel.apparmor_restrict_unprivileged_userns = 1
    Keys carry the sysctl.d(5) `-` prefix so absent keys are
    silently skipped (none of the three are defined on every distro).

  99-rfxn-defense-ptrace.conf (all supported EL — v2.1.0+)
      kernel.yama.ptrace_scope = 2
    No `-` prefix: Yama LSM is present on every supported RHEL
    kernel, so a missing key is an unusual host-config we want
    visibility on (one-line sysctl error during boot, not a silent
    skip). v3.0.2 dropped the prefix so EL7 procps-ng 3.3.10
    (predates the prefix, added in 3.3.12) honours the key.

  99-rfxn-defense-iouring.conf (kernel >= 6.6, when applicable)
      kernel.io_uring_disabled = 2
    PinTheft mitigation; auto-applied on hosts with no io_uring
    workload signal.

The userns drop-in addresses the cf2 / Dirty Frag-ESP / Fragnesia
unshare(CLONE_NEWUSER|CLONE_NEWNET) prerequisite host-wide; the
ptrace_scope drop-in addresses the ssh-keysign-pwn (CVE-2026-46333)
agent-reach via pidfd_getfd; the iouring drop-in addresses the
PinTheft secondary primitive.

EL7 NOTE: the userns drop-in is not shipped on EL7. None of its
three keys exist on EL7 kernel 3.10 (max_user_namespaces was added
in 4.9; the other two are non-RHEL kernel patches), AND EL7
procps-ng 3.3.10 mis-parses the `-` prefix - on every prior 3.0.x
EL7 install the file produced zero effect. RHEL7 kernel-compile
defaults already disable unprivileged userns; rfxn-defense has no
work to add at the sysctl layer on EL7.

WILL BREAK workloads that legitimately need unprivileged userns:
rootless containers (rootless podman/buildah), Flatpak runtimes,
firejail sandboxes, and desktop browser renderer sandboxes
(Chromium/Chrome/Firefox). Auto-detection suppresses the userns
drop-in when these are present; see
/var/lib/rfxn-defense/auto-detect.json for the decision trace.

# ---------------------------------------------------------------------------
%package audit
Summary:        auditd tripwire rules for cf-class userspace prep
BuildArch:      noarch
Obsoletes:      copyfail-defense-audit < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-audit = %{epoch}:%{version}-%{release}
Requires:       audit

%description audit
auditd tripwire rules dropped to /etc/audit/rules.d/99-rfxn-defense.rules
catching the userspace prep steps of the Copy Fail bug class:
  - socket(AF_ALG,  ...) - cf1 (CVE-2026-31431)        - tag rfxn_afalg
  - socket(AF_KEY,  ...) - cf2 / DF-ESP / Fragnesia    - tag rfxn_afkey
  - socket(AF_RXRPC,...) - Dirty Frag-RxRPC (CVE-2026-43500)
                                                       - tag rfxn_afrxrpc

Filters auid>=1000 + auid!=-1 to skip unattended system services;
unprivileged-user exploitation is the precise case these rules catch.

Real value is on hosts where the modprobe blacklist is suppressed
(IPsec / AFS workloads) and the kernel sink is intentionally
reachable - the rules become the residual tripwire.

Query examples:
    ausearch -k rfxn_afalg     --start today
    ausearch -k rfxn_afkey     --start today
    ausearch -k rfxn_afrxrpc   --start today

x86_64 native ABI only (b64); i386-compat socket() rides socketcall()
on b32 and is intentionally out of scope.

v2.1.0 adds rfxn_afrds (PinTheft - AF_RDS=21) and
rfxn_pidfd_getfd (ssh-keysign-pwn / CVE-2026-46333 - syscall 438)
tripwire rules. v3.0.0 renames these audit keys to rfxn_afrds and
rfxn_pidfd_getfd (and the cf-class ones to rfxn_afalg / rfxn_afkey /
rfxn_afrxrpc). SIEM operators upgrading from 2.x must update ausearch
queries; see CHANGELOG for the full key-rename mapping.

# ---------------------------------------------------------------------------
%package autoupdate
Summary:        4-hourly responsive auto-update cron for rfxn-defense
BuildArch:      noarch
Obsoletes:      copyfail-defense-autoupdate < %{epoch}:%{version}-%{release}
Provides:       copyfail-defense-autoupdate = %{epoch}:%{version}-%{release}
# cronie ships /usr/sbin/crond on EL7+. Recommends (not hard Requires)
# because minimal hosts using systemd timers or external schedulers can
# install rfxn-defense-autoupdate to ship the wrapper script and supply
# their own schedule. The cron.d drop-in is harmless if cronie is absent;
# nothing runs it. Recommends works on rpm-4.13+; EL7 (rpm-4.11) falls
# back to a hard Requires.
%if 0%{?rhel} == 7
Requires:       cronie
%else
Recommends:     cronie
%endif
# coreutils ships /usr/bin/timeout; util-linux ships /usr/bin/flock. Both
# present in any base install but listed for completeness.
Requires:       coreutils
Requires:       util-linux

%description autoupdate
Ships /etc/cron.d/rfxn-defense-update and /usr/libexec/rfxn-defense/update.sh.
Every 4 hours (00:15, 04:15, 08:15, 12:15, 16:15, 20:15 host-local) the
wrapper runs a flock-protected, timeout-capped, targeted dnf upgrade of
all rfxn-defense* subpackages from the rfxn-defense repo only. A 0-600s
random jitter spreads mirror load across the fleet. All output is piped
to journald via `logger -t rfxn-defense-update`; tail with
`journalctl -t rfxn-defense-update -n 50`.

This is the delivery mechanism that operationalizes the responsive-defense
-layer pitch: new mitigations land on hosts within 4 hours of a release
tag. Opt out without removing the package by touching
/etc/rfxn-defense/auto-update.disabled. The wrapper exits before invoking
dnf when the touch-file is present, leaving cron itself unmodified.

# ===========================================================================
%prep
%setup -q -n %{upstream_name}-%{version}

# Sanity-check that the source files we expect actually exist. Fail the
# build loud and early if the tarball is malformed rather than packaging
# a half-empty RPM.
test -f no-afalg.c
test -f rfxn-local-check.py
test -f README.md
test -f LICENSE

%build
# Single-translation-unit build, deterministic flags. We deliberately do
# not pull in distro-default LDFLAGS that include --as-needed late in the
# arg list - placement here matches upstream README and is known-good
# across el7/el8/el9/el10.
# SONAME deliberately omitted: an LD_PRELOAD shim is not linked against,
# only dlopen'd by ld.so via /etc/ld.so.preload. Adding -Wl,-soname for
# a non-lib*.so.N filename trips rpmlint's invalid-soname check.
%{__cc} -shared -fPIC -O2 -Wall -Wextra \
    %{?_hardening_cflags} %{optflags} \
    -o no-afalg.so no-afalg.c -ldl

# We disable the debug-info subpackage (debug_package=nil) so an explicit
# strip is needed - RPM's automatic strip is part of the same machinery.
# Without strip, rpmlint flags the .so as unstripped-binary-or-object and
# we ship 30k+ of unnecessary symbol info to every server.
strip --strip-unneeded no-afalg.so

# Smoke-test: confirm the shim we just built (and stripped) actually loads
# and does not break /bin/true under LD_PRELOAD on the build host. This
# catches an entire class of broken builds (missing -fPIC, undefined
# dlsym, over-aggressive strip, etc.) before the file ever reaches a
# server.
LD_PRELOAD=$PWD/no-afalg.so /bin/true

# Confirm the auditor is parseable Python 3 on the build host.
python3 -c "import py_compile; py_compile.compile('rfxn-local-check.py', doraise=True)"

%install
rm -rf %{buildroot}

# --- shim subpackage layout ---
install -d -m 0755 %{buildroot}%{_libdir}
install -m 0755 no-afalg.so %{buildroot}%{_libdir}/no-afalg.so

install -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE1} %{buildroot}%{_sbindir}/rfxn-shim-enable
install -m 0755 %{SOURCE2} %{buildroot}%{_sbindir}/rfxn-shim-disable

# --- auditor subpackage layout ---
install -m 0755 rfxn-local-check.py \
    %{buildroot}%{_sbindir}/rfxn-local-check
sed -i '1s|^#!/usr/bin/env python3|#!/usr/bin/python3|' \
    %{buildroot}%{_sbindir}/rfxn-local-check

# --- modprobe subpackage layout ---
# cf1 always-on; cf2-xfrm + rxrpc as templates under /usr/share/.
install -d -m 0755 %{buildroot}/etc/modprobe.d
install -m 0644 %{SOURCE3} \
    %{buildroot}/etc/modprobe.d/99-rfxn-defense-cf1.conf

install -d -m 0755 %{buildroot}/usr/share/rfxn-defense/conditional/modprobe
install -m 0644 %{SOURCE6} \
    %{buildroot}/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-cf2-xfrm.conf
install -m 0644 %{SOURCE7} \
    %{buildroot}/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rxrpc.conf
install -m 0644 %{SOURCE14} \
    %{buildroot}/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rds.conf

# --- systemd subpackage layout ---
# 10-* always-on body installed for all 5 tenant units.
for u in user@ sshd cron crond atd; do
    install -d -m 0755 \
        %{buildroot}/etc/systemd/system/${u}.service.d
    install -m 0644 %{SOURCE4} \
        %{buildroot}/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf
done

# Conditional drop-in templates (rev 2): 12-rxrpc-af + 15-userns.
install -d -m 0755 %{buildroot}/usr/share/rfxn-defense/conditional/systemd
install -m 0644 %{SOURCE11} \
    %{buildroot}/usr/share/rfxn-defense/conditional/systemd/12-rfxn-defense-rxrpc-af.conf
# v3.0.2: 15-userns drop-in carries RestrictNamespaces= which was introduced
# in systemd v235. EL7 ships systemd v219 (rejects it as Unknown lvalue at
# unit-start). Shipping the file on EL7 was a silent-failure mitigation
# layer - install fine, drop-in present, directive ignored, zero effect.
# Gate so the template is absent on EL7; detect.sh apply_systemd then sees
# a missing source and removes any stale file left by a prior 3.0.x install.
%if 0%{?rhel} != 7
install -m 0644 %{SOURCE8} \
    %{buildroot}/usr/share/rfxn-defense/conditional/systemd/15-rfxn-defense-userns.conf
%endif
install -m 0644 %{SOURCE15} \
    %{buildroot}/usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf

# Container-runtime drop-ins ship as opt-in examples (NOT active).
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 %{SOURCE5} \
    %{buildroot}%{_docdir}/%{name}/examples/containers-dropin.conf

# --- sysctl subpackage layout (v2.0.2) ---
# Ships as a template under /usr/share/...; detect.sh copies to
# /etc/sysctl.d/ in %posttrans iff no userns-consumer is detected
# (rootless containers, Flatpak, firejail, desktop browser).
install -d -m 0755 %{buildroot}/usr/share/rfxn-defense/conditional/sysctl
# v3.0.2: userns sysctl ships three keys, none of which exist on the EL7
# kernel (max_user_namespaces is 4.9+; unprivileged_userns_clone is the
# Ubuntu/Debian patch; apparmor_restrict_unprivileged_userns is the AA
# patch). v3.0.1 used the `-key = val` prefix to silently skip absent
# keys per sysctl.d(5), but EL7 procps-ng 3.3.10 predates that prefix
# (added in 3.3.12) and tries to stat `/proc/sys/-key/...` instead -
# every key in the file errors and the file produces zero effect.
# Userns is also blocked by EL7 kernel compile-time defaults on RHEL,
# so this file has no work to do on EL7. Gate it out; detect.sh sees
# a missing source and removes any stale file from prior installs.
%if 0%{?rhel} != 7
install -m 0644 %{SOURCE12} \
    %{buildroot}/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-userns.conf
%endif
install -m 0644 %{SOURCE16} \
    %{buildroot}/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-iouring.conf
# v3.0.1: ptrace drop-in is in the "conditional/" tree only for layout
# uniformity. detect.sh applies it unconditionally (no suppression
# criteria); the file ships as a template so it can still be inspected
# under /usr/share/ alongside the others.
install -m 0644 %{SOURCE19} \
    %{buildroot}/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-ptrace.conf

# --- audit subpackage layout (v2.0.2) ---
# Rules drop directly into /etc/audit/rules.d/. Mode 0640 matches the
# convention shipped by the audit package itself (root-only readability).
install -d -m 0755 %{buildroot}/etc/audit/rules.d
install -m 0640 %{SOURCE13} \
    %{buildroot}/etc/audit/rules.d/99-rfxn-defense.rules

# --- detection helper + meta layout ---
install -d -m 0755 %{buildroot}/usr/libexec/rfxn-defense
install -m 0755 %{SOURCE9} \
    %{buildroot}/usr/libexec/rfxn-defense/detect.sh

install -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE10} \
    %{buildroot}%{_sbindir}/rfxn-redetect

# State directory (auto-detect.json gets written here at first %posttrans).
install -d -m 0755 %{buildroot}/var/lib/rfxn-defense

# Sentinel directory (operator drops force-full or auto-update.disabled
# files here). Pre-install: /etc/rfxn-defense/force-full triggers
# unconditional install of all conditional drop-ins; post-install:
# /etc/rfxn-defense/auto-update.disabled opts the host out of the
# 4-hourly autoupdate cron without removing the subpackage.
install -d -m 0755 %{buildroot}/etc/rfxn-defense

# --- autoupdate subpackage layout (v3.0.0) ---
# Cron.d drop-in fires the wrapper at 15 minutes past every 4th hour.
# The wrapper lives under /usr/libexec/ (operator-invisible by default;
# cron + journald handle execution + logging).
install -d -m 0755 %{buildroot}/etc/cron.d
install -m 0644 %{SOURCE17} \
    %{buildroot}/etc/cron.d/rfxn-defense-update
install -m 0755 %{SOURCE18} \
    %{buildroot}/usr/libexec/rfxn-defense/update.sh

# ===========================================================================
# Scriptlets - safety-first.
#
# We do NOT modify /etc/ld.so.preload from %post. A bad shim on every
# dynamic-linked binary would lock the operator out before they could
# log in to fix it. The activation helper exists for explicit operator
# action.
#
# We DO scrub /etc/ld.so.preload from %preun on full uninstall ($1=0),
# because the alternative is removing the .so file out from under a
# live preload entry, which is the same brick condition.
# ===========================================================================

# %pretrans (meta) - v3.0.0 path migration from copyfail-defense layout.
#
# Hosts upgrading from 2.x have:
#   /var/lib/copyfail-defense/auto-detect.json
#   /var/lib/copyfail-defense/installed-version
#   /etc/copyfail/force-full         (operator sentinel; %config(noreplace))
#
# v3.0.0 packages own /var/lib/rfxn-defense/ and /etc/rfxn-defense/. If we
# do nothing, the old paths are orphaned (still own data, but no longer
# referenced by detect.sh or the wrapper). Move-if-target-empty preserves
# operator state across the rename.
#
# `mv -n` (no-clobber) skips the move if the target already exists, which
# matters for re-runs (e.g., an aborted upgrade transaction retrying):
# the second %pretrans is a no-op rather than corrupting fresh state.
#
# Runs in BOTH install and upgrade contexts ($1 in {1,2}). On fresh install
# the source paths don't exist, so the moves quietly succeed-with-nothing.
# On upgrade-from-2.x they migrate state. On upgrade-from-3.x they're
# no-ops (source paths already absent post-migration).
%pretrans -p /bin/bash
if [ -d /var/lib/copyfail-defense ] && [ ! -e /var/lib/rfxn-defense ]; then
    mv -n /var/lib/copyfail-defense /var/lib/rfxn-defense 2>/dev/null || true
fi
if [ -d /etc/copyfail ] && [ ! -e /etc/rfxn-defense ]; then
    mv -n /etc/copyfail /etc/rfxn-defense 2>/dev/null || true
fi
# If both old and new exist (e.g., partial migration from a prior aborted
# upgrade), keep the new path and leave the old one in place for operator
# inspection - do NOT overwrite. Log to journald so the operator notices.
if [ -d /var/lib/copyfail-defense ] && [ -d /var/lib/rfxn-defense ]; then
    logger -t rfxn-defense-pretrans \
        "WARN: both /var/lib/copyfail-defense and /var/lib/rfxn-defense exist; \
preserving rfxn-defense path; inspect copyfail-defense for residual data" \
        || true
fi
exit 0

%post shim
cat <<'EOF'

rfxn-defense-shim installed but NOT yet enabled.

To activate the AF_ALG block on this host:
    /usr/sbin/rfxn-shim-enable

To remove later:
    /usr/sbin/rfxn-shim-disable
    dnf remove rfxn-defense

Verify after enabling:
    python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
    # expect: PermissionError [Errno 1] Operation not permitted

EOF
exit 0

%preun shim
# Only run on full uninstall, not upgrade.  $1==0 means erase.
if [ "$1" -eq 0 ]; then
    if [ -f /etc/ld.so.preload ] && \
       grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
        # Remove our line atomically before rpm deletes the .so. If we
        # let rpm remove the .so first, every dynamic-linked invocation
        # of /bin/sh, sed, etc. tries to dlopen a missing file and
        # fails - including the very scripts running this teardown.
        tmp=$(mktemp /etc/ld.so.preload.XXXXXX 2>/dev/null) || tmp=""
        if [ -n "$tmp" ]; then
            grep -Fxv /usr/lib64/no-afalg.so /etc/ld.so.preload > "$tmp" || true
            if [ -s "$tmp" ]; then
                chmod 0644 "$tmp"
                mv -f "$tmp" /etc/ld.so.preload
            else
                rm -f "$tmp" /etc/ld.so.preload
            fi
        else
            # mktemp failed (RO /etc, partition full, etc). Fall back
            # to in-place sed scrub to avoid leaving the .so referenced
            # in /etc/ld.so.preload after rpm deletes it (would brick
            # every dyn-linked exec on the host).
            sed -i '\|^/usr/lib64/no-afalg\.so$|d' /etc/ld.so.preload \
                2>/dev/null || true
            # If file is now empty, remove it (preload-empty is fine,
            # preload-with-only-blank-lines logs a warning per exec).
            if [ -f /etc/ld.so.preload ] && \
               [ ! -s /etc/ld.so.preload ]; then
                rm -f /etc/ld.so.preload
            fi
        fi
    fi
fi
exit 0

%posttrans shim
if [ -f /etc/ld.so.preload ] && \
   grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
    if [ ! -f /usr/lib64/no-afalg.so ]; then
        cat <<'EOF' >&2
WARNING: /etc/ld.so.preload references /usr/lib64/no-afalg.so but the
file is missing. Every dynamic-linked process on this host will log a
preload error. Run: /usr/sbin/rfxn-shim-disable
EOF
    fi
fi
exit 0

# ---------------------------------------------------------------------------
# %pretrans modprobe - v2.0.0 -> v2.0.1 upgrade cleanup (D-37).
# Rename the v2.0.0 monolithic %config file to .rpmsave-v2.0.1 so:
#   1. RPM's default .rpmsave-then-skip-new behavior is bypassed
#      (new split files land cleanly on unpack).
#   2. Operator hand-edits to the v2.0.0 file are preserved on disk
#      for inspection/recovery (C-4: same-day v2.0.0 -> v2.0.1 ship
#      means hand-edits are plausible).
# Conditional on the v2.0.0 RPM having been installed.
%pretrans modprobe
old=/etc/modprobe.d/99-rfxn-defense.conf
if [ -f "$old" ] && \
   rpm -q rfxn-defense-modprobe --qf '%%{version}' 2>/dev/null \
       | grep -q '^2\.0\.0$'; then
    mv -f "$old" "${old}.rpmsave-v2.0.1"
    logger -t rfxn-defense -p authpriv.info \
        "pretrans: renamed v2.0.0 monolithic modprobe drop file to ${old}.rpmsave-v2.0.1" \
        2>/dev/null || true
fi
exit 0

# %pretrans systemd - same logic, five files.
%pretrans systemd
if rpm -q rfxn-defense-systemd --qf '%%{version}' 2>/dev/null \
       | grep -q '^2\.0\.0$'; then
    for u in user@ sshd cron crond atd; do
        f="/etc/systemd/system/${u}.service.d/10-rfxn-defense.conf"
        if [ -f "$f" ]; then
            mv -f "$f" "${f}.rpmsave-v2.0.1"
        fi
    done
    logger -t rfxn-defense -p authpriv.info \
        'pretrans: renamed v2.0.0 monolithic systemd drop-in files to .rpmsave-v2.0.1' \
        2>/dev/null || true
fi
exit 0

# ---------------------------------------------------------------------------
%post modprobe
# %post fires before %posttrans - we don't yet know whether to apply
# cf2-xfrm or rxrpc (detect.sh runs in %posttrans). So %post only
# rmmods cf1 modules unconditionally; %posttrans handles cf2/rxrpc
# rmmod conditionally based on whether the drop-in landed.
{
    for m in algif_aead authenc authencesn af_alg; do
        if /sbin/rmmod "$m" 2>/dev/null; then
            printf 'rmmod %s: unloaded\n' "$m"
        elif [ -d "/sys/module/$m" ]; then
            printf 'rmmod %s: still loaded (in-use or builtin)\n' "$m"
        fi
    done
} | logger -t rfxn-defense -p authpriv.info 2>/dev/null || true
exit 0

%postun modprobe -p /bin/bash
# On full erase, remove conditional /etc/ files via detect.sh
# teardown. RPM has already removed the always-on cf1 file by this
# point. detect.sh ships in the META package (/usr/libexec/rfxn-defense/)
# and is called from both -modprobe and -systemd %posttrans/%postun.
# Both subpackages have a hard Requires on meta, so detect.sh is
# normally available throughout this scriptlet. The fallback inline
# teardown remains for the corner case where dnf removes meta in the
# same transaction (rare but possible if meta itself is being erased).
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/rfxn-defense/detect.sh ]; then
        /usr/libexec/rfxn-defense/detect.sh teardown modprobe \
            2> >(tee /dev/stderr \
                | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        rm -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf
        rm -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf
    fi
fi
exit 0

%posttrans modprobe -p /bin/bash
# v2.0.1 rev 2: run detect.sh in modprobe scope only. Per D-56 the
# scope arg prevents this %posttrans from creating orphan
# /etc/systemd/system/<unit>.service.d/12-* or 15-* files when
# -systemd is not installed. detect.sh writes auto-detect.json
# regardless of scope. stderr tees to dnf output (D-55) so
# operator sees warnings during install.
/usr/libexec/rfxn-defense/detect.sh apply modprobe 2> >(tee /dev/stderr \
    | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
    || true

# cf2 / rxrpc rmmod (conditional - only modules the drop file applies).
{
    if [ -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf ]; then
        for m in esp4 esp6 xfrm_user xfrm_algo; do
            if /sbin/rmmod "$m" 2>/dev/null; then
                printf 'rmmod %s: unloaded\n' "$m"
            elif [ -d "/sys/module/$m" ]; then
                printf 'rmmod %s: still loaded (in-use or builtin)\n' "$m"
            fi
        done
    fi
    if [ -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf ]; then
        if /sbin/rmmod rxrpc 2>/dev/null; then
            printf 'rmmod rxrpc: unloaded\n'
        elif [ -d "/sys/module/rxrpc" ]; then
            printf 'rmmod rxrpc: still loaded (in-use or builtin)\n'
        fi
    fi
} | logger -t rfxn-defense -p authpriv.info 2>/dev/null || true

# Existing "still loaded" warning, scoped to whatever module set is
# actually applied on this host.
applied_mods="algif_aead authenc authencesn af_alg"
[ -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf ] && \
    applied_mods="$applied_mods esp4 esp6 xfrm_user xfrm_algo"
[ -f /etc/modprobe.d/99-rfxn-defense-rxrpc.conf ] && \
    applied_mods="$applied_mods rxrpc"
loaded=""
for m in $applied_mods; do
    grep -qE "^$m " /proc/modules 2>/dev/null && loaded="$loaded $m"
done
if [ -n "$loaded" ]; then
    cat <<EOF >&2
NOTICE: rfxn-defense-modprobe installed but the following listed
modules are still loaded in the running kernel:$loaded
They will be blocked on next load attempt; reboot to clear running state.
EOF
fi
exit 0

# ---------------------------------------------------------------------------
%post systemd
# Defer daemon-reload to %posttrans so we reload after detect.sh has
# applied/suppressed the 15-*.conf userns drop-ins. %post runs before
# %posttrans; reloading here would reload-without the conditional
# drop-ins on first install, then again with them in %posttrans -
# cosmetically wasteful and racy.
exit 0

%posttrans systemd -p /bin/bash
# v2.0.1 rev 2: scope=systemd per D-56. -modprobe %posttrans uses
# scope=modprobe and never touches /etc/systemd/system/...d/. This
# %posttrans only manages systemd drop-ins. Both write
# auto-detect.json (idempotent rewrite).
#
# v3.0.2: tmpfile-based stderr capture (was: `2> >(tee ... | logger)`
# process-substitution). The process-sub idiom raced with the
# scriptlet exit on rpm 4.11 (EL7) - if detect.sh wrote multiple
# stderr lines and the scriptlet returned before the tee subprocess
# flushed, only the last line surfaced in dnf scriptlet output.
# tmpfile capture is fully synchronous on bash 4.2 (no procsub wait
# support).
#
# yum-3 (EL7) caveat: yum-3's scriptlet-stderr display is unreliable
# - it sometimes shows zero lines even when the scriptlet writes to
# stderr (rpm 4.11 buffers small writes; yum filters successful
# scriptlets). The canonical audit trail for stale-removal warnings
# is `journalctl -t rfxn-defense-detect`. dnf-4 on EL8+ displays the
# tee output reliably.
DETECT_ERR=$(mktemp -t rfxn-detect-systemd.XXXXXX)
/usr/libexec/rfxn-defense/detect.sh apply systemd 2>"${DETECT_ERR}" || true
if [ -s "${DETECT_ERR}" ]; then
    cat "${DETECT_ERR}" >&2
    logger -t rfxn-defense -p authpriv.warning -f "${DETECT_ERR}" 2>/dev/null || true
fi
rm -f "${DETECT_ERR}"
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0

%postun systemd -p /bin/bash
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/rfxn-defense/detect.sh ]; then
        /usr/libexec/rfxn-defense/detect.sh teardown systemd \
            2> >(tee /dev/stderr \
                | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        # Fallback: detect.sh removed by -modprobe %postun before this
        # ran. Inline the teardown so /etc/... is clean regardless.
        for u in user@ sshd cron crond atd; do
            rm -f "/etc/systemd/system/${u}.service.d/12-rfxn-defense-rxrpc-af.conf"
            rm -f "/etc/systemd/system/${u}.service.d/15-rfxn-defense-userns.conf"
        done
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl try-reload-or-restart sshd.service 2>/dev/null || true
    fi
fi
exit 0

# ---------------------------------------------------------------------------
# sysctl subpackage scriptlets (v2.0.2)
%post sysctl
cat <<'EOF'

rfxn-defense-sysctl installed.

Detection-driven activation runs in %posttrans below; the host-wide
userns sysctl drop file lands at /etc/sysctl.d/99-rfxn-defense-userns.conf
only if no rootless containers, Flatpak runtimes, firejail, or
desktop browsers are present on this host.

Inspect the decision:
    sudo cat /var/lib/rfxn-defense/auto-detect.json

EOF
exit 0

%posttrans sysctl -p /bin/bash
# Detection-driven file placement first, then sysctl --system to load
# whatever landed.
#
# v3.0.2: tmpfile-based stderr capture (see %posttrans systemd note
# above for the EL7 rpm-4.11 race rationale + yum-3 display caveat).
# Requires -p /bin/bash for the mktemp/local-var idiom.
DETECT_ERR=$(mktemp -t rfxn-detect-sysctl.XXXXXX)
/usr/libexec/rfxn-defense/detect.sh apply sysctl 2>"${DETECT_ERR}" || true
if [ -s "${DETECT_ERR}" ]; then
    cat "${DETECT_ERR}" >&2
    logger -t rfxn-defense -p authpriv.warning -f "${DETECT_ERR}" 2>/dev/null || true
fi
rm -f "${DETECT_ERR}"

# v3.0.2: `sysctl --system` (not a targeted -p loop). The prior loop
# enumerated only userns + iouring, omitting ptrace - so on every
# distro the ptrace_scope file landed on disk but never applied at
# install time (CVE-2026-46333 mitigation latent until next reboot or
# operator-initiated `sysctl --system`). Matches %postun behavior at
# the bottom of this file; also picks up any future drop-ins without
# requiring a spec edit.
sysctl --system 2>&1 \
    | logger -t rfxn-defense -p authpriv.info 2>/dev/null \
    || true
exit 0

%postun sysctl -p /bin/bash
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/rfxn-defense/detect.sh ]; then
        /usr/libexec/rfxn-defense/detect.sh teardown sysctl \
            2> >(tee /dev/stderr \
                | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        rm -f /etc/sysctl.d/99-rfxn-defense-userns.conf \
              /etc/sysctl.d/99-rfxn-defense-iouring.conf
    fi
    # Reload from the remaining sysctl.d set. user.max_user_namespaces
    # stays at whatever value the kernel's last sysctl --system pass left
    # it at; if no other drop-in sets it, the running-kernel value
    # persists until reboot. Document this in the README "Remove" section.
    sysctl --system 2>&1 \
        | logger -t rfxn-defense -p authpriv.info 2>/dev/null \
        || true
fi
exit 0

# ---------------------------------------------------------------------------
# audit subpackage scriptlets (v2.0.2)
%posttrans audit -p /bin/bash
# augenrules compiles /etc/audit/rules.d/*.rules to /etc/audit/audit.rules
# and applies via auditctl. Idempotent; safe on install + upgrade.
# On hosts without auditd running, augenrules will compile the rules
# file but auditctl --load will fail - that's acceptable. Errors tee
# to dnf scriptlet output per D-55.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2> >(tee /dev/stderr \
        | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
        | logger -t rfxn-defense -p authpriv.info 2>/dev/null \
        || true
fi
exit 0

%postun audit -p /bin/bash
# On full erase, RPM has already removed /etc/audit/rules.d/99-rfxn-defense.rules
# by the time this scriptlet fires - reload augenrules so the running
# auditd no longer carries our keys.
if [ "$1" -eq 0 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2> >(tee /dev/stderr \
            | logger -t rfxn-defense -p authpriv.info 2>/dev/null) \
            | logger -t rfxn-defense -p authpriv.info 2>/dev/null \
            || true
    fi
fi
exit 0

%postun
# Meta package %postun: remove auto-detect.json when all three
# detection-managed subpackages (-modprobe, -systemd, -sysctl) are
# gone. -audit is unconditional and does not consume the detect.sh
# state file. rpm -q returncodes (D-45 / M-9) determine subpackage
# presence, not file existence.
if [ "$1" -eq 0 ]; then
    if ! rpm -q rfxn-defense-modprobe >/dev/null 2>&1 && \
       ! rpm -q rfxn-defense-systemd  >/dev/null 2>&1 && \
       ! rpm -q rfxn-defense-sysctl   >/dev/null 2>&1; then
        rm -f /var/lib/rfxn-defense/auto-detect.json
    fi
fi
exit 0

# ===========================================================================
%files
%license LICENSE
%doc README.md
%dir /etc/rfxn-defense
%{_sbindir}/rfxn-redetect
# Detection helper (called from -modprobe + -systemd %posttrans/%postun
# and from rfxn-redetect). Owned here in meta so a single copy
# exists regardless of which subpackages are installed; both -modprobe
# and -systemd hard-Require meta to guarantee this binary is present
# before their scriptlets fire.
%dir /usr/libexec/rfxn-defense
/usr/libexec/rfxn-defense/detect.sh
# State directory (auto-detect.json lives here). Owned by meta so
# it exists from first install regardless of which subpackages are
# present; -modprobe and -systemd no longer need to %dir-claim it.
%dir /var/lib/rfxn-defense

%files shim
%license LICENSE
%doc README.md
%{_libdir}/no-afalg.so
%{_sbindir}/rfxn-shim-enable
%{_sbindir}/rfxn-shim-disable

%files modprobe
%license LICENSE
%doc README.md
# Always-on cf1 cut - operator-editable, RPM-tracked.
%config(noreplace) /etc/modprobe.d/99-rfxn-defense-cf1.conf
# Conditional cut templates - copied to /etc/ by %posttrans
# detect.sh per /var/lib/rfxn-defense/auto-detect.json.
%dir /usr/share/rfxn-defense
%dir /usr/share/rfxn-defense/conditional
%dir /usr/share/rfxn-defense/conditional/modprobe
/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-cf2-xfrm.conf
/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rxrpc.conf
/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rds.conf
# detect.sh + /usr/libexec/rfxn-defense + /var/lib/rfxn-defense
# moved to meta package %files in v2.0.1 fixup pass (M-2): they were
# only listed here, so installing -systemd without -modprobe missed
# detect.sh and the %posttrans silently no-op'd.

%files systemd
%license LICENSE
%doc README.md
%dir /etc/systemd/system/user@.service.d
%dir /etc/systemd/system/sshd.service.d
%dir /etc/systemd/system/cron.service.d
%dir /etc/systemd/system/crond.service.d
%dir /etc/systemd/system/atd.service.d
# Always-on (10-) drop-ins: RestrictAddressFamilies=~AF_ALG +
# SystemCallArchitectures + SystemCallFilter (rev 2: ~AF_RXRPC moved
# to conditional 12-* drop-in).
%config(noreplace) /etc/systemd/system/user@.service.d/10-rfxn-defense.conf
%config(noreplace) /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf
%config(noreplace) /etc/systemd/system/cron.service.d/10-rfxn-defense.conf
%config(noreplace) /etc/systemd/system/crond.service.d/10-rfxn-defense.conf
%config(noreplace) /etc/systemd/system/atd.service.d/10-rfxn-defense.conf
# Conditional drop-in templates (rev 2):
#   12-* RestrictAddressFamilies=~AF_RXRPC: copied to /etc/...d/12-*.conf
#        by %posttrans detect.sh; suppressed on AFS hosts.
#   15-* RestrictNamespaces=~user ~net: copied to /etc/...d/15-*.conf;
#        suppressed for user@.service.d when rootless containers detected.
%dir /usr/share/rfxn-defense/conditional/systemd
/usr/share/rfxn-defense/conditional/systemd/12-rfxn-defense-rxrpc-af.conf
/usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf
# v3.0.2: gated on EL7 (systemd 219 silently ignores RestrictNamespaces=)
%if 0%{?rhel} != 7
/usr/share/rfxn-defense/conditional/systemd/15-rfxn-defense-userns.conf
%endif
# %dir /var/lib/rfxn-defense moved to meta %files (v2.0.1 fixup M-2).
# Existing example doc unchanged.
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/containers-dropin.conf

%files auditor
%license LICENSE
%doc README.md
%{_sbindir}/rfxn-local-check

%files sysctl
%license LICENSE
%doc README.md
# Conditional sysctl drop-in template - copied to /etc/sysctl.d/ by
# %posttrans detect.sh per /var/lib/rfxn-defense/auto-detect.json
# (suppressed when rootless containers, Flatpak, firejail, or a
# desktop browser is detected on the host).
%dir /usr/share/rfxn-defense/conditional/sysctl
# v3.0.2: userns sysctl gated on EL7 (none of the 3 keys exist on kernel
# 3.10; '-' prefix unsupported by procps-ng 3.3.10)
%if 0%{?rhel} != 7
/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-userns.conf
%endif
/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-iouring.conf
/usr/share/rfxn-defense/conditional/sysctl/99-rfxn-defense-ptrace.conf

%files audit
%license LICENSE
%doc README.md
# auditd rules drop directly to /etc/audit/rules.d/. Marked
# %config(noreplace) so an operator hand-edit survives upgrade
# (the rule set is small and well-defined; if you have a tuned
# set, you want yours preserved). /etc/audit/rules.d/ itself is
# owned by the audit package (hard Require); we do NOT %dir-claim
# it to avoid co-ownership warnings.
%config(noreplace) %attr(0640, root, root) /etc/audit/rules.d/99-rfxn-defense.rules

%files autoupdate
%license LICENSE
%doc README.md
# Cron.d entry is %config(noreplace) so an operator hand-edit (e.g.,
# changing the cadence from 4-hourly to hourly, or to a longer
# interval) survives package upgrade.
%config(noreplace) %attr(0644, root, root) /etc/cron.d/rfxn-defense-update
# Wrapper script ships under /usr/libexec/ (operator-invisible by
# default). Standard mode 0755. /usr/libexec/rfxn-defense/ itself is
# %dir-owned by the meta package (created by the modprobe/systemd
# install paths above); we do NOT %dir-claim it here to avoid
# co-ownership warnings.
%attr(0755, root, root) /usr/libexec/rfxn-defense/update.sh

# ===========================================================================
%changelog
* Sun May 24 2026 Ryan MacDonald <ryan@rfxn.com> - 1:3.0.2-1
- EL7 silent-failure release. Empirically validated against a fresh
  CentOS 7.9.2009 VM (systemd 219, procps-ng 3.3.10, kernel 3.10).
  Closes three EL7-only silent-mitigation gaps that shipped in every
  prior 3.0.x build and were masked by the auditor's own SKIP path:
  * CRITICAL: systemd v219 (EL7) does not recognise the
    RestrictNamespaces= directive (introduced in systemd v235, Oct
    2017). The 15-rfxn-defense-userns.conf drop-in installed on
    sshd/cron/crond/atd/user@.service.d/ was parsed at unit-start as
    "Unknown lvalue", the directive silently dropped, every drop-in
    inert. cf2 / dirtyfrag-ESP unshare prerequisite reachable inside
    every tenant unit on every EL7 host running 3.0.x. Gated the
    Source8 install with `%if 0%{?rhel} != 7`; detect.sh's
    apply_systemd now also removes any stale drop-in on EL7 upgrades.
  * CRITICAL: 99-rfxn-defense-ptrace.conf and -userns.conf used the
    `-key = value` sysctl.d(5) prefix to silently skip absent keys.
    The prefix was added in procps-ng 3.3.12 (Feb 2017); EL7 ships
    3.3.10, which interprets `-kernel.yama.ptrace_scope` literally
    as a path under /proc/sys/-kernel/yama/... and fails the stat.
    Every key in both files no-op'd on EL7. ssh-keysign-pwn primary
    mitigation (CVE-2026-46333) silently absent on every EL7 host.
    Dropped the `-` prefix from ptrace.conf (Yama is in every
    supported RHEL kernel; one-line boot error on a no-Yama kernel is
    visibility we want). Gated userns.conf install with
    `%if 0%{?rhel} != 7` (none of its three keys exist on EL7 kernel
    3.10 anyway; userns is gated at kernel-compile time on RHEL7).
  * Auditor (rfxn-local-check): check_systemd_restrict_namespaces
    returned `SKIP "no tenant units found in this systemd instance"`
    on EL7 because `systemctl show -p RestrictNamespaces <unit>`
    emits no property line on systemd v219 - the whole tenant-unit
    loop hit the rc!=0 continue and findings_missing stayed empty.
    Added a systemd_version() probe; when version < 235, glob
    /etc/systemd/system/*.service.d/15-rfxn-defense-userns.conf and
    emit FAIL when stale drop-ins are present (with rm remediation),
    SKIP with explicit "v235 directive" reason otherwise.
  * Auditor: check_unprivileged_userns_sysctl returned OK
    "unprivileged userns disabled" when kernel/distro defaults set
    max_user_namespaces=0, masking the fact that the rfxn-defense
    sysctl drop-in is not on disk. Operator believed rfxn-defense
    was enforcing it; runtime operator override would re-enable
    userns without rfxn-defense pulling it back. Distinguish
    "blocked by rfxn drop-in" from "blocked by kernel default" in
    the OK message; details.rfxn_sysctl_dropin_present reports
    on-disk truth.
  * Auditor: check_ptrace_scope remediation message referenced
    99-rfxn-defense-userns.conf (stale from v3.0.0 before the v3.0.1
    ptrace-split). Now references 99-rfxn-defense-ptrace.conf and
    cites the v3.0.2 `-` prefix removal so EL7 operators understand
    why ptrace_scope was =0 despite the file being present.
  * NEW: packaging/test-el7-live.sh - permanent live-host EL7 test
    runner. Bootstraps vault.centos.org repos (EL7 EOL mirrorlist is
    dead), installs the local RPM set, runs 27 assertions across
    packaging sanity / auditor JSON / empirical mitigation probes
    (AF_ALG socket creation with shim, ptrace_scope runtime value,
    systemd-analyze verify on all drop-ins) / upgrade path from
    copyfail-defense 2.1.1. Replaces ad-hoc /tmp test scripts.
  Tool version bumps: detect.sh 3.0.1 -> 3.0.2; rfxn-local-check
  __version__ 3.0.1 -> 3.0.2.

* Sun May 24 2026 Ryan MacDonald <ryan@rfxn.com> - 1:3.0.1-1
- Fixup release validated against two live EL10 hosts (cPanel tenant
  fleet + admin host). Closes several mitigation-effectiveness gaps
  that lay dormant since v2.0.2 onwards:
  * CRITICAL: systemd drop-in deny-list syntax was ~A ~B ~C, which
    systemd parses as "~" prefix + tokens "A" and "~B" - the second
    token is invalid, so systemd LOGS A WARNING AND DROPS THE WHOLE
    DIRECTIVE. RestrictNamespaces=~user ~net became RestrictNamespaces=no
    (default: no restriction). RestrictAddressFamilies=~AF_ALG ~AF_KEY
    ~AF_RDS collapsed to just ~AF_ALG. Fixed: only the FIRST token
    carries ~ (per systemd.exec(5) semantics); the remaining tokens
    join the deny-list. Now: RestrictAddressFamilies=~AF_ALG AF_KEY
    AF_RDS and RestrictNamespaces=~user net. Files touched:
    rfxn-systemd-dropin.conf, rfxn-systemd-dropin-userns.conf,
    rfxn-systemd-dropin-containers.conf (the optional example).
    Empirical verification: a test unit running unshare --user --net
    failed under the FIXED drop-in (status=1) but succeeded under the
    BROKEN drop-in (status=0).
  * CRITICAL: kernel.yama.ptrace_scope=2 (ssh-keysign-pwn primary
    mitigation, CVE-2026-46333) was bundled inside
    rfxn-sysctl-userns.conf. When userns suppression fired (rootless
    containers / Flatpak / firejail / browser detected), the entire
    file was removed - taking ptrace_scope with it. keysign-pwn
    coverage was therefore missing on the bulk of modern Linux
    hosts. Split into a new always-applied drop-in
    /etc/sysctl.d/99-rfxn-defense-ptrace.conf (new file
    packaging/rfxn-sysctl-ptrace.conf, Source19). detect.sh gains
    apply_sysctl_ptrace() with no suppression criteria.
  * CRITICAL: detect_rootless_containers Signal 2 fired on the
    storage tree initialization (tmp/, overlay-containers/containers.lock,
    overlay-images/images.lock, libpod/, db.sql, ...) that
    containers-common / podman install creates without any actual
    container run. Both test hosts FP'd: zero podman containers
    ever ran, signal still fired, sysctl_userns suppressed (and
    pre-fix, ptrace_scope died with it via the bundled-file bug
    above). Tightened to require a non-lockfile entry inside
    overlay-containers/, overlay-images/, vfs-containers/, or
    vfs-images/ - those directories receive children only when real
    containers or images are created. Eliminates the false positive
    on RHEL hosts with podman/buildah pre-installed but unused.
  * Auditor (rfxn-local-check): audit_rule_af_alg regex was a0=38
    (decimal); auditctl -l prints a0=0x26 (hex), so all 5 loaded
    rfxn_* rules were misreported as MISSING. Switched to key-name
    match (key=rfxn_afalg / afkey / afrxrpc / afrds / pidfd_getfd);
    works regardless of auditctl's a0= rendering. Old "splice
    audit rule" check removed (was never shipped). Adds explicit
    OK reporting for the 4 non-AF_ALG rfxn_* keys.
  * Auditor: cf1 applicability now derives from algif_aead_state
    (kernel sink reachability) instead of af_alg_socket (userspace
    reachability). The shim returning EPERM is a mitigation, not a
    "sink not reachable" signal - the old logic mis-credited cf1 as
    n/a on every host where the shim worked. After fix, cf1 row in
    the matrix correctly shows "YES / yes / ld_preload_shim".
  * Auditor: systemd_restrict_namespaces no longer silently drops
    units whose RestrictNamespaces parses but does not block both
    user+net (cascade from the parse-fail bug above; surfaced
    "no tenant units found" on production hosts where 5 drop-ins
    were installed).
  * Auditor banner reframed from "Copy Fail bug-class Checker /
    cf1 / cf2 / Dirty Frag" to "rfxn-defense host posture auditor /
    cf1 / cf2 / DF-ESP / DF-RxRPC / Fragnesia / PinTheft /
    DirtyDecrypt / keysign-pwn" - covers all 7 shipped classes.
  * v3.0.1 auto-detect.json adds applied.sysctl_ptrace boolean
    (true iff -sysctl subpackage shipped the template); no
    schema_version bump (additive per the established protocol).
  Tool version bumps: detect.sh 3.0.0 -> 3.0.1; rfxn-local-check
  __version__ 3.0.0 -> 3.0.1. README and gh-pages landing matrix
  rows annotated with the suppression-decoupling notes.

* Sat May 23 2026 Ryan MacDonald <ryan@rfxn.com> - 1:3.0.0-1
- Project rename: copyfail-defense -> rfxn-defense. The package family
  is now positioned as a responsive defense layer that ships mitigations
  as 0days land, closing the delta between public CVE disclosure and the
  kernel/software vendor patch set landing on hosts. Compat retained
  through the 3.0.x release line via the double Obsoletes/Provides chain
  (copyfail-defense + afalg-defense). dnf upgrade handles either lineage
  transparently; the .repo file is renamed from copyfail.repo to
  rfxn-defense.repo and the gpgkey field lists both keys.
- NEW subpackage rfxn-defense-autoupdate ships /etc/cron.d/rfxn-defense
  -update and /usr/libexec/rfxn-defense/update.sh. The wrapper runs
  every 4 hours (00:15, 04:15, 08:15, 12:15, 16:15, 20:15 host-local),
  jittered 0-600s, flock-protected, timeout-capped at 600s, targeted
  to rfxn-defense* from the rfxn-defense repo only. All output to
  journald (logger -t rfxn-defense-update). Opt out without removing
  the package by touching /etc/rfxn-defense/auto-update.disabled.
  Hard-Required by the meta package: delivery is core to the reframe.
- Audit-key rename: legacy copyfail_{afalg,afkey,afrxrpc,afrds,pidfd_getfd}
  -> rfxn_{afalg,afkey,afrxrpc,afrds,pidfd_getfd}. SIEM operators with
  ausearch -k queries on the legacy keys MUST update on deployment of
  v3.0.0. The rule file path also moves from /etc/audit/rules.d/99-
  copyfail-defense.rules to /etc/audit/rules.d/99-rfxn-defense.rules;
  the existing %posttrans audit runs augenrules --load which replaces
  the kernel rule set atomically, so old keys are flushed and new keys
  loaded in one auditctl -R cycle without an auditd restart.
- Path migration: %pretrans (meta) moves /var/lib/copyfail-defense ->
  /var/lib/rfxn-defense and /etc/copyfail -> /etc/rfxn-defense via
  mv -n (no-clobber). Operator state (auto-detect.json, force-full,
  installed-version) preserved across the rename. Both-paths-present
  case (partial prior migration) logs WARN to journald and leaves the
  legacy path untouched for operator inspection.
- New GPG key file RPM-GPG-KEY-rfxn ships alongside the retained
  RPM-GPG-KEY-copyfail. Both files carry the same key bytes (RSA-4096,
  fingerprint 6001 1CDC EA2F F52D 975A FDEE 6D30 F32C D5E8 0F80); only
  the filename differs so legacy copyfail.repo clients keep verifying.
- Auditor renamed: /usr/sbin/copyfail-local-check -> /usr/sbin/rfxn
  -local-check. __version__ bumped 2.1.1 -> 3.0.0. All on-disk path
  literals migrated; bug-class detection logic unchanged.
- README, STATE.md, SPEC.md, BRIEF.md, FOLLOWUPS.md rewritten with the
  responsive-defense-layer reframe. gh-pages landing page rewritten.
  Legacy URL /copyfail/ returns HTTP 404 after repo rename (GitHub
  Pages does not redirect renamed-repo URLs); v2.x hosts with
  copyfail.repo in /etc/yum.repos.d/ require manual migration
  (recipe documented in FOLLOWUPS.md "Known issue").
- BRIEF.md DirtyDecrypt (CVE-2026-31635) cross-stamp confirms coverage
  by the existing rxrpc cuts (modprobe blacklist + RestrictAddressFamilies
  ~AF_RXRPC + rfxn_afrxrpc audit rule). No new primitive needed.
- Bug-class coverage unchanged from v2.1.1: cf1, cf2/DF-ESP, DF-RxRPC,
  Fragnesia, PinTheft (RDS + io_uring), ssh-keysign-pwn, DirtyDecrypt.
  Build matrix unchanged: EL7 / EL8 / EL9 / EL10, x86_64.

* Fri May 22 2026 Ryan MacDonald <ryan@rfxn.com> 2.1.1-1
- Promote kernel.io_uring_disabled to auto-applied with layered
  suppression. v2.1.0 shipped the key commented-out as opt-in;
  v2.1.1 ships it active in a new /etc/sysctl.d/99-rfxn-defense-
  iouring.conf drop-in, gated on detect.sh signals.
- detect.sh adds detect_io_uring_workload(): liburing.so in any
  /proc/*/maps, known-consumer binary list (postgres, scylla,
  mariadbd, dockerd, redis-server, nginx, envoy, rabbitmq), and
  io_uring-named systemd units. Kernel <6.6 gate suppresses with
  reason kernel_too_old. Operator env knobs
  CFD_FORCE_IOURING_DISABLE=1 / CFD_SUPPRESS_IOURING_DISABLE=1.
- Split sysctl drop-in into two files so io_uring can be suppressed
  independently of userns/ptrace_scope. The userns sysctl file
  keeps user.max_user_namespaces + kernel.yama.ptrace_scope; the
  new iouring file carries the io_uring key alone.
- JSON state: suppressed.sysctl_iouring is now a {suppressed,
  reason} dict (not bool) so the suppression reason surfaces
  for operator triage. detected.io_uring_workload added.
  applied.sysctl_iouring added.
- Auditor adds check_io_uring_disabled (MITIGATION); reports
  OK when applied, INFO/SKIP on correctly-suppressed hosts, FAIL
  on hosts where workload absent but key not applied.
- gh-pages publish: older RPMs (2.0.x, 2.1.0) moved to
  repo/N/x86_64/archive/ so dnf install resolves only v2.1.1
  via createrepo_c. Archive URLs remain reachable for backward-
  compatible curl links.
- test-repo.sh adds bare_iouring_host (clean EL10 -> applied),
  iouring_consumer_host (pre-staged liburing.so process -> suppressed),
  iouring_old_kernel_host (uname stub -> kernel_too_old).

* Fri May 22 2026 Ryan MacDonald <ryan@rfxn.com> 2.1.0-1
- Add PinTheft (RDS + io_uring) coverage: rds/rds_tcp/rds_rdma modprobe
  blacklist, ~AF_RDS in always-on systemd 10-* drop-in, rfxn_afrds
  auditd rule on AF_RDS=21 socket creation.
- Add ssh-keysign-pwn (CVE-2026-46333) coverage: kernel.yama.ptrace_scope=2
  sysctl key, rfxn_pidfd_getfd auditd rule on syscall 438 numeric.
- Add commented-out kernel.io_uring_disabled=2 secondary mitigation
  (operator opt-in; Linux 6.6+ only).
- Bug-class taxonomy gains pintheft (Copy Fail class) and keysign-pwn
  (FD-theft class - first member).
- detect.sh adds detect_rds_workload() with three signals (Oracle oratab,
  crsctl binary, rds.ko already loaded). Suppresses modprobe-rds on
  Oracle Grid / HPC hosts; JSON state schema_version stays "2" (backward
  compatible).
- Auditor adds check_ptrace_scope, check_pidfd_getfd_auditd_rule,
  check_rds_modprobe, check_af_rds_restrict. _aggregate_bug_classes()
  extended with pintheft + keysign-pwn entries.
- Build matrix expands to EL7/8/9/10. EL7 uses custom mock chroot with
  vault.centos.org URLs; falls back to native rpmbuild if vault unreachable.
- test-repo.sh adds IMAGE[7]=quay.io/centos/centos:7, defaults to (7 8 9 10),
  adds new assertions for AF_RDS in 10-* drop-in, ptrace_scope sysctl,
  both new audit-rule keys, rds-host suppression scenario.

* Wed May 13 2026 rfxn.com <proj@rfxn.com> - 1:2.0.2-1
- v2.0.2 broadens cf2 / Dirty Frag / Fragnesia coverage along three
  axes informed by the Fragnesia advisory and the Red Hat / AWS /
  Wiz / Sysdig mitigation guidance published the week of 2026-05-08.
- New subpackage rfxn-defense-sysctl: ships a host-wide sysctl
  drop-in at /etc/sysctl.d/99-rfxn-defense-userns.conf that
  disables unprivileged user-namespace creation
  (user.max_user_namespaces=0, kernel.unprivileged_userns_clone=0,
  kernel.apparmor_restrict_unprivileged_userns=1). Keys are
  '-'-prefixed so unknown keys on a given kernel are silently
  skipped (sysctl.d(5)). Closes the CLONE_NEWUSER prerequisite that
  the cf2 / DF-ESP / Fragnesia chain needs for
  CAP_NET_ADMIN-in-namespace and the subsequent xfrm SA install,
  on processes NOT covered by the per-tenant-unit systemd
  RestrictNamespaces drop-in (a shell-user running an exploit
  binary).
- detect.sh extends with detect_userns_consumers() that flags
  Flatpak (system+user installs), firejail, and desktop browsers
  (Chromium/Chrome/Firefox). The sysctl drop-in is suppressed when
  EITHER the existing rootless-container signal OR the new
  userns-consumer signal fires. Per-unit systemd RestrictNamespaces
  is unaffected - still applies to all five tenant units regardless
  of userns-consumer detection. New `apply sysctl` and `teardown
  sysctl` scopes (plus `all` covering modprobe+systemd+sysctl).
  TOOL_VERSION bumped 2.0.1 -> 2.0.2.
- New subpackage rfxn-defense-audit (Requires: audit, Recommends
  from meta so minimal hosts can skip the auditd pull-in): ships
  /etc/audit/rules.d/99-rfxn-defense.rules with three -k-tagged
  rules detecting socket(AF_ALG/AF_KEY/AF_RXRPC) syscalls from
  unprivileged users (auid>=1000 + auid!=-1). Real value is on hosts
  where modprobe blacklist is suppressed by auto-detection
  (IPsec / AFS workloads) and the kernel sink is intentionally
  reachable - the rules become the residual tripwire. Query via
  `ausearch -k rfxn_afalg` / `rfxn_afkey` /
  `rfxn_afrxrpc`. x86_64 native ABI only (b64); i386-compat
  socketcall is intentionally out of scope.
- systemd drop-in 10-rfxn-defense.conf adds ~AF_KEY to
  RestrictAddressFamilies, closing the legacy PF_KEYv2 SA-config
  path used by the Dirty Frag / Fragnesia chain (the other,
  XFRM netlink, still requires CAP_NET_ADMIN). Modern userland
  uses XFRM netlink; AF_KEY is legacy with negligible
  compatibility risk on the five tenant units. Same change
  applied to the containers-dropin.conf example.
- auto-detect.json schema: backward-compatible additions of
  detected.userns_consumers (present + signals array),
  suppressed.sysctl_userns, applied.sysctl_userns. schema_version
  stays at "2" - consumers ignore unknown keys.
- %description modprobe now documents the RHEL builtin case
  (CRYPTO_USER_API_AEAD=y makes the cf1 modprobe drop a no-op) and
  the supported workaround: `grubby --update-kernel ALL --args
  "initcall_blacklist=algif_aead_init"` followed by reboot. The
  cf1 modprobe drop-in itself is unchanged from v2.0.1; this is
  documentation only.
- CVE cross-stamping in subpackage %descriptions:
  cf2 / Dirty Frag-ESP = CVE-2026-43284,
  Dirty Frag-RxRPC = CVE-2026-43500,
  Fragnesia = no CVE yet (same surface as CVE-2026-43284, per Wiz
  and oss-sec disclosure). Previously only CVE-2026-31431 (cf1)
  was pinned inline.

* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.1-2
- 2.0.1-2 packaging hotfix (no functional change): declare
  `-p /bin/bash` on the four scriptlets that use bash process
  substitution (`2> >(tee /dev/stderr | logger ...)`):
  %posttrans modprobe, %posttrans systemd, %postun modprobe,
  %postun systemd. RPM scriptlets default to /bin/sh; on EL/Alma 8
  /bin/sh is bash invoked in POSIX mode, where process substitution
  is rejected as a syntax error. 2.0.1-1 added the proc-sub idiom
  per D-55 (surface detect.sh stderr to dnf output) without a
  matching `-p /bin/bash` on the scriptlet headers, causing
  %posttrans/%postun to abort with `syntax error near unexpected
  token \`>'\` on EL8 hosts. detect.sh never ran, so auto-detect.json
  was never written and conditional drop-ins (cf2-xfrm/rxrpc/userns)
  were never suppressed - the install appeared to succeed but the
  detection-driven hardening was inert. Reported by Jamie Sexton on
  AlmaLinux 8 stage hosts (2026-05-08).
- packaging/test-repo.sh adds a scriptlet-failure regression guard:
  every dnf install/upgrade/remove now greps the captured output
  for `scriptlet failed`, `Error in (POST|PRE)*`, and `syntax error`
  markers and fails loudly if any appear. Closes the gap that let
  2.0.1-1 ship without a final dnf-from-gh-pages canary catching
  this class of bug.
- spec: %pretrans modprobe and %pretrans systemd were querying
  `rpm -q ... --qf '%{version}'` with an unescaped %{version} - RPM
  expanded the macro at build time to the literal new-package
  version (e.g. '2.0.1'), so the rpm-q always returned that string
  regardless of what was installed, and the v2.0.0 -> v2.0.1
  monolithic-file rename guard never fired. Switched to '%%{version}'
  so RPM emits a literal %{version} into the scriptlet body and the
  rpm-q queries the *currently-installed* version. Bug present in
  2.0.1-1; only surfaced on this hotfix's gh-pages-staging canary.
- packaging/test-repo.sh fixes: (a) `mp_count=$(grep -ch ... 3 files)`
  produced a multi-line per-file count, breaking `[ -eq 9 ]` - swap
  to cat-then-grep for a single integer; (b) the systemd_only
  scenario asserted -modprobe was NOT pulled, but the meta package
  Requires all four subpackages (umbrella semantics for
  `dnf install rfxn-defense`), so -modprobe IS always pulled
  transitively - removed the inverted assertion and assert presence
  instead.

* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.1-1
- v2.0.1 hotfix: auto-detect IPsec / AFS / rootless-container
  workloads at install time and suppress the conflicting drop-ins.
  The README's "Override paths" section is now package-driven via
  /usr/libexec/rfxn-defense/detect.sh and reported in
  /var/lib/rfxn-defense/auto-detect.json. Operators can re-run
  detection on demand via /usr/sbin/rfxn-redetect, and force
  full-install (skip detection) by creating /etc/rfxn-defense/force-full
  before %posttrans.
- File-layout split: 99-rfxn-defense.conf becomes three files
  (-cf1 always-on, -cf2-xfrm suppressible-on-IPsec, -rxrpc
  suppressible-on-AFS). Per-tenant-unit systemd drop-ins split into
  10-rfxn-defense.conf (always-on RestrictAddressFamilies +
  SystemCallFilter) and 15-rfxn-defense-userns.conf (suppressible
  on user@.service.d when rootless containers are detected;
  unconditional on sshd/cron/crond/atd).
- %pretrans removes v2.0.0 monolithic %config files before v2.0.1
  unpacks (avoids RPM's default .rpmsave-then-skip-new behavior).
  Conditional on the v2.0.0 RPM having been the source of those
  files - operator-pre-staged files are preserved.
- Auditor reads auto-detect.json and surfaces the detection state
  under posture.auto_detect; new check_auto_detect_state() under
  MITIGATION reports OK / INFO / WARN per detection posture.
- test-repo.sh extends to 25 per-EL checks (was 18 in v2.0.0): clean
  host, IPsec host, AFS host, rootless host, force-full, redetect
  helper, v2.0.0->v2.0.1 split-file upgrade.

* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.0-1
- v2.0.0: rename afalg-defense -> rfxn-defense umbrella, expand to
  cover the full Copy Fail bug class:
    cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
    cf2 ("Electric Boogaloo") - xfrm-ESP skip_cow path
    Dirty Frag - xfrm-ESP and RxRPC pcbc(fcrypt) on splice'd frag
- New subpackage rfxn-defense-modprobe: ships
  /etc/modprobe.d/99-rfxn-defense.conf with the cf-class
  kernel-module entry-point cuts (algif_aead/authenc/authencesn/af_alg,
  esp4/esp6/xfrm_user/xfrm_algo, rxrpc). Best-effort rmmod on install.
- New subpackage rfxn-defense-systemd: ships drop-ins for
  user@/sshd/cron/crond/atd applying RestrictAddressFamilies=~AF_ALG
  ~AF_RXRPC, RestrictNamespaces=~user ~net, SystemCallFilter=~@swap,
  SystemCallArchitectures=native. Container-runtime drop-ins ship as
  opt-in examples under /usr/share/doc/rfxn-defense/examples/.
- rfxn-defense-shim: pure rename of afalg-defense-shim. No
  behavioural change. Obsoletes/Provides afalg-defense-shim.
- rfxn-defense-auditor: pure rename of afalg-defense-auditor with
  expanded checks for cf2/Dirty Frag (xfrm-ESP and RxRPC reachability,
  modprobe extended coverage, systemd RestrictNamespaces, PAM nullok
  scan, page-cache integrity for /usr/bin/su and PAM stacks). New JSON
  output: posture.bug_classes_covered (SIEM array) and
  posture.bug_classes (granular map). Exit codes unchanged.
- Epoch: 1 introduced. Compat metadata (Obsoletes/Provides
  afalg-defense*) retained through 2.0.x; dropped in 2.1.0.

* Thu Apr 30 2026 R-fx Networks <proj@rfxn.com> - 1.0.1-1
- Signed release. RPMs and repodata are GPG-signed with the
  Copyfail Project Signing Key (fingerprint 6001 1CDC EA2F F52D 975A
  FDEE 6D30 F32C D5E8 0F80). The published .repo file enforces
  gpgcheck=1 / repo_gpgcheck=1; the public key is published as
  /RPM-GPG-KEY-copyfail at the gh-pages root and as a release asset.
- Initial RPM packaging of the AF_ALG defensive primitives.
- Package family renamed from copyfail-* to afalg-defense-* to track the
  defensive primitive rather than a single CVE.
- Subpackages: afalg-defense-shim (LD_PRELOAD AF_ALG block) and
  afalg-defense-auditor (read-only host posture auditor).
- Shim is installed but not auto-enabled - operator runs
  rfxn-shim-enable to wire it into /etc/ld.so.preload, after a
  pre-flight LD_PRELOAD smoke-test against /bin/true.
- preun on full erase scrubs /etc/ld.so.preload before the .so is
  removed to avoid bricking dynamic-linked binaries during teardown.
