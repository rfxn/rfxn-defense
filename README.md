<div align="center">

# rfxn-defense

**Responsive defense layer for Linux.** Ships kernel-LPE mitigations as
0days land, closing the window between public CVE disclosure and the
vendor patch reaching your hosts (or a fleet reboot becoming available).

Signed yum/dnf repo for EL7 / EL8 / EL9 / EL10. 4-hourly auto-update
cron. Zero reboot required for any mitigation. New bug classes ship
with each release tag. Install once, stay covered.

Today's shipping coverage: 7 LPE classes across two families. Copy Fail
page-cache writes (cf1, cf2, Dirty Frag-ESP, DF-RxRPC, Fragnesia,
PinTheft, DirtyDecrypt) and FD-theft via SUID exit-race (ssh-keysign-pwn).
See the [coverage matrix](#coverage-matrix) for per-class detail.

<a href="https://rfxn.github.io/rfxn-defense/"><img src="https://img.shields.io/badge/%F0%9F%93%A6%20yum%2Fdnf%20repo-rfxn.github.io%2Frfxn--defense-22d3ee?style=for-the-badge&labelColor=09090b" alt="rfxn-defense yum/dnf package repo"></a>
<a href="https://www.rfxn.com/research/copyfail-cve-2026-31431"><img src="https://img.shields.io/badge/%F0%9F%94%AC%20deep%20dive-rfxn.com%2Fresearch-d97757?style=for-the-badge&labelColor=09090b" alt="Deep-dive research article on rfxn.com"></a>

[![Severity](https://img.shields.io/badge/severity-LOCAL%20PRIVESC-d44d4d?labelColor=09090b)](#coverage-matrix)
[![License](https://img.shields.io/badge/license-GPL--2.0-22d3ee?labelColor=09090b)](LICENSE)
[![EL7/8/9/10](https://img.shields.io/badge/EL-7%20%2F%208%20%2F%209%20%2F%2010-4ade80?labelColor=09090b)](https://rfxn.github.io/rfxn-defense/)
[![Latest release](https://img.shields.io/github/v/release/rfxn/rfxn-defense?label=release&color=22d3ee&labelColor=09090b)](https://github.com/rfxn/rfxn-defense/releases/latest)

[Install](#install) · [Verify](#verify) · [Coverage](#coverage-matrix) · [Defense in depth](#defense-in-depth) · [Audit](#audit-the-host) · [Subpackages](#subpackages) · [Overrides](#override-paths) · [Signatures](#verifying-signatures) · [Limitations](#limitations)

</div>

---

## Install

```sh
sudo curl -sSL https://rfxn.github.io/rfxn-defense/rfxn-defense.repo \
  -o /etc/yum.repos.d/rfxn-defense.repo
sudo dnf install -y rfxn-defense
sudo /usr/sbin/rfxn-shim-enable
```

One repo file works on EL7 / EL8 / EL9 / EL10. RPMs are GPG-signed; dnf
imports the public key on first use. Cross-check the fingerprint when
prompted:

```
6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
```

The 4-hourly auto-update cron keeps hosts current; new mitigations land
within 4 hours of a release tag with no operator action. Opt out by
touching `/etc/rfxn-defense/auto-update.disabled`.

The meta package pulls seven subpackages (`-audit` as a soft dep on
EL8/9/10, hard dep on EL7 since rpm-4.11 has no `Recommends:`):

| Subpackage | Coverage |
|---|---|
| `rfxn-defense-shim` | `LD_PRELOAD` `AF_ALG` block (cf1 primary) |
| `rfxn-defense-modprobe` | kernel-module entry-point cuts (cf1, cf2, Dirty Frag, PinTheft, DirtyDecrypt) |
| `rfxn-defense-systemd` | per-unit `RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RXRPC ~AF_RDS` + `RestrictNamespaces=~user ~net` |
| `rfxn-defense-sysctl` | host-wide `user.max_user_namespaces=0`, `kernel.yama.ptrace_scope=2`, `kernel.io_uring_disabled=2` (auto-suppressed where unsafe) |
| `rfxn-defense-auditor` | read-only host posture auditor (`rfxn-local-check`) with per-class coverage report |
| `rfxn-defense-audit` | auditd tripwires (`rfxn_afalg/afkey/afrxrpc/afrds/pidfd_getfd`) |
| `rfxn-defense-autoupdate` | 4-hourly responsive auto-update cron + flock wrapper |

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28 with split `libdl`; EL9/EL10: 2.34+
with merged `libdl`). **Do not cross-install across ELs.** Direct
download links + sha256s:
[rfxn.github.io/rfxn-defense](https://rfxn.github.io/rfxn-defense/#direct-downloads).

> [!IMPORTANT]
> **Upgrading from v2.x (`copyfail-defense`) or v1.x (`afalg-defense`):**
> `sudo dnf upgrade -y rfxn-defense`. The Obsoletes/Provides chain
> handles every prior layout; operator state under
> `/var/lib/copyfail-defense/` and `/etc/copyfail/` migrates to
> `/var/lib/rfxn-defense/` and `/etc/rfxn-defense/` via `%pretrans`
> `mv -n` (idempotent). SIEM queries must update the audit-key prefix
> (`copyfail_*` → `rfxn_*`).
>
> **Legacy URL hosts need manual migration.** GitHub Pages does not
> redirect renamed-repo URLs. v2.x hosts with `copyfail.repo` in
> `/etc/yum.repos.d/` will 404 on `dnf check-update` after v3.0.0:
>
> ```sh
> sudo curl -sSL https://rfxn.github.io/rfxn-defense/rfxn-defense.repo \
>     -o /etc/yum.repos.d/rfxn-defense.repo
> sudo rm -f /etc/yum.repos.d/copyfail.repo
> sudo dnf upgrade -y rfxn-defense
> ```

Auditor only (no `LD_PRELOAD`, for hot infrastructure):

```sh
sudo dnf install -y rfxn-defense-auditor
```

> [!NOTE]
> **EL7 note.** EL7 RPMs are built against `vault.centos.org`
> (CentOS 7 reached EOL 2024-06-30). If your host loses vault access,
> install via the GitHub release assets directly; the RPMs themselves
> carry no runtime vault dependency.

## Verify

```sh
# cf1: AF_ALG socket creation should fail
python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
# expect: PermissionError [Errno 1] Operation not permitted

# Holistic per-class coverage report
sudo rfxn-local-check
```

The auditor renders a surface-area matrix per bug-class showing whether
the kernel sink is reachable on this host AND which mitigation layers
are active.

## Audit the host

```sh
sudo rfxn-local-check                # human-readable, only flags non-OK
sudo rfxn-local-check --json         # SIEM ingestion (posture.bug_classes_covered)
sudo rfxn-local-check --emit-remediation   # bash script of suggested fixes
```

Read-only by design: writes only to `mkdtemp()` sentinels, never modifies
`/usr/bin` or `/etc`, runs unprivileged.

Exit codes (unchanged from v1.0.1): `0` clean · `2` **VULN** (no
userspace mitigation) · `3` VULN-but-mitigated · `4` hardening
recommendations only.

`--json` exposes `posture.bug_classes_covered` (single SIEM filter for
"is this host hardened?"), `posture.bug_classes` (per-class `applicable`
/ `mitigated` / `kernel_sink` / layer flags for dashboards), and the
v1.0.x `posture.verdict` headline for backwards compat.

## Remove

```sh
sudo /usr/sbin/rfxn-shim-disable
sudo dnf remove rfxn-defense
```

`%preun` scrubs `/etc/ld.so.preload` on full erase; the modprobe drop
file is removed. `%config(noreplace)` preserves operator hand-edits to
systemd drop-ins across upgrade.

---

## Coverage matrix

Which rung blocks which bug class. **✅** primary mitigation, applied
without caveat. **✅ ⁿ** active coverage with a kernel- or
workload-conditional caveat (see footnote). **ⁿ** alone is detection
only, no mitigation. **·** not applicable.

Rows are mitigation rungs the package installs. Operator-applied
hardening (suid lockdown, additional auditd rules) is in a separate
table below; no subpackage performs those actions because each can
break legitimate workloads on a busy fleet.

| Mitigation rung                                  | cf1 | cf2 | DF-ESP | DF-RxRPC ⁶ | Fragnesia | PinTheft | keysign-pwn |
|---                                               |:---:|:---:|:---:   |:---:       |:---:      |:---:     |:---:        |
| LD_PRELOAD shim (`AF_ALG` hook)                  | ✅  |  ·  |   ·    |   ✅ ¹      |    ·      |    ·     |     ·       |
| modprobe `algif_aead` family                     | ✅ ² |  ·  |   ·    |    ·       |    ·      |    ·     |     ·       |
| modprobe `esp4 esp6 xfrm_user xfrm_algo`         |  ·  | ✅  |  ✅    |    ·       |   ✅      |    ·     |     ·       |
| modprobe `rxrpc`                                 |  ·  |  ·  |   ·    |   ✅       |    ·      |    ·     |     ·       |
| modprobe `rds rds_tcp rds_rdma`                  |  ·  |  ·  |   ·    |    ·       |    ·      |   ✅ ⁵   |     ·       |
| systemd `RestrictAddressFamilies=~AF_ALG`        | ✅  |  ·  |   ·    |    ·       |    ·      |    ·     |     ·       |
| systemd `RestrictAddressFamilies=~AF_KEY`        |  ·  | ✅  |  ✅    |    ·       |   ✅      |    ·     |     ·       |
| systemd `RestrictAddressFamilies=~AF_RXRPC`      |  ·  |  ·  |   ·    |   ✅       |    ·      |    ·     |     ·       |
| systemd `RestrictAddressFamilies=~AF_RDS`        |  ·  |  ·  |   ·    |    ·       |    ·      |   ✅     |     ·       |
| systemd `RestrictNamespaces=~user ~net`          |  ·  | ✅  |  ✅    |    ·       |   ✅      |    ·     |     ·       |
| sysctl `user.max_user_namespaces=0`              |  ·  | ✅  |  ✅    |    ·       |   ✅      |    ·     |     ·       |
| sysctl `kernel.yama.ptrace_scope=2`              |  ·  |  ·  |   ·    |    ·       |    ·      |    ·     |    ✅       |
| sysctl `kernel.io_uring_disabled=2` ⁴            |  ·  |  ·  |   ·    |    ·       |    ·      |   ✅ ⁴   |     ·       |
| auditd tripwire rules                            | ³   | ³   |  ³     |   ³        |   ³       |   ³      |    ³        |

¹ Catches the `cksum` step in the public DF-RxRPC PoC, not the kernel
sink itself. Defense-in-depth, not a primary stop.
² No-op on RHEL stock kernels: `CRYPTO_USER_API*` is built-in, so the
blacklist line cannot prevent load. Supported workaround is
`grubby --update-kernel ALL --args "initcall_blacklist=algif_aead_init"`
+ reboot; the auditor reports this state under MITIGATION.
³ Detection only, not mitigation. Telemetry for
`socket(AF_ALG/AF_KEY/AF_RXRPC/AF_RDS)` and `pidfd_getfd` from
unprivileged users. Highest value on hosts where modprobe blacklists
are auto-suppressed (IPsec / AFS / RDS) and the kernel sink is
intentionally reachable. Query via `ausearch -k rfxn_afalg` /
`rfxn_afkey` / `rfxn_afrxrpc` / `rfxn_afrds` / `rfxn_pidfd_getfd`.
⁴ `kernel.io_uring_disabled=2` ships as a separate
`/etc/sysctl.d/99-rfxn-defense-iouring.conf` (Linux 6.6+ only).
Auto-suppressed on rootless-container, Flatpak/firejail/browser, and
io_uring-workload hosts (liburing.so in `/proc/*/maps`, known consumer
binaries, or io_uring-named systemd units), and on kernels older
than 6.6. Operator escape hatch: `CFD_SUPPRESS_IOURING_DISABLE=1`
(suppress) or `CFD_FORCE_IOURING_DISABLE=1` (force-apply). PinTheft's
primary cut is the RDS modprobe blacklist; io_uring is secondary.
⁵ Functional on Ubuntu/Debian/Arch kernels and ELRepo kernel-ml swaps
where `rds.ko` is loadable. No-op on stock RHEL/Alma/Rocky/Oracle UEK
kernels (no `CONFIG_RDS=m`). Auto-suppressed on Oracle Grid / HPC
hosts where RDS is in active use (`/etc/oratab`, `crsctl` binary, or
loaded `rds*.ko`).
⁶ DirtyDecrypt (CVE-2026-31635, `rxgk_*` RXGK token-decrypt in-place
crypto) is cross-stamped onto the DF-RxRPC column: every AF_RXRPC
mitigation that covers DF-RxRPC also covers DirtyDecrypt.

### Audit keys (`-audit` subpackage)

| Key                  | Signature                                                              |
|---                   |---                                                                     |
| `rfxn_afalg`         | `socket(AF_ALG=38)` by unprivileged user (cf1)                         |
| `rfxn_afkey`         | `socket(AF_KEY=15)` by unprivileged user (cf2 / DF-ESP / Fragnesia)    |
| `rfxn_afrxrpc`       | `socket(AF_RXRPC=33)` by unprivileged user (DF-RxRPC / DirtyDecrypt)   |
| `rfxn_afrds`         | `socket(AF_RDS=21)` by unprivileged user (PinTheft)                    |
| `rfxn_pidfd_getfd`   | `pidfd_getfd()` syscall 438 by unprivileged user (ssh-keysign-pwn)     |

### Operator-applied (auditor-recommended)

Surfaced via `--emit-remediation`. **No subpackage applies these**, since
each can break legitimate workloads on a busy fleet. Review every line
before pasting.

| Action                                                     | Targets       | When the auditor recommends it |
|---                                                         |---            |--- |
| `chmod 4750 /usr/bin/su && chgrp wheel /usr/bin/su`        | cf2, DF-ESP   | Suppressed when `/etc/passwd` shows non-wheel/admin interactive users (cPanel-style tenant fleets); chmod 4750 would break their `su` workflow. |
| `grubby --update-kernel ALL --args "initcall_blacklist=algif_aead_init"` + reboot | cf1 | RHEL kernels with `CRYPTO_USER_API_AEAD=y` (modprobe blacklist is a no-op on those); the supported escape per CIQ / Rocky Linux mitigation guidance. |
| `auditd` rule `cf_userns` (`unshare(CLONE_NEWUSER)`)       | cf2, DF-ESP   | Hosts where `auditd` is tuned for userns events (otherwise high alert noise). |
| `auditd` rule `cf_addkey` (`add_key("rxrpc",...)`)         | DF-RxRPC      | Always; `rxrpc` keyring activity is rare enough that the false-positive rate stays low. |

### CVE / disclosure references

| Bug class | CVE | Kernel sink |
|---|---|---|
| cf1 | [CVE-2026-31431](https://www.rfxn.com/research/copyfail-cve-2026-31431) | `algif_aead` AEAD scratch-write |
| cf2 / Dirty Frag-ESP | CVE-2026-43284 | `esp_input` `skip_cow` |
| Dirty Frag-RxRPC | CVE-2026-43500 | `rxkad_verify_packet_1` |
| Fragnesia | (no CVE yet; same surface as CVE-2026-43284) | `espintcp` ULP after splice |
| PinTheft | CVE pending | RDS zerocopy double-free + io_uring fixed-buffer |
| DirtyDecrypt | CVE-2026-31635 | `rxgk_*` RXGK token-decrypt in-place crypto |
| ssh-keysign-pwn | [CVE-2026-46333](https://nvd.nist.gov/vuln/detail/CVE-2026-46333) | `__ptrace_may_access()` race + `pidfd_getfd` on exiting SUID |

> 🔬 **Full writeup:** [Copy Fail (CVE-2026-31431) on rfxn.com/research](https://www.rfxn.com/research/copyfail-cve-2026-31431)
> covers cf1 kernel mechanics; the rest of the Copy Fail family extends
> the same `splice() → MSG_SPLICE_PAGES → in-place-crypto` primitive to
> additional sinks.

---

## Defense in depth

Each rung defeats the bug by a **different mechanism**, so an attack
that defeats one doesn't necessarily defeat the next:

| Rung | Where it fails | What the next rung covers |
|---|---|---|
| **Kernel patch (vendor)** | EL7 EOL; EL8/9/10 patch rollout lags disclosure days-to-weeks; production reboot may not be available; **Dirty Frag-RxRPC has no upstream patch** | Userspace cuts close the window without a reboot |
| **modprobe blacklist** | No-op when the relevant module is **builtin** (RHEL `algif_aead` is); no effect on already-resident modules | Functional for `esp4`/`esp6`/`xfrm_user`/`xfrm_algo`/`rxrpc` on stock RHEL kernels |
| **systemd `RestrictAddressFamilies` / `RestrictNamespaces`** | Reaches only services systemd starts post-restriction. Misses cron jobs running as root, sshd-pre-restriction, container payloads with their own pid 1 | LD_PRELOAD shim covers every dyn-linked process regardless of init |
| **LD_PRELOAD shim** | Static binaries; processes issuing `syscall` instruction directly; SUID binaries (kernel strips LD_PRELOAD for secure-exec) | seccomp at unit/runtime level catches direct-syscall path |
| **seccomp filter** | Per-service. Operationally heavy: each unit/runtime needs explicit policy | This package's systemd subpackage ships a one-line filter for the highest-leverage tenant units |

Where the shim itself fails (static binaries, direct `syscall`, SUID
stripping) is **attacker engineering territory**. The other rungs fail
under **routine operator reality**: vendors haven't shipped yet, the
kernel was built with builtin crypto, the threat surface includes a
cron job. That asymmetry is the case for deploying every rung.

---

## Subpackages

| Package | Arch | Contents |
|---|---|---|
| `rfxn-defense` | x86_64 | meta, pulls all six below (`-audit` as Recommends on EL8/9/10) |
| `rfxn-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so` + `rfxn-shim-{enable,disable}` |
| `rfxn-defense-modprobe` | noarch | `/etc/modprobe.d/99-rfxn-defense-{cf1,cf2-xfrm,rxrpc,rds}.conf` |
| `rfxn-defense-systemd` | noarch | drop-ins for `user@`/`sshd`/`cron`/`crond`/`atd` + container-runtime + RDS opt-in examples |
| `rfxn-defense-sysctl` | noarch | `/etc/sysctl.d/99-rfxn-defense-{userns,ptrace,iouring}.conf` (each independently auto-suppressed) |
| `rfxn-defense-auditor` | noarch | `/usr/sbin/rfxn-local-check` (Python, stdlib-only, read-only) |
| `rfxn-defense-audit` | noarch | `/etc/audit/rules.d/99-rfxn-defense.rules` (syscall tripwires) |
| `rfxn-defense-autoupdate` | noarch | `/etc/cron.d/rfxn-defense-autoupdate` + `/usr/sbin/rfxn-defense-update` (flock-protected wrapper) |

---

## Auto-detection of conflicting workloads

The installer inspects the host and **suppresses any drop-in that would
break a detected workload**. Every other layer stays active. Intent:
do no harm to running production; nothing else relaxes.

### Detection signals

| Workload | Signals (any of) | Suppresses |
|---|---|---|
| **IPsec** (strongSwan, libreswan, openswan) | enabled systemd unit (strongswan/libreswan/openswan/ipsec/pluto); `/etc/ipsec.conf` `conn` stanza; non-empty `*.conf` under `/etc/swanctl/conf.d/`, `/etc/ipsec.d/`, `/etc/strongswan{,/conf.d}/` | `99-rfxn-defense-cf2-xfrm.conf` (esp4, esp6, xfrm_user, xfrm_algo blacklist) |
| **AFS** (openafs, kafs) | enabled systemd unit (openafs-client/server, kafs, afsd); `/etc/openafs/{CellServDB,ThisCell}`; `/etc/krb5.conf.d/openafs*`; `/proc/fs/afs/` registered | `99-rxrpc.conf` + `12-rxrpc-af.conf` (`RestrictAddressFamilies=~AF_RXRPC` on all 5 tenant units) |
| **Rootless containers** | `/home/*/.local/share/containers/storage/overlay-containers/` (mtime ≤180d); `/var/lib/containers/storage/` non-empty (mtime ≤90d); `/run/user/<UID≥1000>/containers/`; `podman.socket` enabled | `15-userns.conf` on **`user@.service` only** + `99-rfxn-defense-userns.conf` host-wide sysctl |
| **Userns consumers** (Flatpak, firejail, desktop browser) | non-empty `/var/lib/flatpak/{app,runtime}` or per-user `~/.local/share/flatpak/app` (mtime ≤180d); `/usr/bin/firejail`; `/usr/bin/{chromium,chromium-browser,google-chrome,firefox,firefox-esr}` | `99-rfxn-defense-userns.conf` host-wide sysctl **only**; per-unit `RestrictNamespaces` stays active |
| **io_uring workload** | `liburing.so` in `/proc/*/maps`; known consumer binary executable (`postgres`, `scylla`, `mariadbd`, `dockerd`, `redis-server`, `nginx`, `envoy`, `rabbitmq-server`); io_uring-named systemd unit | `99-rfxn-defense-iouring.conf` **only** |

False-positive guards baked into the detector: `/etc/subuid` populated
by `useradd` is **not** a rootless signal (shadow-utils auto-populates
it for every regular user, which produced ~100% FPs on cPanel-shaped fleets
in v2.0.1 rev 1). Rootful container signal requires `mtime <90d`.
`/home` walk bounded (`maxdepth 6`, `mtime -180`). `/run/user` signal
requires `UID ≥ 1000`.

The cf1 shim and audit tripwires are **never** suppressed. cf1 coverage
is unchanged on every host.

### Inspect the decision

```sh
sudo cat /var/lib/rfxn-defense/auto-detect.json
sudo journalctl -t rfxn-defense-detect --since today
sudo rfxn-local-check --json | jq '.posture.auto_detect'
```

`auto-detect.json` (schema v2) lists `detected.<workload>.signals`,
`suppressed.<dropin>`, and `applied.<dropin>` flags. Detection runs in
`%posttrans` after every install/upgrade and on demand via
`rfxn-redetect`.

### Re-detect after the host changes

If you enable IPsec / AFS / rootless containers / Flatpak / firejail /
a desktop browser post-install:

```sh
sudo /usr/sbin/rfxn-redetect
sudo systemctl daemon-reload
sudo systemctl try-reload-or-restart sshd.service
sudo sysctl --system   # if any sysctl drop-in was added or removed
```

The helper refreshes `auto-detect.json` and copies/removes the
conditional drop-in files. It does NOT auto-reload systemd or sysctl;
the operator decides when running services pick up the change.

**Removing the sysctl drop-in does not reset the running-kernel value.**
`user.max_user_namespaces` stays at `0` until another sysctl.d file
sets it or the host reboots.

### Force full coverage (skip detection)

```sh
sudo mkdir -p /etc/rfxn-defense
sudo touch /etc/rfxn-defense/force-full
sudo dnf install -y rfxn-defense
```

The auditor reports `force-full sentinel active` when this is on.

---

## Override paths

systemd drop-ins use the standard layered-override pattern. Within a
`<unit>.service.d/` directory, files merge in lex order, and **lower
numbers lose to higher numbers** for `=value` directives. rfxn-defense
ships at `10-`, `12-`, `15-`; operator escape hatches sit at `20-`
and `25-`.

**`20-override.conf`** (neutralize one of our directives). Empty `=`
clears the union for list-valued directives. Survives package upgrade
(operator-owned, RPM does not manage it):

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d
sudo tee /etc/systemd/system/user@.service.d/20-override.conf >/dev/null <<'EOF'
[Service]
RestrictNamespaces=
RestrictAddressFamilies=
EOF
sudo systemctl daemon-reload
```

**`25-additions.conf`** (add a directive on top of ours). Sorts after
`20-` so it can layer on top of an empty-override:

```sh
sudo tee /etc/systemd/system/sshd.service.d/25-additions.conf >/dev/null <<'EOF'
[Service]
NoNewPrivileges=true
EOF
sudo systemctl daemon-reload
sudo systemctl try-reload-or-restart sshd.service
```

**modprobe override**: conditional `cf2-xfrm.conf` and `rxrpc.conf` are
managed by detect.sh (cmp-and-skip). Hand-edit and detect.sh logs WARN
on next `%posttrans` / `rfxn-redetect` and **preserves your edits**
(does not overwrite). For the always-on `cf1.conf`, edits survive
package upgrade via `%config(noreplace)`. Do not `chattr +i` a managed
file: it breaks dnf via EPERM on the next `install -m 0644`.

---

## Verifying signatures

v1.0.1+ and v2.0.0+ are signed by the Copyfail Project Signing Key
(retained as the project's canonical signing identity through the
v3.0.0 rfxn-defense rename). The `.repo` file enforces both
`gpgcheck=1` (per-RPM) and `repo_gpgcheck=1` (detached `repomd.xml.asc`
over the metadata), so a stock `dnf install` does end-to-end
verification automatically.

```
fingerprint: 6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
uid:         Copyfail Project Signing Key <proj@rfxn.com>
key file:    https://rfxn.github.io/rfxn-defense/RPM-GPG-KEY-rfxn
```

Out-of-band verification of a downloaded RPM:

```sh
curl -sSL https://rfxn.github.io/rfxn-defense/RPM-GPG-KEY-rfxn \
  | sudo rpm --import /dev/stdin
rpm -K rfxn-defense-3.0.0-1.el9.x86_64.rpm
# expect: digests signatures OK
```

---

## Auditor JSON schema (v2.0)

```json
{
  "schema_version": "2.0",
  "covers": ["CVE-2026-31431", "cf2-xfrm-esp", "dirtyfrag-esp", "dirtyfrag-rxrpc"],
  "posture": {
    "verdict": "vulnerable_kernel_userspace_mitigated",
    "bug_classes_covered": ["cf1", "cf2", "dirtyfrag-esp"],
    "bug_classes": { "cf1": { "applicable": true, "mitigated": true, "layers": {} } },
    "auto_detect": { "available": true, "suppressed_modprobe": [], "suppressed_systemd": [] }
  }
}
```

`bug_classes_covered` is the SIEM-ergonomic single filter.
`bug_classes` exposes per-layer breakdown for finer dashboards. `verdict`
and `layers` from v1.0.x are preserved for backwards compat.

`--emit-remediation` prints a bash script aggregating per-check
remediation hints. Output is **fully commented** by default; review
every block before pasting (chmod on suid binaries, modprobe blacklist,
and the unprivileged-userns sysctl are policy-dependent or require a
reboot to undo).

---

## Build from source

`no-afalg.c` is single-file, no build system. Tested on EL7
(gcc 4.8 / glibc 2.17), EL8 (gcc 8.5 / glibc 2.28), EL9 (gcc 11.5 /
glibc 2.34), EL10 (gcc 14 / glibc 2.39). x86_64 only.

```sh
gcc -shared -fPIC -O2 -Wall -Wextra \
    -o /usr/lib64/no-afalg.so no-afalg.c -ldl
```

To rebuild the RPMs from the published SRPM (under your own signing):

```sh
mock -r centos-stream+epel-9-x86_64 --rebuild \
  https://github.com/rfxn/rfxn-defense/releases/download/v3.0.0/rfxn-defense-3.0.0-1.el9.src.rpm
```

The spec lives at `packaging/rfxn-defense.spec`.

---

## Limitations

- **x86_64 only.** The shim has architecture asserts; the auditor's
  trigger probe struct layout is x86_64. Patches welcome for arm64.
- The userspace shim is irrelevant to static binaries and
  syscall-instruction issuers. Other rungs cover those.
- **Dirty Frag-RxRPC has no upstream patch.** Mitigation is the `rxrpc`
  modprobe blacklist + systemd `RestrictAddressFamilies=~AF_RXRPC`
  until upstream merges V4bel's proposed `skb_cloned(skb) ||
  skb->data_len` gate.
- modprobe blacklists do not unload already-resident modules.
  `%post modprobe` does a best-effort `rmmod`; reboot to fully clear.
- Auditor's trigger probe is destructive *only* against its own
  sentinel; it will briefly load `algif_aead` and friends if they
  aren't already loaded (which is the point).
- Removing `-sysctl` does NOT reset `user.max_user_namespaces` to the
  kernel default. The running kernel value persists until reboot or
  another sysctl.d drop-in overrides it.

## License

GPL v2. See `LICENSE`.

---

[rfxn.com](https://www.rfxn.com/) | forged in prod | Ryan MacDonald
