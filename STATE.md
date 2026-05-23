# rfxn-defense, shipping state

Snapshot: **2026-05-23**

rfxn-defense is a responsive defense layer for Linux — it ships
kernel-LPE mitigations as 0days land, closing the delta between public
CVE disclosure and the kernel/software vendor patch set landing on
hosts. Each release pairs a disclosed bug class with the on-disk
primitives (modprobe blacklists, systemd `RestrictAddressFamilies` /
`RestrictNamespaces`, sysctl drop-ins, auditd tripwires, LD_PRELOAD
entry-point shim) that cut the attack path without waiting for a
kernel reboot or upstream patch. A 4-hourly auto-update cron (v3.0.0+)
keeps hosts current — install once, stay covered.

## Latest release

- **v3.0.0** (2026-05-23) — project rename `copyfail-defense` ->
  `rfxn-defense` reframing the package family as a kernel-LPE umbrella.
  Coverage unchanged from v2.1.1; rename mechanics, the responsive
  -defense-layer pitch, 4-hourly auto-update cron, audit-key rename,
  GPG key sibling, and DirtyDecrypt (CVE-2026-31635) cross-stamp under
  existing rxrpc cuts. Double Obsoletes/Provides chain (copyfail-defense
  + afalg-defense) handles upgrades from either lineage.
  - NEW subpackage `rfxn-defense-autoupdate` hard-Required by meta:
    `/etc/cron.d/rfxn-defense-update` (4-hour cadence, 0-600s jitter,
    flock + 600s timeout, targeted `dnf upgrade rfxn-defense*`,
    journald-logged, opt-out via `/etc/rfxn-defense/auto-update.disabled`).
  - Audit-key rename `copyfail_*` -> `rfxn_*`; SIEM operators must
    update `ausearch -k` queries on deploy.
  - Repo file `copyfail.repo` -> `rfxn-defense.repo`; new GPG key
    `RPM-GPG-KEY-rfxn` ships alongside the retained `RPM-GPG-KEY-copyfail`
    (same key bytes, dual gpgkey URLs in `.repo`).
  - gh-pages branch travels with the GitHub repo rename; legacy
    `https://rfxn.github.io/copyfail/` 301-redirects to
    `https://rfxn.github.io/rfxn-defense/`.
- Tag: <https://github.com/rfxn/rfxn-defense/releases/tag/v3.0.0>
- **v2.1.1**, promotes `kernel.io_uring_disabled=2` from operator
  opt-in (commented) to auto-applied with layered suppression. New
  `/etc/sysctl.d/99-rfxn-defense-iouring.conf` drop-in (separate
  from userns file). detect.sh adds `detect_io_uring_workload()` with
  three runtime signals (liburing.so in `/proc/*/maps`, known consumer
  binaries, io_uring-named systemd units); kernel < 6.6 gate
  auto-suppresses with `reason=kernel_too_old`. Operator env knobs:
  `CFD_FORCE_IOURING_DISABLE=1` / `CFD_SUPPRESS_IOURING_DISABLE=1`.
  Signed RPMs for EL7 / EL8 / EL9 / EL10.
- Tag: <https://github.com/rfxn/rfxn-defense/releases/tag/v2.1.1>
- **v2.1.0**, adds PinTheft (RDS zerocopy + io_uring) and
  ssh-keysign-pwn (CVE-2026-46333; ptrace exit-race + `pidfd_getfd`)
  coverage; new `-modprobe` cut for `rds`/`rds_tcp`/`rds_rdma`; new
  `RestrictAddressFamilies=~AF_RDS` in the always-on systemd
  10-* drop-in; new `kernel.yama.ptrace_scope=2` sysctl entry; opt-in
  `kernel.io_uring_disabled=2` line (commented out by default); two
  new auditd tripwire rules (`rfxn_afrds`, `rfxn_pidfd_getfd`).
  Build matrix expands to **EL7 / EL8 / EL9 / EL10**, x86_64.
  Signed RPMs.
- Tag: <https://github.com/rfxn/rfxn-defense/releases/tag/v2.1.0>
- v2.0.2 RPMs retained in repo trees for upgrade path
  (`dnf upgrade rfxn-defense`).
- v2.0.1 RPMs retained for one cycle.
- v2.0.0 RPMs retained for one cycle.
- v1.0.1 RPMs retained for one cycle (clean
  `dnf upgrade afalg-defense -> rfxn-defense` path).
- v1.0.0 was rolled back (was unsigned baseline; deleted from GH releases).

ELS = {7, 8, 9, 10}. EL7 RPMs are built against `vault.centos.org`
repositories (CentOS 7 EOL 2024-06-30); if mock-EL7 chroot fails at
build time, fallback is best-effort native rpmbuild against the
existing EL7 toolchain. The CHANGELOG notes whether EL7 shipped via
mock canary or native fallback for each release.

## Distribution

| Surface | URL |
|---|---|
| Source repo (main) | <https://github.com/rfxn/rfxn-defense> |
| GH Pages site | <https://rfxn.github.io/rfxn-defense/> |
| DNF repo file | <https://rfxn.github.io/rfxn-defense/copyfail.repo> |
| Public signing key | <https://rfxn.github.io/rfxn-defense/RPM-GPG-KEY-copyfail> |
| Per-EL RPM trees | `https://rfxn.github.io/rfxn-defense/repo/{8,9,10}/x86_64/` |
| Detached repodata sigs | `…/repo/{8,9,10}/x86_64/repodata/repomd.xml.asc` |
| Deep-dive article | <https://www.rfxn.com/research/copyfail-cve-2026-31431> |

## Operator one-liner

```sh
sudo curl -sSL https://rfxn.github.io/rfxn-defense/copyfail.repo \
  -o /etc/yum.repos.d/copyfail.repo
sudo dnf install -y rfxn-defense
sudo /usr/sbin/rfxn-shim-enable
```

Upgrade from `afalg-defense` v1.0.x:

```sh
sudo dnf upgrade -y rfxn-defense
```

## RPM family

| Package | Arch | Path |
|---|---|---|
| `rfxn-defense` (meta) | x86_64 | requires shim + modprobe + systemd + auditor |
| `rfxn-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so`, `/usr/sbin/copyfail-shim-{enable,disable}` |
| `rfxn-defense-modprobe` | noarch | `/etc/modprobe.d/99-rfxn-defense-cf1.conf` (always-on) + cf2-xfrm + rxrpc (conditional via detect.sh) |
| `rfxn-defense-systemd` | noarch | `/etc/systemd/system/{user@,sshd,cron,crond,atd}.service.d/10-rfxn-defense.conf` (always-on) + rxrpc-af (12-*, conditional) + userns (15-*, conditional) |
| `rfxn-defense-auditor` | noarch | `/usr/sbin/rfxn-local-check` |

`Epoch: 1` introduced in 2.0.0; `Obsoletes:` / `Provides: afalg-defense*`
metadata retained through 2.0.x release line. `/usr/sbin/rfxn-redetect`
added in 2.0.1 (ships in meta package).

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28; EL9/10: 2.34+).

Do **not** cross-install across ELs.

## Coverage matrix

| Layer | cf1 | cf2 | dirtyfrag-ESP | dirtyfrag-RxRPC | Fragnesia | PinTheft | keysign-pwn |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `-shim` (LD_PRELOAD AF_ALG) | ✅ primary | – | – | (incidental) | – | – | – |
| `-modprobe` (algif/authenc/af_alg) | ✅ (modular kernels) | – | – | – | – | – | – |
| `-modprobe` (esp4/esp6/xfrm_user/xfrm_algo) | – | ✅ | ✅ | – | ✅ | – | – |
| `-modprobe` (rxrpc) | – | – | – | ✅ | – | – | – |
| `-modprobe` (rds/rds_tcp/rds_rdma) *(v2.1.0)* | – | – | – | – | – | ✅ | – |
| `-systemd` (`~AF_ALG`) | ✅ | – | – | – | – | – | – |
| `-systemd` (`~AF_KEY`) *(v2.0.2)* | – | ✅ | ✅ | – | ✅ | – | – |
| `-systemd` (`~AF_RXRPC`) | – | – | – | ✅ | – | – | – |
| `-systemd` (`~AF_RDS`) *(v2.1.0)* | – | – | – | – | – | ✅ | – |
| `-systemd` (`~user ~net`) | – | ✅ | ✅ | – | ✅ | – | – |
| `-sysctl` (`user.max_user_namespaces=0`) *(v2.0.2)* | – | ✅ | ✅ | – | ✅ | – | – |
| `-sysctl` (`kernel.yama.ptrace_scope=2`) *(v2.1.0)* | – | – | – | – | – | – | ✅ |
| `-sysctl` (`kernel.io_uring_disabled=2`) *(v2.1.1, auto-detect)* | – | – | – | – | – | ✅ ⁴ | – |
| `-audit` (`rfxn_afalg/afkey/afrxrpc`) *(v2.0.2)* | tripwire | tripwire | tripwire | tripwire | tripwire | – | – |
| `-audit` (`rfxn_afrds`) *(v2.1.0)* | – | – | – | – | – | tripwire | – |
| `-audit` (`rfxn_pidfd_getfd`) *(v2.1.0)* | – | – | – | – | – | – | tripwire |
| Kernel patch | `a664bf3d` | `f4c50a4034` | `f4c50a4034` | (none upstream) | netdev only | (none upstream) | (CVE-2026-46333; none upstream) |

## Signing

```
fingerprint:  6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
key id:       6D30F32CD5E80F80
algo:         RSA-4096 (signing only), no passphrase
created:      2026-04-30
expires:      2028-04-29  (rotate or extend before)
uid:          Copyfail Project Signing Key <proj@rfxn.com>
```

- Live private key: `/root/.gnupg/` on freedom (this box)
- Backed up at: `forge.lab.rpx.sh:/hdd-pool/backups/copyfail-signing-key/` (ZFS, lz4, snapshot `@20260430`)
- Backup runbook: `rfxn-infra/docs/runbooks/copyfail-signing-key-backup.md`
- Portable export: `/root/admin/secrets/copyfail-signing-key/`
- `/etc/yum.repos.d/copyfail.repo` enforces `gpgcheck=1` + `repo_gpgcheck=1`

## Build / package conventions

- Spec: `packaging/rfxn-defense.spec`
- Helper scripts: `packaging/copyfail-shim-{enable,disable}`
- Active dropins source: `packaging/copyfail-modprobe-{cf1,cf2-xfrm,rxrpc}.conf`, `packaging/copyfail-systemd-dropin{,-rxrpc-af,-userns}.conf`, `packaging/copyfail-sysctl-{userns,iouring}.conf`
- Container-runtime example dropin source: `packaging/copyfail-systemd-dropin-containers.conf`
- Workload detection helper: `packaging/rfxn-defense-detect.sh`
- Operator re-detect helper: `packaging/rfxn-redetect`
- `.repo` source: `packaging/copyfail.repo`
- Public key source: `packaging/RPM-GPG-KEY-copyfail`
- Build invocation: `rpmbuild --define "_topdir /home/copyfail/rpmbuild" -ba packaging/rfxn-defense.spec`
- Per-EL: `mock -r centos-stream+epel-{8,9,10}-x86_64 --rebuild SRPMS/...`
- Sign: `rpmsign --addsign <RPM>` (uses `/root/.rpmmacros`)
- Repo metadata: `createrepo_c --general-compress-type=gz <dir>/`
  - `gz` (not zstd) for older-dnf compatibility
- Detach-sign metadata: `gpg --detach-sign --armor -o repomd.xml.asc repomd.xml`

## Test harness

`packaging/test-repo.sh`, podman-driven, **26 checks per EL** (was 18 in
v2.0.0; v2.0.1 adds detection-scenario tests for IPsec/AFS/rootless/clean
host + redetect helper + auto_detect auditor JSON).

```sh
bash packaging/test-repo.sh           # all three ELs
bash packaging/test-repo.sh 9         # single EL
REPO_URL=... bash packaging/test-repo.sh   # override source
```

## Auditor

`/usr/sbin/rfxn-local-check`, 26 checks across ENV/KERNEL/MITIGATION/
HARDENING/DETECTION categories, stdlib-only Python 3.6+. Five-class
scoring:

```
ENV         : kernel_info, distro_info, privilege, apparmor_userns_restrict, lsm_stack
KERNEL      : af_alg_socket, authencesn_cipher, algif_aead_state, xfrm_modules, rxrpc_module, trigger_probe
MITIGATION  : ld_so_preload, shim_blocks_af_alg, modprobe_blacklist, modprobe_extended,
              modules_disabled, initcall_blacklist, systemd_restrict, systemd_restrict_namespaces,
              user_service_dropin, dropin_freshness
HARDENING   : suid_inventory, page_cache_integrity (extended), file_capabilities,
              su_target_hardening, userns_sysctl
DETECTION   : auditd, audit_rules_extended, seccomp_runtime, pam_nullok, af_alg_holders,
              kernel_log_iocs, recent_iocs
```

JSON output gains `posture.bug_classes_covered` (SIEM-ergonomic array)
and `posture.bug_classes` (per-class map with kernel_sink + per-layer
booleans). Exit codes unchanged from v1.0.1.

v2.0.1 adds `posture.auto_detect` with `available`, `suppressed_modprobe`,
and `suppressed_systemd` fields. Available only when
`/var/lib/rfxn-defense/auto-detect.json` schema version 2 is present.

## Auto-detection (v2.0.1+)

`/usr/libexec/rfxn-defense/detect.sh` runs during `%posttrans` for
modprobe and systemd subpackages. It writes
`/var/lib/rfxn-defense/auto-detect.json` (schema version 2) and
conditionally installs or suppresses drop files.

| Signal | Source | Suppresses |
|---|---|---|
| IPsec (xfrm/esp) | kernel modules loaded; ipsec.conf/nss db | cf2-xfrm modprobe conf |
| AFS | kafs module; afs mount | rxrpc modprobe conf + rxrpc-af systemd drop-in |
| rootless containers | storage-tree: `~/.local/share/containers/storage` | userns systemd drop-in (user@ only) |

`/usr/sbin/rfxn-redetect`, operator-callable wrapper; re-runs
`detect.sh apply both`. Required after enabling a workload post-install.
Does NOT call `systemctl daemon-reload`, operator decides reload timing.

`/etc/rfxn-defense/force-full`, sentinel file; when present, detection is
skipped and all mitigations applied unconditionally.

## Safety properties enforced by the spec

- `%post` does **not** touch `/etc/ld.so.preload`, operator must run `rfxn-shim-enable`.
- `rfxn-shim-enable` smoke-tests the .so against `/bin/true` before writing the preload file.
- `%preun shim` on full erase scrubs `/etc/ld.so.preload` *before* RPM removes the .so (otherwise every dyn-linked binary fails to dlopen the missing preload, brick).
- `%posttrans shim` warns if the file ever ends up dangling.
- `%post modprobe` does best-effort `rmmod` of cf1 modules + LOG_AUTHPRIV trail; failures silenced.
- `%posttrans modprobe` calls `detect.sh apply modprobe`; best-effort rmmod of cf2/rxrpc if suppressed.
- `%postun modprobe` calls `detect.sh teardown modprobe` (or inline fallback); removes all drop files.
- `%posttrans systemd` calls `detect.sh apply systemd`; daemon-reload.
- `%postun systemd` calls `detect.sh teardown systemd` (or inline fallback); daemon-reload.
- All shipped conf files marked `%config(noreplace)`, operator hand-edits survive package upgrade.
- ExclusiveArch: x86_64 (the .c source has `#error` for non-x86_64).
- Both `gpgcheck=1` and `repo_gpgcheck=1` enforced in the published `.repo`.

## Defense-in-depth posture

The toolkit is a stack of independent layers:

1. **LD_PRELOAD shim**, works on every kernel, every dyn-linked process. cf1 primary defense.
2. **modprobe blacklist** of `algif_aead`/`authenc`/`authencesn`/`af_alg` (cf1; no-op on RHEL builtin) + `esp4`/`esp6`/`xfrm_user`/`xfrm_algo` (cf2/dirtyfrag-ESP) + `rxrpc` (dirtyfrag-RxRPC). Functional for the latter two on stock RHEL kernels (these are modules).
3. **systemd `RestrictAddressFamilies=~AF_ALG ~AF_RXRPC`** + **`RestrictNamespaces=~user ~net`** on tenant units (user@/sshd/cron/crond/atd). Kernel-enforced seccomp; uncircumventable from userspace.
4. **suid surface lockdown** (auditor recommends `chmod 4750 /usr/bin/su` only when `/etc/passwd` analysis shows no non-wheel interactive users).
5. **page-cache integrity probe** for `/etc/passwd`, PAM stacks, `/etc/ld.so.preload`, `/usr/bin/su`, dynamic linker.
6. **audit telemetry**, keys: `afalg_attempt`, `cf_userns`, `cf_addkey`, `cf_xfrm_nl`, `splice_tenant`.
7. **kernel patches**, cf1 `a664bf3d`, cf2/df-ESP `f4c50a4034`, df-RxRPC (none upstream).

The auditor scores all layers and reports per-class `applicable` /
`mitigated` / `active layers` so a fleet console can render per-host
posture without re-implementing verdict logic.

## Cross-repo state

- `rfxn/copyfail` main `<TBD-after-v2.0.1-commit>`, rfxn-defense v2.0.1 hotfix
- `rfxn/copyfail` gh-pages `<TBD>`, index.html refresh pending Phase 8
- `rfxn/copyfail` v2.0.0 tag, signed release (previous)
- `rfxn/copyfail` v2.0.1 tag, pending Phase 9 (manual)
- `rfxn/rfxn-infra` main `b86d9b7`, `docs/runbooks/copyfail-signing-key-backup.md` (unchanged)
- forge ZFS, `hdd-pool/backups/copyfail-signing-key/` populated, snapshot `@20260430` (unchanged)
