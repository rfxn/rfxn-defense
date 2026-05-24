# Outstanding follow-ups

Snapshot: **2026-05-24** (post v3.0.2 ship)

## Shipped in v3.0.2 (2026-05-24)

EL7 silent-failure closure. Empirical testing on a fresh CentOS
7.9.2009 VM surfaced four EL7-specific silent-mitigation gaps that
shipped in every prior 3.0.x build and were masked by the auditor's
own SKIP path. The defense-in-depth premise — "if a layer is shipped,
it MUST actually work" — was being violated for the ssh-keysign-pwn
primary mitigation (CVE-2026-46333) on every EL7 host since v3.0.0.

- **systemd userns drop-in gated out of EL7 builds.** systemd v219
  (EL7) does not recognise `RestrictNamespaces=` (added v235); the
  `15-rfxn-defense-userns.conf` drop-in shipped on EL7 was inert at
  unit-start. Spec gates Source8 + the `%files` entry on
  `%if 0%{?rhel} != 7`. `detect.sh` `apply_systemd` removes any stale
  files left by prior installs (verified on v3.0.1 → v3.0.2 upgrade
  on a live EL7 VM: 5 stale drop-ins cleaned, 0 remaining).
- **userns sysctl gated out of EL7 builds.** None of the three keys
  exist on kernel 3.10 (`max_user_namespaces` was 4.9+; the other
  two are non-RHEL kernel patches), AND EL7 procps-ng 3.3.10
  mis-parses the `-key` silent-skip prefix (added in 3.3.12), so
  every key in the file silently no-op'd. RHEL7 kernel-compile
  defaults already disable unprivileged userns.
- **ptrace_scope sysctl prefix removed.** Same procps-ng 3.3.10 issue
  killed `kernel.yama.ptrace_scope=2` host-wide on every EL7 host
  running v3.0.0 / v3.0.1 — CVE-2026-46333 mitigation latent until
  reboot. Dropped the `-` prefix; Yama LSM is in every supported RHEL
  kernel so a missing key is a one-line sysctl error (acceptable
  visibility on the rare no-Yama kernel) instead of a silent no-op.
  Also fixed the `%posttrans sysctl` loop in the spec, which only
  enumerated userns + iouring before — ptrace.conf landed on disk but
  was never `sysctl`-loaded at install time on ANY distro (regression
  from the v3.0.1 ptrace-split that omitted the loop entry).
- **Auditor `systemd_restrict_namespaces`** returned silent SKIP
  "no tenant units found" on EL7 because `systemctl show -p` doesn't
  emit the property line on systemd v219. Added a `systemd_version()`
  probe; when version < 235, emit FAIL with stale-drop-in list or
  SKIP with explicit "predates v235" reason. Auditor no longer masks
  the gap.
- **Auditor `userns_sysctl`** returned OK "unprivileged userns
  disabled" when kernel/distro defaults set `max_user_namespaces=0`,
  masking that the rfxn-defense sysctl drop-in was not on disk.
  Operator falsely believed rfxn-defense was enforcing it. Now
  distinguishes "by rfxn drop-in" from "by kernel/distro default" in
  the message + `details.rfxn_sysctl_dropin_present` boolean.
- **`check_ptrace_scope`** remediation text in both WARN and FAIL
  branches pointed at the v3.0.0-stale `99-rfxn-defense-userns.conf`
  path (ptrace_scope split into its own file in v3.0.1). Now points
  at `99-rfxn-defense-ptrace.conf` and cites the v3.0.2 `-` prefix
  removal so operators understand why the value was =0 despite the
  file being present.
- **NEW permanent EL7 live-host test runner** at
  `packaging/test-el7-live.sh`. 33 assertions across packaging
  sanity / auditor JSON / empirical mitigation probes (AF_ALG with
  shim isolated from modprobe blacklist; ptrace install-time runtime
  value captured BEFORE any manual sysctl by the runner; systemd-
  analyze verify on every drop-in) / copyfail-defense 2.1.1 → rfxn-
  defense 3.0.2 upgrade path including stale-drop-in cleanup. Guards
  vault.centos.org rewrite with `/etc/redhat-release` check (refuses
  to run on non-EL7 hosts).

**Spec process improvement.** Adversarial sentinel + engineer-fixup
cycle was load-bearing: sentinel caught (a) the `%posttrans sysctl`
loop missing ptrace.conf — the headline EL7 fix was broken at
install time on every distro; (b) one of two `check_ptrace_scope`
branches still had the stale remediation text; (c) the AF_ALG shim
probe in the test runner was a tautology (modprobe blacklist killed
the syscall before the shim was exercised). All three would have
shipped without the sentinel pass.

## v3.0.2 watch list

- [ ] `detect.sh` stale-removal of `15-rfxn-defense-userns.conf` and
      `99-rfxn-defense-userns.conf` does NOT honor D-57 cmp-and-skip
      for operator hand-edits. The summary `log_warn` and per-unit
      `log` info lines make removal visible in `journalctl -t
      rfxn-defense-detect`, but the rm itself proceeds without
      preserving operator divergence. Realistic case is rare (operator
      hand-edited a directive that EL7 systemd doesn't support
      anyway), but sentinel flagged it as a D-57 spirit violation.
      Possible fix: embed a sentinel comment in shipped templates and
      grep for it before rm; preserve + WARN on divergence. Defer
      until an operator actually reports a stale-removal surprise.
- [ ] **yum-3 on EL7 does not display scriptlet stderr reliably.**
      Tried 4 capture patterns (procsub tee, tmpfile-tee,
      cat-to-stderr, `logger -f`) — all deliver every warning to
      syslog with `authpriv.warning` facility cleanly, but yum-3
      filters/buffers small scriptlet stderr writes from
      "successful" scriptlets. dnf-4 on EL8+ displays them. The
      `%posttrans systemd` comment block documents the limitation
      and points operators at `journalctl -t rfxn-defense-detect`
      as the canonical audit trail. Not fixable from the package
      side; track for any future yum-3 audit-output workarounds.
- [ ] Auditor `systemd_version()` regex covers `systemd 219`,
      `systemd 252 (252.34-1.el9_5)`, and `systemd 245~rc1` correctly
      (anchored `(\d+)` matches the leading integer regardless of
      suffix). systemd 235-240 had bugs where `RestrictNamespaces=`
      was accepted at parse time but failed to propagate to
      template-unit instances; the per-unit `systemctl show -p`
      check reflects what the running unit actually applies so the
      mitigation status is correct, but the auditor doesn't surface
      "broken systemd version" as a category. Track for a future
      auditor expansion if EL8.4 (systemd 239) hosts surface
      unexpected mitigation gaps.
- [ ] `packaging/test-el7-live.sh` is sound on a fresh CentOS 7.9.2009
      VM but assumes vault.centos.org is reachable. If vault becomes
      unreachable, the runner exits 2 in the bootstrap phase. Mirror
      the test for EL8/EL9/EL10 (currently the only empirical
      mitigation testbed is on EL7; `test-repo.sh` covers the
      gh-pages published-repo path on all four distros but doesn't
      exercise mitigation runtime behavior). Defer until a non-EL7
      silent-failure class actually surfaces.

## Shipped in v3.0.0 (2026-05-23)

Project rename + reframe. The package family was renamed `copyfail-
defense` → `rfxn-defense` to reflect the umbrella scope (kernel-LPE
defense, not just the Copy Fail page-cache family) and to support the
narrative reframe as a **responsive defense layer** — one that ships
mitigations as 0days land, closing the delta between public disclosure
and the kernel/software vendor patch set.

- **Rename mechanics**, 19 packaging files + the auditor renamed via
  `git mv`. Content swept inside renamed files (paths, LOGGER_TAG,
  TOOL_VERSION 2.1.1 → 3.0.0). Spec rewritten end-to-end: `Name:`,
  `Version:`, Sources 14-16 (RDS + io_uring) preserved, Sources 17-18
  added for autoupdate cron + wrapper, all `%install`/`%files` paths
  updated, double Obsoletes/Provides chain on every subpackage
  (copyfail-defense + afalg-defense where applicable), new
  `%pretrans` meta migration block for `/var/lib/` and `/etc/` path
  moves via `mv -n` (idempotent).
- **NEW `rfxn-defense-autoupdate` subpackage**, hard-Required by meta.
  4-hourly cron drop-in at `/etc/cron.d/rfxn-defense-update` + wrapper
  at `/usr/libexec/rfxn-defense/update.sh`. flock-protected single
  runner, 0-600s random jitter, 600s timeout cap, targeted
  `dnf upgrade rfxn-defense*` via `--disablerepo='*'
  --enablerepo='rfxn-defense'`, journald logging. Opt out via touch
  `/etc/rfxn-defense/auto-update.disabled`. The auto-update cadence
  operationalizes the responsive-defense-layer pitch.
- **Audit-key rename**, `copyfail_{afalg,afkey,afrxrpc,afrds,pidfd_
  getfd}` → `rfxn_*`. SIEM operators MUST update `ausearch -k`
  queries on deploy. README + CHANGELOG document the mapping with
  a sed recipe.
- **GPG key sibling**, `RPM-GPG-KEY-rfxn` ships alongside the retained
  `RPM-GPG-KEY-copyfail` (same RSA-4096 key bytes; only filename
  differs). v3.0.0 `.repo` lists both `gpgkey=` URLs so dnf accepts
  either.
- **BRIEF.md DirtyDecrypt (CVE-2026-31635) cross-stamp** confirms
  coverage by existing rxrpc cuts; no new primitive needed. Escalation
  path documented if future variant surfaces non-AF_RXRPC entry.
- **GitHub repo rename**, `rfxn/copyfail` → `rfxn/rfxn-defense`.
  GitHub auto-redirects the github.com web URL + git remote ~6 months.
  gh-pages branch travels with the rename. **Known limitation:** the
  legacy `https://rfxn.github.io/copyfail/` URL returns HTTP 404
  (GitHub Pages does not issue HTTP redirects for renamed repos);
  v2.x hosts need manual migration. See the "Known issue" section
  below for the operator recipe.
- **Docs**, README + STATE + SPEC + BRIEF + FOLLOWUPS rewritten
  with the responsive-defense-layer reframe. SPEC.md gains §14
  (v3.0.0 architecture + decision index D-68..D-75).

## v3.0.0 watch list

- [ ] **Drop `RPM-GPG-KEY-copyfail`** from the spec Source list in
  3.1.0 once 2.x dnf clients have all refreshed their `.repo` files.
- [ ] **Drop `copyfail.repo`** from gh-pages in 3.1.0 (same trigger).
- [ ] **Drop `Obsoletes: afalg-defense*` chain** from spec in 3.1.0
  (1.0.x lineage has been carried through 3.0.x — long enough).
- [ ] **Drop `Obsoletes: copyfail-defense*` chain** in 4.0.0 (one
  major release of compat from the 2.x line).
- [ ] **Rename operator env knobs** `CFD_FORCE_IOURING_DISABLE` /
  `CFD_SUPPRESS_IOURING_DISABLE` → `RFXN_*` in 3.1.0 with deprecation
  cycle (the `CFD_*` form documented as legacy-compat in 3.0.x).
- [ ] **rfxn.com `/projects/copyfail/` page redirect** — set up
  301-redirect to `/projects/rfxn-defense/` once the rfxn-website-2026
  repo is updated. Out-of-band from this release.
- [ ] **Live-URL canary post-rename** — `gh repo rename` is irreversible
  enough to want a fresh `dnf install rfxn-defense` from the renamed
  URL on EL7/8/9/10 as a final smoke. The meta-RPM glob-gap incident
  from v2.1.0 (insight 2026-05-23T03:57:03Z) makes the live canary
  load-bearing.

## Shipped in v2.0.2 (2026-05-13)

Three Fragnesia / Dirty Frag bug-class hardening additions landed,
all driven by the 2026-05-08..2026-05-13 advisory wave (CloudLinux,
Wiz, Sysdig, Red Hat RHSB-2026-003, AWS, Microsoft, Tenable):

- New subpackage `copyfail-defense-sysctl`, host-wide
  `user.max_user_namespaces=0` (+ `kernel.unprivileged_userns_clone=0`,
  + `kernel.apparmor_restrict_unprivileged_userns=1`) drop-in to
  `/etc/sysctl.d/99-rfxn-defense-userns.conf`. Keys are
  `-`-prefixed so unknown keys silently skip (sysctl.d(5)). Closes
  the userns prerequisite of the cf2 / DF-ESP / Fragnesia chain
  host-wide, complementing the per-unit `RestrictNamespaces`. **This
  closes the "Open for v2.1.0" item below in v2.0.2 instead of v2.1.**
  Deviation from the original plan: meta hard-Requires `-sysctl`
  (not opt-in-only) because auto-detection suppresses the drop file
  on rootless containers, Flatpak, firejail, and desktop browsers
  the "blast radius documented loudly" requirement is satisfied by
  detection rather than operator gating.
- New subpackage `copyfail-defense-audit`, auditd rules at
  `/etc/audit/rules.d/99-rfxn-defense.rules` catching
  `socket(AF_ALG/AF_KEY/AF_RXRPC)` syscalls from `auid>=1000`.
  Meta pulls it via `Recommends` (soft) so minimal hosts without
  auditd skip the auditd transitive pull. Real value on hosts where
  modprobe blacklists are auto-suppressed (IPsec/AFS workloads)
  and the kernel sink stays reachable.
- `RestrictAddressFamilies` extended with `~AF_KEY` on the always-on
  10-* drop-in and the containers-dropin.conf example. Closes the
  PF_KEYv2 SA-config path used by the Dirty Frag / Fragnesia chain
  (XFRM netlink, the other SA-config path, still requires
  `CAP_NET_ADMIN`, harder route).
- detect.sh extended: `detect_userns_consumers` (Flatpak / firejail
  / desktop browsers), new `sysctl` and `all` scopes,
  auto-detect.json schema gets backward-compat additions
  (`detected.userns_consumers`, `suppressed.sysctl_userns`,
  `applied.sysctl_userns`). TOOL_VERSION bumped 2.0.1 → 2.0.2.
- README: CVE cross-stamping (cf2 = CVE-2026-43284, DF-RxRPC =
  CVE-2026-43500, Fragnesia surface notation). Coverage matrix
  gets a Fragnesia column, sysctl userns row, audit tripwire row.
  Operator-applied table gets the `initcall_blacklist=algif_aead_init`
  + grubby + reboot row for the RHEL builtin algif_aead case.

## Documentation drift to apply elsewhere

- [ ] **rfxn.com research article**, extend the article at <https://www.rfxn.com/research/copyfail-cve-2026-31431> with cf2 (xfrm-ESP) and Dirty Frag (V4bel) sections, matching the cf-class framing now in README.md. Article source lives in `rfxn/rfxn-website-2026` (private). The full v2.0.1 coverage matrix from STATE.md should land in the article's mitigation section. Include a note on the v2.0.1 auto-detection feature (IPsec/AFS/rootless workload detection, `rfxn-redetect` helper).

## Cron entries from the backup runbook (documented but not installed)

`rfxn-infra/docs/runbooks/copyfail-signing-key-backup.md` documents these, the initial sync + snapshot are done, but the recurring schedule isn't installed yet.

- [ ] On freedom, nightly rsync to forge:
  ```
  5 3 * * * rsync -a --chmod=Du=rwx,Dgo=,Fo=,Fg= /root/admin/secrets/copyfail-signing-key/ \
      forge.lab.rpx.sh:/hdd-pool/backups/copyfail-signing-key/ 2>&1 | logger -t copyfail-key-backup
  ```
- [ ] On forge, daily snapshot:
  ```
  5 3 * * * zfs snapshot hdd-pool/backups/copyfail-signing-key@$(date +\%Y\%m\%d)
  ```

The bundle is durable as-is (one full sync + one snapshot already on forge); cron just keeps it fresh after future key edits.

## Subsumed by v2.0.0 (was: v1.0.2 queue)

The v1.0.2 modprobe-file-catchup queue is folded into v2.0.0
the new `-modprobe` subpackage owns
`/etc/modprobe.d/99-copyfail-defense.conf` with the full
cf-class entry-point list (algif_aead/authenc/authencesn/af_alg
+ esp4/esp6/xfrm_user/xfrm_algo + rxrpc). No separate v1.0.2
release.

## Subsumed by v2.0.1 (was: README operator-side overrides)

v2.0.0 README's "Override paths" section pushed conflict resolution
onto operators (skip subpackages, hand-edit `%config(noreplace)`
files, write `20-override.conf` drop-ins). v2.0.1 replaces that with
package-driven auto-detection of IPsec / AFS / rootless-container
workloads, operators get the right drop-ins by default. Manual
override paths remain documented for finer-grained needs but are no
longer the primary recommendation.

## v2.0.2 watch list (post v2.0.1 ship)

Carried from v2.0.0 ship:

- [ ] **AF_ALG legitimate userspace consumers**, v2.0.1 keeps
  `RestrictAddressFamilies=~AF_ALG` unconditional on the assumption
  that no production workload uses AF_ALG. If a counter-example
  surfaces (some QEMU + AF_ALG deployment), add the detection signal
  to `detect.sh` and ship as v2.0.2.
  (AF_RXRPC was conditionalized in v2.0.1 rev 2 per reviewer C-3
  AFS userspace tooling, `aklog` in particular, opens AF_RXRPC
  sockets to vlserver/ptserver.)
- [ ] **Cross-subpackage removal: detection drift on partial
  uninstall**, `dnf remove copyfail-defense-systemd` (keeping
  `-modprobe`) does not currently re-run detection. The auditor
  flags drift on next audit run. If this proves operationally
  noisy, hook `%preun` to re-run `detect.sh` for the surviving
  subpackages.

Added in v2.0.1 rev 2 (reviewer fixup deferrals; in-scope items
were folded into the v2.0.1 ship, see SPEC §12 D-51..D-58):

- [ ] **`find /home -maxdepth 6` performance** (reviewer M-5) on
  huge-`/home` fleets (cPanel, multi-tenant). The rev 2 rootless
  detection signal walks `/home/*/.local/share/containers/storage/`
  to find podman storage trees. The `-mtime -180` gate bounds inode
  scans per subtree but not the directory traversal itself. May
  need a fallback that enumerates only `loginctl list-users` active
  users instead of walking all of `/home`. Watch for scriptlet
  timeouts in production reports; auditd noise from filesystem
  watchers may also surface.
- [ ] **Conditional `daemon-reload` optimization** (reviewer M-7)
  `detect.sh` always returns rc=0 on apply success regardless of
  whether any conditional file actually changed. `%posttrans
  systemd` always runs `daemon-reload`. Optimization: have
  `detect.sh` return rc=2 when no `/etc/...` changes happened;
  `%posttrans` skips `daemon-reload` on rc=2. Saves cosmetic reload
  work on re-runs. Defer until profiling shows a need.
- [ ] **Test fixture redundant write cleanup** (reviewer M-8)
  a few of the rev 2 detection-scenario tests do redundant
  `echo > file` followed by `printf > file` writes (force-full
  test pre-stages `/etc/ipsec.conf` twice in a row). Tighten on
  next revision.
- [ ] **v2.0.0 yank vs v2.0.1 hotfix narrative** (reviewer L-1)
  document in BRIEF.md / external article whether v2.0.0 should
  be tagged "yanked" given the same-day v2.0.1 ship. Current plan:
  keep v2.0.0 RPMs in the repo through the v2.0.x line per D-22
  retention. The narrative could read either way (hotfix vs yank);
  pick before the next blog post.
- [ ] **`%{_libexecdir}` macro adoption** (reviewer L-2), v2.0.1
  hard-codes `/usr/libexec/rfxn-defense/` in the spec. Convert
  to `%{_libexecdir}/copyfail-defense/` macro form in v2.0.2 for
  distro-portability cleanliness. The hard-coded path is FHS-correct
  on EL but the macro is the conventional spec idiom.
- [ ] **test-repo.sh file-count assertion tightening** (reviewer
  L-4), clean-host test asserts presence of 18 expected files but
  does not fail on *additional* unexpected files. Add a
  `find /etc/modprobe.d /etc/systemd/system/*.service.d -name '*copyfail*' | wc -l`
  exact-count assertion in v2.0.2.
- [ ] **mock chroot UID_MIN assumption documentation** (reviewer
  L-5), D-48 documents that mock chroots have only system users
  (UID < 1000), so rootless detection signals never trip in mock.
  Add an INTERNAL-NOTES.md entry citing `/etc/login.defs` `UID_MIN`
  and tying our detection threshold (1000) to that convention.
- [ ] **Per-mitigation force flags** (reviewer L-6), current
  `force-full` is a single boolean. Operators may want
  `force-modprobe-cf2-xfrm`, `force-systemd-rxrpc-af`, etc. as more
  granular existence-based flags. Defer until requested; the
  `force-full` lever covers the documented use cases.
- [ ] **STATE.md cross-repo state line** (reviewer L-8), v2.0.1
  rev 2 deferred the placeholder commit-hash insertion to Phase 9
  (post-commit). Verify on next ship-cycle that Phase 9's STATE.md
  update happened and no `<TBD-after-v2.0.1-commit>` marker leaked
  to gh-pages.

## v2.1.0 forward-cleanup obligation (reviewer M-10)

- [ ] **`%pretrans` must handle BOTH v2.0.0 monolithic files AND
  v2.0.1 split files** when migrating forward to v2.1.0. The v2.0.0
  monolithic file may still exist as `.rpmsave-v2.0.1` on hosts
  that upgraded but never cleaned up the rename artifact; the
  v2.0.1 split files are `%config(noreplace)` for the always-on
  cf1/10-* files and detect.sh-managed for the rest. v2.1.0's
  `%pretrans` needs explicit branches for both lineages.

  Recommended forward-compatible signal: write a plain-text file
  `/var/lib/rfxn-defense/installed-version` from v2.0.1
  `%posttrans` containing the version string. v2.1.0's `%pretrans`
  reads this file to decide which migration path to take, instead
  of re-querying `rpm -q copyfail-defense-modprobe --qf '%{version}'`
  (which is unreliable mid-transaction). v2.0.1 rev 2 plan does
  NOT yet write this signal, adding the writer is itself a
  v2.1.0 prep task.

## Open for v2.1.0 (after v2.0.0 lands)

(The original v2.1.0 userns-subpackage item moved to "Shipped in
v2.0.2" above, landed early as `copyfail-defense-sysctl`.)

- [ ] Drop the `Obsoletes:`/`Provides:` for `afalg-defense*`
  names from the spec. The compat chain is retained through the
  2.0.x line per **[D-21]**.
- [ ] Cleanup: remove old `afalg-defense-1.0.1*` RPMs from the
  gh-pages repo trees (kept for one release cycle per **[D-22]**).
- [ ] **Fragnesia CVE pin**, when the upstream CVE assignment
  for the ESP-in-TCP variant lands, cross-stamp SPEC/README/PLAN.
  Current state: CloudLinux blog cited "CVE-2026-46300" but Wiz,
  Sysdig, Tenable, Red Hat, AlmaLinux, AWS, oss-sec all describe
  Fragnesia as a follow-on bug in the CVE-2026-43284 surface with
  no separate CVE assigned yet (as of 2026-05-13). Worth
  re-checking the cna/Red Hat tracker monthly until pinned.

## Architecture extension (not scheduled)

- [ ] arm64 support. The `no-afalg.c` source has `#error "no-afalg.so currently only supports x86_64"` and the auditor's trigger probe struct layout is x86_64-only. Spec has `ExclusiveArch: x86_64`. Patches welcome (mentioned in README "Limitations").

## Key lifecycle

- [ ] **2028-04-29, signing key expires.** Either extend (`gpg --edit-key proj@rfxn.com expire`) or rotate (generate new key, ship 2.0.0 release whose `.repo` points at the new key URL, bump version so old signed RPMs aren't accidentally trusted). Re-run the backup procedure after either operation.

## v2.1.1 watch list

- **liburing.so detector misses**, auto-detect signal 1 walks
  /proc/[0-9]*/maps for liburing.so. Statically-linked io_uring
  consumers (Go binaries with liburing built in, Rust binaries
  linking statically) won't surface. Track operator reports of
  io_uring stalls post-v2.1.1 and expand signal 2 (binary list)
  accordingly.

## v2.1.0 watch list

- [RESOLVED v2.1.1] **io_uring opt-in**, `kernel.io_uring_disabled=2`
  shipped commented out in v2.1.0 `-sysctl` drop-in (operator opt-in
  only). Promoted to auto-applied with layered suppression in v2.1.1:
  separate drop-in file, detect.sh `detect_io_uring_workload()`,
  kernel < 6.6 gate, operator env knobs.
- **DirtyDecrypt (CVE-2026-31635) formal verification.** v2.1.0 ships
  under the assumption that the RXGK/RxRPC primitive is covered by the
  existing rxrpc cuts (modprobe blacklist + ~AF_RXRPC + rfxn_afrxrpc
  audit rule). Verify against the public advisory post-publish; if the
  entry primitive is not AF_RXRPC-mediated, open a v2.1.1 hotfix.
- **EL7 mock vault availability.** vault.centos.org and
  archives.fedoraproject.org/pub/archive/epel/7/ were live 2026-05-22.
  If they become unreachable, drop EL7 from subsequent releases or
  document the unmocked native-build fallback in CHANGELOG.
- **Rename to rfxn-defense (deferred).** v3.0.0 rename plan
  (docs/plans/2026-05-21-rfxn-defense-rename-plan.md) remains deferred
  to a future major release. Coverage from that plan landed in v2.1.0
  minus the rename mechanics.

## Known issue: legacy /copyfail/ URL after v3.0.0 repo rename

After `gh repo rename rfxn/copyfail -> rfxn/rfxn-defense`, the GitHub
Pages URL `https://rfxn.github.io/copyfail/` returns HTTP 404
(GitHub Pages does NOT support HTTP redirects on renamed repos; only
the git remote and the github.com/rfxn/copyfail web URL are
auto-redirected for ~6 months).

Existing v2.x dnf clients with `/etc/yum.repos.d/copyfail.repo` still
in place will see HTTP 404 on `dnf check-update` after v3.0.0 ships,
because their baseurl is `https://rfxn.github.io/copyfail/repo/...`
which no longer resolves. They are stranded on v2.1.1 until manually
re-pointed.

**Operator migration path:**
```
sudo curl -sSL https://rfxn.github.io/rfxn-defense/rfxn-defense.repo \
    -o /etc/yum.repos.d/rfxn-defense.repo
sudo rm -f /etc/yum.repos.d/copyfail.repo
sudo dnf upgrade -y rfxn-defense
```

**Possible mitigations for the next cycle:**

- [ ] Create a new `rfxn/copyfail-redirect` repo with a gh-pages
      branch containing HTML meta-refresh redirects (won't help dnf
      clients but serves browser traffic).
- [ ] Document in rfxn.com blog post + auditor JSON output
      (`installation_path_legacy` field flags hosts still on
      copyfail.repo so operators see it in their fleet surveys).
- [ ] Update the rfxn.com /research/copyfail-cve-2026-31431 page
      with a banner pointing at the new repo URL.
