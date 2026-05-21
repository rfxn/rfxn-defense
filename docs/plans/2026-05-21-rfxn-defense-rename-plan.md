# Implementation Plan: rfxn-defense v3.0.0 rename + new CVE coverage

**Goal:** Rename the `copyfail-defense` RPM family to `rfxn-defense` (umbrella for kernel-LPE defense), add PinTheft (RDS+io_uring) coverage, add CVE-2026-46333 ssh-keysign-pwn (ptrace exit-race) coverage, verify CVE-2026-31635 DirtyDecrypt falls under existing rxrpc cut, expand build targets to EL7-EL10.

**Architecture:** Bug-class taxonomy split into **Copy Fail class** (page-cache overwrite: cf1, cf2, DF-RxRPC, Fragnesia, PinTheft, DirtyDecrypt) and **FD-theft class** (privilege-confusion via SUID exit race: ssh-keysign-pwn). Defense primitives unchanged in shape — modprobe blacklists, systemd `RestrictAddressFamilies`, sysctl drop-ins, auditd tripwires, LD_PRELOAD shim — extended with three new entry-point cuts (`rds`/`rds_tcp`/`rds_rdma`, `AF_RDS` in systemd, `kernel.yama.ptrace_scope=2`) and two new auditd rules (`AF_RDS`, `pidfd_getfd`). Package rename uses RPM `Obsoletes:`/`Provides:` chain (proven at v2.0.0 for `afalg-defense` → `copyfail-defense`).

**Tech Stack:** RPM `.spec` (rpmbuild + mock + rpmsign + createrepo_c + gpg), Python 3.6+ stdlib-only (auditor), C99 + libdl (LD_PRELOAD shim, x86_64-only), bash + jq-free JSON via python3 (detect.sh), podman + bash (test harness). Verified against EL7-EL10 build matrix.

**Spec:** inline brief in conversation turn at 2026-05-21 (no `docs/specs/` file in this project).

**Phases:** 13

**Plan Version:** 3.0.6

---

## Conventions

**Project naming pivot** — every reference to the package family changes:

| Old | New |
|---|---|
| `copyfail-defense` | `rfxn-defense` |
| `copyfail-defense-{shim,modprobe,systemd,auditor,sysctl,audit}` | `rfxn-defense-{shim,modprobe,systemd,auditor,sysctl,audit}` |
| `/var/lib/copyfail-defense/` | `/var/lib/rfxn-defense/` |
| `/etc/copyfail/force-full` | `/etc/rfxn-defense/force-full` |
| `/etc/modprobe.d/99-copyfail-defense-*.conf` | `/etc/modprobe.d/99-rfxn-defense-*.conf` |
| `/etc/systemd/system/*.service.d/{10,12,15}-copyfail-defense-*.conf` | `/etc/systemd/system/*.service.d/{10,12,15}-rfxn-defense-*.conf` |
| `/etc/sysctl.d/99-copyfail-defense-*.conf` | `/etc/sysctl.d/99-rfxn-defense-*.conf` |
| `/etc/audit/rules.d/99-copyfail-defense.rules` | `/etc/audit/rules.d/99-rfxn-defense.rules` |
| `/usr/libexec/copyfail-defense/` | `/usr/libexec/rfxn-defense/` |
| `/usr/share/copyfail-defense/conditional/` | `/usr/share/rfxn-defense/conditional/` |
| `/usr/sbin/copyfail-redetect` | `/usr/sbin/rfxn-redetect` |
| `/usr/sbin/copyfail-shim-enable` | `/usr/sbin/rfxn-shim-enable` |
| `/usr/sbin/copyfail-shim-disable` | `/usr/sbin/rfxn-shim-disable` |
| `/usr/sbin/copyfail-local-check` | `/usr/sbin/rfxn-local-check` |
| `LOGGER_TAG="copyfail-defense-detect"` | `LOGGER_TAG="rfxn-defense-detect"` |
| Audit keys `copyfail_afalg`, `copyfail_afkey`, `copyfail_afrxrpc` | `rfxn_afalg`, `rfxn_afkey`, `rfxn_afrxrpc` |
| Tarball `copyfail-VERSION.tar.gz` | `rfxn-defense-VERSION.tar.gz` |

**Bug-class identifiers** — preserved as-is (`cf1`, `cf2`, `df-rxrpc`, `fragnesia`); these are public IOC strings tied to the bug class, not the package. PinTheft and ssh-keysign-pwn get new identifiers `pinthift` (no — typo, use `pintheft`) and `keysign-pwn` respectively.

**Path migration policy** — on-disk paths under `/var/lib/`, `/etc/copyfail/`, `/etc/modprobe.d/`, `/etc/systemd/system/*.d/`, `/etc/sysctl.d/`, `/etc/audit/rules.d/` migrate via `%pretrans` move-if-exists. Bin/sbin paths gain compat symlinks for the 3.0.x line, dropped in 3.1.0.

**Audit key migration** — old `copyfail_*` keys are removed from the new ruleset; CHANGELOG documents old→new mapping. SIEM operators must update their `ausearch -k <key>` queries before deploying v3.0.0.

**Boilerplate** — every renamed `.conf` file's header block updates:
- `# Owned by copyfail-defense-X` → `# Owned by rfxn-defense-X`
- Path comments updated to new layout
- CVE / class identifiers preserved verbatim

**Bash** — `#!/bin/bash`, `set -euo pipefail`, `|| true` on legitimately-failing commands; explicit `return 0` on functions whose last expression is a chained `[ x ] && y` (per memory `feedback_set_e_pipefail_traps`).

**Spec** — multi-paragraph commentary in `packaging/rfxn-defense.spec` is intentional and load-bearing per `.rdf/governance/anti-patterns.md`. Preserve density on edits.

**Commit messages** — lowercase area-prefix + colon + active-voice (per `.rdf/governance/conventions.md`). Release commit: `3.0.0: rename copyfail-defense -> rfxn-defense umbrella + PinTheft + ssh-keysign-pwn coverage`. No em-dashes (per anti-patterns).

**CRITICAL** — never `git add -A`; stage explicit file lists. Never `--no-verify`. Never strip the spec's commentary. Never edit `/root/.claude/` directly. Always run `packaging/test-repo.sh` in containers before declaring done (per memory `feedback_test_repo_before_done`).

**EL7 build infrastructure** — CentOS 7 reached EOL 2024-06-30; mainline mirrors are dead. The plan adds a custom mock chroot config (`epel-7-x86_64-vault.cfg`) pointing at `vault.centos.org` for base/updates/extras and `archives.fedoraproject.org/pub/archive/epel/7/` for EPEL. test-repo.sh uses `quay.io/centos/centos:7` (still served as of 2026-05). If vault becomes unreachable, EL7 builds degrade to "best-effort native build on freedom, signed and published, no mock canary." Plan verifies vault availability in Phase 12 before declaring EL7 shippable.

---

## File Map

### New Files
| File | Lines | Purpose | Test File |
|------|-------|---------|-----------|
| `packaging/rfxn-modprobe-rds.conf` | ~15 | PinTheft `rds`/`rds_tcp`/`rds_rdma` module blacklist | `packaging/test-repo.sh` (check 34) |
| `packaging/rfxn-systemd-dropin-rds.conf` | ~10 | `RestrictAddressFamilies=~AF_RDS` conditional drop-in template (operator opt-in for container-runtime daemons; NOT auto-staged to tenant units) | `packaging/test-repo.sh` (check 36) |
| `packaging/RPM-GPG-KEY-rfxn` | ~50 | Symlink or duplicate of `RPM-GPG-KEY-copyfail` (same key, new filename for forward branding) | manual: `gpg --verify` |
| `packaging/rfxn-defense.repo` | ~40 | New repo file at `[rfxn-defense]`; old `copyfail.repo` ships in parallel during 3.0.x | `packaging/test-repo.sh` (REPO_URL override) |
| `packaging/mock-config/epel-7-x86_64-vault.cfg` | ~70 | Vault-mirror mock chroot config for EL7 builds | Phase 12 mock canary |
| `docs/plans/2026-05-21-rfxn-defense-rename-plan.md` | this file | N/A (plan) | N/A (docs) |

### Modified Files
| File | Changes | Test File |
|------|---------|-----------|
| `packaging/copyfail-defense.spec` → `packaging/rfxn-defense.spec` | rename file; `Name:` and 6 `%package` stanzas; `Version: 3.0.0`; double `Obsoletes:`/`Provides:` chain (copyfail + afalg); `Source0` tarball name; 4 new `Source` lines; all `%install` and `%files` paths; `%pretrans` migration scriptlets; `%posttrans` keep detect.sh wiring; new `%pretrans meta` that migrates `/var/lib/` and `/etc/copyfail/` to new paths; CHANGELOG entry | `packaging/test-repo.sh` (all checks); mock builds × 4 EL |
| `packaging/copyfail-modprobe-cf1.conf` → `packaging/rfxn-modprobe-cf1.conf` | rename via `git mv`; header comment path update | `packaging/test-repo.sh` (check 3) |
| `packaging/copyfail-modprobe-cf2-xfrm.conf` → `packaging/rfxn-modprobe-cf2-xfrm.conf` | rename; header path update | `packaging/test-repo.sh` (check 3) |
| `packaging/copyfail-modprobe-rxrpc.conf` → `packaging/rfxn-modprobe-rxrpc.conf` | rename; header path update | `packaging/test-repo.sh` (check 3) |
| `packaging/copyfail-systemd-dropin.conf` → `packaging/rfxn-systemd-dropin.conf` | rename; header path update; add `~AF_RDS` to `RestrictAddressFamilies=` | `packaging/test-repo.sh` (check 31) |
| `packaging/copyfail-systemd-dropin-containers.conf` → `packaging/rfxn-systemd-dropin-containers.conf` | rename; add `~AF_RDS` to example | `packaging/test-repo.sh` (check 15) |
| `packaging/copyfail-systemd-dropin-rxrpc-af.conf` → `packaging/rfxn-systemd-dropin-rxrpc-af.conf` | rename; header path update | `packaging/test-repo.sh` (check 19) |
| `packaging/copyfail-systemd-dropin-userns.conf` → `packaging/rfxn-systemd-dropin-userns.conf` | rename; header path update | `packaging/test-repo.sh` (check 22) |
| `packaging/copyfail-sysctl-userns.conf` → `packaging/rfxn-sysctl-userns.conf` | rename; header path update; keep keys identical | `packaging/test-repo.sh` (check 29) |
| `packaging/copyfail-defense-audit.rules` → `packaging/rfxn-defense-audit.rules` | rename; replace `copyfail_*` keys with `rfxn_*`; add 2 new rules (`AF_RDS` socket, `pidfd_getfd` syscall) | `packaging/test-repo.sh` (check 30 retargeted to rfxn_* keys; new checks for rds/pidfd) |
| `packaging/copyfail-defense-detect.sh` → `packaging/rfxn-defense-detect.sh` | rename; refactor constants (`STATE_DIR`, `TEMPLATE_DIR`, `FORCE_FULL`, `LOGGER_TAG`, `TOOL_VERSION="3.0.0"`); new `detect_rds_workload()` + `apply_rds_modprobe()` + `teardown_rds_modprobe()` (PinTheft). AF_RDS lives in the always-on 10-* systemd drop-in (already handled by the existing `apply_systemd` loop — no new function needed). `kernel.yama.ptrace_scope` lives in the existing `rfxn-sysctl-userns.conf` (handled by the existing `apply_sysctl` — no new function needed). Updates to `decide_suppressions()` and `write_state_json()` to add `rds_workload` detected/suppressed/applied keys | `packaging/test-repo.sh` (clean_host check 19; new rds_host scenario) |
| `packaging/copyfail-redetect` → `packaging/rfxn-redetect` | rename; update internal logger tag; same scope=all semantics | `packaging/test-repo.sh` (check 25 retargeted) |
| `packaging/copyfail-shim-enable` → `packaging/rfxn-shim-enable` | rename; update error string prefixes; no logic change | `packaging/test-repo.sh` (check 7) |
| `packaging/copyfail-shim-disable` → `packaging/rfxn-shim-disable` | rename; update error string prefixes; no logic change | `packaging/test-repo.sh` (check 10) |
| `copyfail-local-check.py` → `rfxn-local-check.py` (new path: `rfxn-local-check.py` at repo root, install target `/usr/sbin/rfxn-local-check`) | rename; update `AUTO_DETECT_PATH = "/var/lib/rfxn-defense/auto-detect.json"`; `mkdtemp(prefix="rfxn-")`; rpm-q `rfxn-defense-modprobe` etc.; remediation strings reference new sbin paths; new checks `check_ptrace_scope` (HARDENING), `check_pidfd_getfd_auditd_rule` (DETECTION), `check_rds_modprobe` + `check_af_rds_restrict` (MITIGATION), `check_package_audit_rules` (DETECTION — monitors the new `rfxn_*` package-shipped keys; complementary to the existing `check_audit_rules_extended` which still watches operator-emitted IOC keys and is NOT modified); extend `_aggregate_bug_classes()` with `pintheft` + `keysign-pwn` entries | `packaging/test-repo.sh` (check 9 JSON assertions retargeted) |
| `packaging/copyfail.repo` | KEEP filename (legacy operators still curl it); content unchanged for 3.0.x line — same `baseurl`, same `gpgkey` URL; deprecation notice as leading comment block; drop at 3.1.0 | manual: gh-pages canary |
| `packaging/RPM-GPG-KEY-copyfail` | KEEP filename (operator install one-liners still curl it); content unchanged; ship `RPM-GPG-KEY-rfxn` symlink alongside | manual: gpg fingerprint match |
| `packaging/test-repo.sh` | bulk rename of all `copyfail-defense*` subpackage refs to `rfxn-defense*`; bulk rename `/etc/modprobe.d/99-copyfail-defense-*` to `99-rfxn-defense-*`; same for sysctl, systemd, audit, libexec, var/lib paths; new check rds-modprobe present (check 34); new check ptrace_scope sysctl present (check 35); new check AF_RDS in systemd 10-* drop-in (check 36); new check `rfxn_afrds` audit rule present; new check `rfxn_pidfd_getfd` audit rule present; audit key assertion updated `copyfail_*` → `rfxn_*`; new upgrade-path test v2.0.2 → v3.0.0; ELS default to `(7 8 9 10)`; new IMAGE[7]="quay.io/centos/centos:7"; new mock chroot config invocation comment | self-test |
| `README.md` | rebrand title to `rfxn-defense`; add PinTheft + ssh-keysign-pwn rows to coverage matrix; add ssh-keysign-pwn FD-theft class section; install one-liner switches to `rfxn-defense.repo`; backward-compat note for `copyfail-defense` curls still working; coverage matrix extended with new columns; audit-key rename table with old→new mapping for SIEM; EL7 support note | `packaging/test-repo.sh` (manual docs visual review) |
| `STATE.md` | bump shipping state to v3.0.0; new RPM family table; ELs={7,8,9,10}; coverage matrix extended with PinTheft + FD-theft rows; sources path updates; build invocation `packaging/rfxn-defense.spec` | N/A (docs) |
| `SPEC.md` | append v3.0.0 architecture section with [D-NN] decisions (continue numbering from v2.0.x); bug-class taxonomy split; rename mechanics; EL7 addition rationale | N/A (docs) |
| `BRIEF.md` | add PinTheft and ssh-keysign-pwn brief sections alongside existing cf-class material; cross-link to disclosure URLs | N/A (docs) |
| `FOLLOWUPS.md` | mark v2.1.0 forward-cleanup obligation (afalg-defense Obsoletes drop) as superseded by v3.0.0 rename (the rename itself bumps the obsoletes-chain forward); add v3.1.0 forward-cleanup: drop the `copyfail-*` Obsoletes/Provides after 3.0.x line; add DirtyDecrypt verification result line; add v3.0.0 watch list (audit key migration follow-ups, EL7 mock vault availability monitoring) | N/A (docs) |
| `PLAN.md` (project root) | replace v2.0.1 plan body with one-line pointer to `docs/plans/2026-05-21-rfxn-defense-rename-plan.md` + brief v3.0.0 scope summary; preserve historical v2.0.1 plan under `docs/plans/PLAN-v2.0.1-archive.md` first | N/A (docs) |
| `.rdf/governance/architecture.md` | rename Project Overview `copyfail-defense` → `rfxn-defense`; update Components table paths; add PinTheft and ssh-keysign-pwn to Defense layers | N/A (governance) |
| `.rdf/governance/conventions.md` | rename references; update "Naming" section to reflect v3.0.0 rename; update File organization tree | N/A (governance) |
| `.rdf/governance/constraints.md` | extend Platform targets to EL7-EL10; document EL7 vault dependency; update Per-EL details table | N/A (governance) |
| `.rdf/governance/verification.md` | update test-repo.sh ELS default to (7 8 9 10); update build invocation spec filename; update auditor invocation binary name | N/A (governance) |
| `.rdf/governance/anti-patterns.md` | append entry: "DO NOT cross-pollinate copyfail_* and rfxn_* audit keys in CHANGELOG migration tables"; preserve existing entries | N/A (governance) |
| `.rdf/governance/index.md` | rename references; bump active plan pointer | N/A (governance) |

### Deleted Files
| File | Reason |
|------|--------|
| (none) | All renames use `git mv` to preserve history; no outright deletions. Old `copyfail.repo` and `RPM-GPG-KEY-copyfail` retained for 3.0.x compat. |

### Renamed Files (summary; all preserved via `git mv` for history)
12 files in `packaging/` rename from `copyfail-*` prefix to `rfxn-*` prefix.
1 file at repo root: `copyfail-local-check.py` → `rfxn-local-check.py`.

---

## Phase Dependencies

- Phase 1: none
- Phase 2: [1]
- Phase 3: [1]
- Phase 4: [1, 2, 3]
- Phase 5: [4]
- Phase 6: [4, 5]
- Phase 7: none
- Phase 8: [4, 5, 6]
- Phase 9: [4, 5, 6, 7, 8]
- Phase 10: [9]
- Phase 11: [4]
- Phase 12: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
- Phase 13: [12]

Phases 1 & 7 are eligible for the first batch under `/r-build --parallel`. Phase 7 (DirtyDecrypt verification) is independent of all rename work — pure read + comment additions.

---

### Phase 1: Bulk source-file renames (git mv only, zero content changes)

Pure refactor: rename every `packaging/copyfail-*` source file and `copyfail-local-check.py` to `rfxn-*`, leaving file contents untouched. This phase is isolated from all content edits so a rollback is a single `git revert` if the rename plan changes.

**Files:**
- Modify (rename via `git mv`):
  - `packaging/copyfail-defense.spec` → `packaging/rfxn-defense.spec`
  - `packaging/copyfail-defense-detect.sh` → `packaging/rfxn-defense-detect.sh`
  - `packaging/copyfail-defense-audit.rules` → `packaging/rfxn-defense-audit.rules`
  - `packaging/copyfail-modprobe-cf1.conf` → `packaging/rfxn-modprobe-cf1.conf`
  - `packaging/copyfail-modprobe-cf2-xfrm.conf` → `packaging/rfxn-modprobe-cf2-xfrm.conf`
  - `packaging/copyfail-modprobe-rxrpc.conf` → `packaging/rfxn-modprobe-rxrpc.conf`
  - `packaging/copyfail-systemd-dropin.conf` → `packaging/rfxn-systemd-dropin.conf`
  - `packaging/copyfail-systemd-dropin-containers.conf` → `packaging/rfxn-systemd-dropin-containers.conf`
  - `packaging/copyfail-systemd-dropin-rxrpc-af.conf` → `packaging/rfxn-systemd-dropin-rxrpc-af.conf`
  - `packaging/copyfail-systemd-dropin-userns.conf` → `packaging/rfxn-systemd-dropin-userns.conf`
  - `packaging/copyfail-sysctl-userns.conf` → `packaging/rfxn-sysctl-userns.conf`
  - `packaging/copyfail-redetect` → `packaging/rfxn-redetect`
  - `packaging/copyfail-shim-enable` → `packaging/rfxn-shim-enable`
  - `packaging/copyfail-shim-disable` → `packaging/rfxn-shim-disable`
  - `copyfail-local-check.py` → `rfxn-local-check.py`
- Preserve (do not rename):
  - `packaging/copyfail.repo` (compat — also need a new `packaging/rfxn-defense.repo` in Phase 3)
  - `packaging/RPM-GPG-KEY-copyfail` (compat — also need new `RPM-GPG-KEY-rfxn` in Phase 3)
  - `no-afalg.c` (semantic name tied to the AF_ALG syscall it intercepts; renaming would lose meaning)
  - `packaging/test-repo.sh` (not a copyfail-named source file)

- **Mode**: serial-context (15 mechanical `git mv`s, single agent)
- **Accept**: `git status -s | grep -c '^R'` returns 15 (15 renames staged); `test -f packaging/copyfail.repo && test -f packaging/RPM-GPG-KEY-copyfail && echo OK` returns `OK` (legacy filenames preserved); `ls packaging/ | grep -c '^copyfail-'` returns 0 (after rename no files start with `copyfail-`; the `.repo` is `copyfail.repo` with a dot and the GPG key starts with `RPM-`).
- **Test**: `bash -c 'cd packaging && for f in rfxn-defense.spec rfxn-defense-detect.sh rfxn-defense-audit.rules rfxn-modprobe-cf1.conf rfxn-modprobe-cf2-xfrm.conf rfxn-modprobe-rxrpc.conf rfxn-systemd-dropin.conf rfxn-systemd-dropin-containers.conf rfxn-systemd-dropin-rxrpc-af.conf rfxn-systemd-dropin-userns.conf rfxn-sysctl-userns.conf rfxn-redetect rfxn-shim-enable rfxn-shim-disable; do test -f "$f" || { echo "MISSING: $f"; exit 1; }; done' && test -f rfxn-local-check.py` returns rc=0 (all 15 renamed files present).
- **Edge cases**: none — this phase is mechanical renames with no logic.
- **Regression-case**: N/A — refactor — pure rename with no behavior change; downstream phases edit content and are themselves regression-tested.

- [ ] **Step 1.1: Rename 14 packaging/ files**

  ```bash
  git mv packaging/copyfail-defense.spec packaging/rfxn-defense.spec
  git mv packaging/copyfail-defense-detect.sh packaging/rfxn-defense-detect.sh
  git mv packaging/copyfail-defense-audit.rules packaging/rfxn-defense-audit.rules
  git mv packaging/copyfail-modprobe-cf1.conf packaging/rfxn-modprobe-cf1.conf
  git mv packaging/copyfail-modprobe-cf2-xfrm.conf packaging/rfxn-modprobe-cf2-xfrm.conf
  git mv packaging/copyfail-modprobe-rxrpc.conf packaging/rfxn-modprobe-rxrpc.conf
  git mv packaging/copyfail-systemd-dropin.conf packaging/rfxn-systemd-dropin.conf
  git mv packaging/copyfail-systemd-dropin-containers.conf packaging/rfxn-systemd-dropin-containers.conf
  git mv packaging/copyfail-systemd-dropin-rxrpc-af.conf packaging/rfxn-systemd-dropin-rxrpc-af.conf
  git mv packaging/copyfail-systemd-dropin-userns.conf packaging/rfxn-systemd-dropin-userns.conf
  git mv packaging/copyfail-sysctl-userns.conf packaging/rfxn-sysctl-userns.conf
  git mv packaging/copyfail-redetect packaging/rfxn-redetect
  git mv packaging/copyfail-shim-enable packaging/rfxn-shim-enable
  git mv packaging/copyfail-shim-disable packaging/rfxn-shim-disable
  ```

- [ ] **Step 1.2: Rename auditor at repo root**

  ```bash
  git mv copyfail-local-check.py rfxn-local-check.py
  ```

- [ ] **Step 1.3: Verify rename completeness**

  ```bash
  git status -s | grep -E '^R' | wc -l
  # expect: 15
  ```

  ```bash
  ls packaging/ | grep -c '^copyfail-'
  # expect: 0
  # (copyfail.repo and RPM-GPG-KEY-copyfail do NOT match '^copyfail-' due
  #  to the dot and RPM- prefix respectively. The check below verifies
  #  they are preserved.)
  ```

  ```bash
  test -f packaging/copyfail.repo && test -f packaging/RPM-GPG-KEY-copyfail && echo "legacy compat names preserved"
  # expect: legacy compat names preserved
  ```

  ```bash
  test -f packaging/rfxn-defense.spec && test -f rfxn-local-check.py && echo OK
  # expect: OK
  ```

- [ ] **Step 1.4: Commit**

  ```bash
  git add -u packaging/ rfxn-local-check.py
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 1: bulk-rename copyfail-* sources to rfxn-*

  Pure git mv preserving history. Content untouched - Phase 2 sweeps the
  internal path/identifier references. .repo file and GPG key keep their
  copyfail-named filenames for 3.0.x compat.
  EOF
  )"
  ```

  ```bash
  git log -1 --format='%s' | grep -q '^v3.0.0 phase 1' && echo OK
  # expect: OK
  ```

---

### Phase 2: Content sweep inside renamed files (path/identifier strings)

Update internal references inside the 15 renamed files. No new logic — pure string substitution of paths, log tags, sbin binary names, and shipped-filename references. Spec file is excluded from this phase (Phase 4 owns the spec rewrite end-to-end).

**Files:**
- Modify (path/identifier sweep):
  - `packaging/rfxn-modprobe-cf1.conf` (header comment: `/etc/modprobe.d/99-copyfail-defense-cf1.conf` → `/etc/modprobe.d/99-rfxn-defense-cf1.conf`; `Owned by copyfail-defense-modprobe` → `Owned by rfxn-defense-modprobe`)
  - `packaging/rfxn-modprobe-cf2-xfrm.conf` (same shape; reference to `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json`)
  - `packaging/rfxn-modprobe-rxrpc.conf` (same shape; same JSON-path update)
  - `packaging/rfxn-systemd-dropin.conf` (header path)
  - `packaging/rfxn-systemd-dropin-containers.conf` (header path + example activation paths)
  - `packaging/rfxn-systemd-dropin-rxrpc-af.conf` (header path + JSON path reference)
  - `packaging/rfxn-systemd-dropin-userns.conf` (header path)
  - `packaging/rfxn-sysctl-userns.conf` (header path + JSON path + `force-full` path `/etc/copyfail/` → `/etc/rfxn-defense/`)
  - `packaging/rfxn-defense-audit.rules` (header paths; rule keys updated in Phase 5 — leave key strings alone here)
  - `packaging/rfxn-defense-detect.sh` (constants `STATE_DIR`, `TEMPLATE_DIR`, `FORCE_FULL`, `LOGGER_TAG`, `TOOL_VERSION`; touched in finer detail in Phase 3 — this phase only renames the 5 constants' values, no new functions)
  - `packaging/rfxn-redetect` (error messages, libexec path, JSON path reference)
  - `packaging/rfxn-shim-enable` (helper name in `err()`/`info()`; sbin path references)
  - `packaging/rfxn-shim-disable` (same as enable)
  - `rfxn-local-check.py` (`AUTO_DETECT_PATH` constant line 144; `tempfile.mkdtemp(prefix=...)` line 427; `_rpm_q_installed("copyfail-defense-modprobe")` line 1435 and similar throughout; remediation-string `/usr/sbin/copyfail-redetect` → `/usr/sbin/rfxn-redetect` lines 1448, 1452, 1466; install instruction lines 2287, 2322-2376, 2425, 2445, 2473; do NOT touch audit-key strings yet — Phase 5 owns those)

- **Mode**: parallel-agent (files are independent; 3 tracks: modprobe+sysctl+audit-rules confs, systemd dropins, helper scripts+detect.sh+auditor)
- **Accept**:
  - `grep -rn '/var/lib/copyfail-defense\|/etc/copyfail/\|copyfail-defense-modprobe\|copyfail-defense-systemd\|copyfail-defense-sysctl\|copyfail-defense-audit\|copyfail-defense-shim\|copyfail-defense-auditor\|copyfail-redetect\|copyfail-shim-enable\|copyfail-shim-disable\|copyfail-local-check' packaging/rfxn-*.conf packaging/rfxn-defense-*.sh packaging/rfxn-defense-*.rules packaging/rfxn-redetect packaging/rfxn-shim-* rfxn-local-check.py | wc -l` returns 0 (zero stale `copyfail-*` identifiers in the renamed source files).
  - **Exception:** `packaging/rfxn-defense-audit.rules` still contains literal `copyfail_afalg`/`copyfail_afkey`/`copyfail_afrxrpc` rule keys at this point — Phase 5 renames them. The grep above does NOT match `copyfail_` (underscore) since the pattern requires `copyfail-` (hyphen) variants.
- **Test**:
  - `bash -n packaging/rfxn-defense-detect.sh` (syntax check, expect rc=0)
  - `bash -n packaging/rfxn-redetect packaging/rfxn-shim-enable packaging/rfxn-shim-disable` (expect rc=0 each)
  - `python3 -c 'import py_compile; py_compile.compile("rfxn-local-check.py", doraise=True)'` (expect rc=0, no stdout)
  - File-content verification with explicit greps below in Step 2.5.
- **Edge cases**:
  - The `copyfail.repo` and `RPM-GPG-KEY-copyfail` filenames are intentionally preserved — do not rewrite references to those filenames during the sweep.
  - String `copyfail_afalg`/`copyfail_afkey`/`copyfail_afrxrpc` in `packaging/rfxn-defense-audit.rules` is reserved for Phase 5 audit-key rename; Phase 2 must NOT touch underscore variants.
  - `rfxn-local-check.py` ASCII-art remediation block (lines ~2287+) embeds the install one-liner that references `copyfail.repo` URL on rfxn.github.io — keep `copyfail.repo` URL literal (gh-pages URL is preserved), update the package name in the `dnf install` line only.
- **Regression-case**: N/A — refactor — string substitution within renamed files; functional behavior unchanged until Phase 4 wires the new spec.

- [ ] **Step 2.1: Update modprobe and sysctl conf headers**

  For each of `packaging/rfxn-modprobe-cf1.conf`, `packaging/rfxn-modprobe-cf2-xfrm.conf`, `packaging/rfxn-modprobe-rxrpc.conf`, `packaging/rfxn-sysctl-userns.conf`:
  - Replace `# /etc/modprobe.d/99-copyfail-defense-` → `# /etc/modprobe.d/99-rfxn-defense-` and the analogous `# /etc/sysctl.d/` path
  - Replace `# Owned by copyfail-defense-modprobe` → `# Owned by rfxn-defense-modprobe` (etc. per subpackage)
  - Replace `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json`
  - In `rfxn-sysctl-userns.conf`: replace `/etc/copyfail/force-full` → `/etc/rfxn-defense/force-full`

  Use targeted Edit operations per file, not bulk `sed -i` across the tree (need to leave audit-key underscores alone).

- [ ] **Step 2.2: Update systemd drop-in headers**

  For each of `packaging/rfxn-systemd-dropin.conf`, `packaging/rfxn-systemd-dropin-containers.conf`, `packaging/rfxn-systemd-dropin-rxrpc-af.conf`, `packaging/rfxn-systemd-dropin-userns.conf`:
  - Replace `# /etc/systemd/system/<unit>.service.d/10-copyfail-defense.conf` → `# /etc/systemd/system/<unit>.service.d/10-rfxn-defense.conf` (and `12-`, `15-`)
  - Replace `# Owned by copyfail-defense-systemd` → `# Owned by rfxn-defense-systemd`
  - In `rfxn-systemd-dropin-containers.conf`: replace example paths `/usr/share/doc/copyfail-defense/examples/containers-dropin.conf` → `/usr/share/doc/rfxn-defense/examples/containers-dropin.conf`
  - Replace `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json` where present

- [ ] **Step 2.3: Update audit-rules file header (NOT keys)**

  In `packaging/rfxn-defense-audit.rules`:
  - Replace `## Owned by copyfail-defense-audit` → `## Owned by rfxn-defense-audit`
  - Replace `## ausearch -k copyfail_afalg` documentation example lines → `## ausearch -k rfxn_afalg` (and `rfxn_afkey`, `rfxn_afrxrpc`)

  Note: this updates the documentation comment block's example queries. The actual rule keys (`-k copyfail_afalg` on the `-a always,exit` lines) stay literal `copyfail_*` until Phase 5; Phase 2 only touches the documentation examples to avoid double-handling.

  **Self-correction note:** It is tempting to rename audit-rule keys here too since they are in the same file, but the CHANGELOG-driven migration table (Phase 5) needs the keys to flip in a single atomic commit so SIEM operators see a single before/after pair. Splitting the comment-update vs key-update across phases is intentional.

- [ ] **Step 2.4: Update detect.sh constants**

  In `packaging/rfxn-defense-detect.sh` (lines 14-21 area):
  - `STATE_DIR="/var/lib/copyfail-defense"` → `STATE_DIR="/var/lib/rfxn-defense"`
  - `TEMPLATE_DIR="/usr/share/copyfail-defense/conditional"` → `TEMPLATE_DIR="/usr/share/rfxn-defense/conditional"`
  - `FORCE_FULL="/etc/copyfail/force-full"` → `FORCE_FULL="/etc/rfxn-defense/force-full"`
  - `LOGGER_TAG="copyfail-defense-detect"` → `LOGGER_TAG="rfxn-defense-detect"`
  - `TOOL_VERSION="2.0.2"` → `TOOL_VERSION="3.0.0"`

  In the inline python3 JSON emitter (around line 484):
  - `"tool": "copyfail-defense-detect"` → `"tool": "rfxn-defense-detect"`

  Leave all detect/apply/teardown function names and signal-array names untouched in this phase. Phase 3 adds new functions (RDS detection, ptrace sysctl).

- [ ] **Step 2.5: Update redetect and shim helpers**

  In `packaging/rfxn-redetect`:
  - Header comment block: `# copyfail-redetect` → `# rfxn-redetect`; update purpose comment
  - `if [ "$(id -u)" -ne 0 ]; then echo "copyfail-redetect: must be run as root"` → `... echo "rfxn-redetect: ..."`
  - `if [ ! -x /usr/libexec/copyfail-defense/detect.sh ]` → `if [ ! -x /usr/libexec/rfxn-defense/detect.sh ]`
  - Error message `(re-install copyfail-defense-modprobe or -systemd to restore)` → `(re-install rfxn-defense-modprobe or -systemd to restore)`
  - Final state path echo: `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json`

  In `packaging/rfxn-shim-enable`:
  - `# copyfail-shim-enable` → `# rfxn-shim-enable`
  - `err()  { printf 'copyfail-shim-enable: %s\n'` → `printf 'rfxn-shim-enable: %s\n'`
  - `info()` same shape
  - `err "$SHIM not present - reinstall copyfail-shim package"` → `err "$SHIM not present - reinstall rfxn-defense-shim package"`

  In `packaging/rfxn-shim-disable`:
  - Same shape: `# copyfail-shim-disable` → `# rfxn-shim-disable`; `err()`/`info()` printf prefixes

- [ ] **Step 2.6: Update auditor (rfxn-local-check.py)**

  - Line ~5: `# copyfail-local-check.py` → `# rfxn-local-check.py`
  - Line ~11 docstring: `copyfail-local-check.py - comprehensive Copy Fail bug-class auditor` → `rfxn-local-check.py - comprehensive rfxn-defense host posture auditor (Copy Fail + FD-theft bug classes)`
  - Lines ~29-35 usage block: `./copyfail-local-check.py` → `./rfxn-local-check.py` (all 7 occurrences)
  - Line 144: `AUTO_DETECT_PATH = "/var/lib/copyfail-defense/auto-detect.json"` → `AUTO_DETECT_PATH = "/var/lib/rfxn-defense/auto-detect.json"`
  - Line 427: `tmp = tempfile.mkdtemp(prefix="copyfail-")` → `tmp = tempfile.mkdtemp(prefix="rfxn-")`
  - Lines 1330, 1363, 1402-1403: replace `99-copyfail-defense.conf` → `99-rfxn-defense-cf1.conf` (matches the actual current shipped filename in v2.0.2)
  - Lines 1402, 1593: `Install copyfail-defense-modprobe` → `Install rfxn-defense-modprobe`; same for `copyfail-defense-systemd`
  - Line 1422: `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json`
  - Lines 1435, 1436: `_rpm_q_installed("copyfail-defense-modprobe")` → `_rpm_q_installed("rfxn-defense-modprobe")`; same for `-systemd`
  - Lines 1448, 1452, 1466: `Run: /usr/sbin/copyfail-redetect` → `Run: /usr/sbin/rfxn-redetect`
  - Line 1584: `.service.d/10-copyfail-defense.conf` → `.service.d/10-rfxn-defense.conf`; same on line 1586
  - Lines 2322-2360 remediation block (ASCII-art install instructions):
    - `# # FAST PATH: install the copyfail-defense umbrella package` → `# # FAST PATH: install the rfxn-defense umbrella package`
    - `# sudo dnf install -y copyfail-defense` → `# sudo dnf install -y rfxn-defense`
    - `# sudo /usr/sbin/copyfail-shim-enable` → `# sudo /usr/sbin/rfxn-shim-enable`
    - `# sudo tee /etc/modprobe.d/99-copyfail-defense.conf` → `# sudo tee /etc/modprobe.d/99-rfxn-defense-cf1.conf`
    - `# sudo tee /etc/systemd/system/${u}.service.d/10-copyfail-defense.conf` → `# ...10-rfxn-defense.conf`
    - `# sudo tee /etc/audit/rules.d/copyfail.rules` → `# sudo tee /etc/audit/rules.d/99-rfxn-defense.rules`
    - Curl URL lines: PRESERVE literal `copyfail.repo` URL (gh-pages stable) — change only the local download target if shown
  - Line 2425: `sys.stderr.write("copyfail-defense checker (cf1+cf2+Dirty Frag) ` → `sys.stderr.write("rfxn-defense host posture checker (cf-class + FD-theft) `
  - Line 2445: `"tool": "copyfail-local-check"` → `"tool": "rfxn-local-check"`
  - **Do NOT touch in this phase:** audit-key strings (`copyfail_afalg` etc. — Phase 5); auditor's `cf1`/`cf2`/`dirtyfrag-esp`/`dirtyfrag-rxrpc` posture map keys (preserved as IOC identifiers); the `# rfxn.com - forged in prod - github.com/rfxn/copyfail` branding line (already says rfxn.com — leave).

- [ ] **Step 2.7: Run completeness verification**

  ```bash
  grep -rn '/var/lib/copyfail-defense\|/etc/copyfail/\|copyfail-defense-\|copyfail-redetect\|copyfail-shim-\|copyfail-local-check' \
      packaging/rfxn-defense.spec packaging/rfxn-defense-detect.sh \
      packaging/rfxn-defense-audit.rules packaging/rfxn-modprobe-*.conf \
      packaging/rfxn-systemd-dropin*.conf packaging/rfxn-sysctl-*.conf \
      packaging/rfxn-redetect packaging/rfxn-shim-* rfxn-local-check.py \
      2>/dev/null
  # expect: only matches from packaging/rfxn-defense.spec (Phase 4 owns the spec)
  ```

  ```bash
  bash -n packaging/rfxn-defense-detect.sh
  bash -n packaging/rfxn-redetect packaging/rfxn-shim-enable packaging/rfxn-shim-disable
  python3 -c 'import py_compile; py_compile.compile("rfxn-local-check.py", doraise=True)'
  echo "syntax OK"
  # expect: syntax OK
  ```

  ```bash
  grep -c 'copyfail_af' packaging/rfxn-defense-audit.rules
  # expect: 3
  # (3 audit-rule keys unchanged in Phase 2; Phase 5 renames them)
  ```

- [ ] **Step 2.8: Commit**

  ```bash
  git add -u packaging/ rfxn-local-check.py
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 2: content sweep - rename internal path/identifier refs

  Updates internal references inside renamed files to match the new
  package family naming. Pure string substitution: path constants, log
  tags, sbin binary names, doc-comment paths. Audit rule -k keys stay
  literal copyfail_* until Phase 5's atomic key rename. Spec file
  (rfxn-defense.spec) deferred to Phase 4.
  EOF
  )"
  ```

---

### Phase 3: New defensive source files (PinTheft + ssh-keysign-pwn)

Add three new packaged source files plus a new `.repo` and a new `RPM-GPG-KEY-rfxn` symlink. No spec changes here — Phase 4 wires Sources. New auditd rules and the `kernel.yama.ptrace_scope` sysctl key land in the existing `rfxn-defense-audit.rules` and `rfxn-sysctl-userns.conf` files respectively (single conf per subpackage, additive).

**Files:**
- Create:
  - `packaging/rfxn-modprobe-rds.conf` (PinTheft `rds`/`rds_tcp`/`rds_rdma` block) — test: `packaging/test-repo.sh` (check 34)
  - `packaging/rfxn-systemd-dropin-rds.conf` (conditional `~AF_RDS` drop-in for tenant units, suppressible on RDS-workload hosts) — test: `packaging/test-repo.sh` (check 36)
  - `packaging/rfxn-defense.repo` (new repo file `[rfxn-defense]` baseurl/gpgkey unchanged) — test: manual gh-pages canary
  - `packaging/RPM-GPG-KEY-rfxn` (filesystem-level copy of `RPM-GPG-KEY-copyfail`; same key bytes, new filename) — test: `gpg --import-options show-only --import < packaging/RPM-GPG-KEY-rfxn` (fingerprint match)
- Modify:
  - `packaging/rfxn-sysctl-userns.conf` (append `kernel.yama.ptrace_scope` and commented `kernel.io_uring_disabled` key — single sysctl conf file owns userns + ptrace + io_uring keys to avoid creating a phantom `rfxn-sysctl-ptrace.conf` not wired by spec) — test: `packaging/test-repo.sh` (check 35)
  - `packaging/rfxn-defense-audit.rules` (append two new `-a always,exit` rules for `AF_RDS` socket and `pidfd_getfd` syscall) — test: `packaging/test-repo.sh` (new checks 37, 38)
  - `packaging/rfxn-systemd-dropin.conf` (extend `RestrictAddressFamilies=` with `~AF_RDS` on the always-on 10-* body) — test: `packaging/test-repo.sh` (check 31 extended)
  - `packaging/rfxn-systemd-dropin-containers.conf` (extend the example body with `~AF_RDS`) — test: `packaging/test-repo.sh` (check 15)

- **Mode**: serial-agent (one engineer; 4 file creates + 4 file modifies are tightly coupled to the bug-class additions)
- **Accept**:
  - `test -f packaging/rfxn-modprobe-rds.conf && test -f packaging/rfxn-systemd-dropin-rds.conf && test -f packaging/rfxn-defense.repo && test -f packaging/RPM-GPG-KEY-rfxn` returns rc=0
  - `grep -c '^install +\(rds\|rds_tcp\|rds_rdma\) +/bin/false' packaging/rfxn-modprobe-rds.conf` returns 3
  - `grep -q 'kernel.yama.ptrace_scope' packaging/rfxn-sysctl-userns.conf` returns rc=0
  - `grep -q 'AF_RDS' packaging/rfxn-systemd-dropin.conf` returns rc=0
  - `grep -cE '^-a always,exit .* -k (rfxn_afrds|rfxn_pidfd_getfd)' packaging/rfxn-defense-audit.rules` returns 2 (the two new rules use new `rfxn_*` keys directly; existing 3 still on `copyfail_*` until Phase 5)
  - GPG fingerprint of `RPM-GPG-KEY-rfxn` matches `6001 1CDC EA2F F52D 975A FDEE 6D30 F32C D5E8 0F80`
- **Test**: file-content greps in Step 3.7 below; GPG fingerprint verification in Step 3.5.
- **Edge cases**:
  - **EL7 caveat for `pidfd_getfd` rule**: EL7 kernel 3.10 has no `pidfd_getfd` syscall name (added in 5.6). On EL7, `augenrules` will reject `-S pidfd_getfd` with "Syscall name unknown: pidfd_getfd". Use the numeric form `-S 438` on b64 with a comment explaining the name vs number choice. Tested behavior: `auditctl -S 438` works on every EL kernel; `auditctl -S pidfd_getfd` fails on EL7/EL8 audit-userspace and works on EL9+.
  - **`-` prefix on Yama sysctl**: per existing pattern, `kernel.yama.ptrace_scope` is prefixed with `-` so kernels without Yama LSM (very rare) silently skip. EL7+ stock all ship Yama as builtin.
  - **`io_uring_disabled` commented opt-in**: this sysctl exists only on Linux 6.6+. Even with `-` prefix, an `io_uring_disabled=2` setting that takes effect on RHEL 10 may break container runtimes that depend on io_uring. Ship as commented-out by default; document operator opt-in in README.
  - **`AF_RDS` value**: socket-domain numeric value is 21 (per linux/socket.h `AF_RDS`). Use numeric `a0=21` in audit rule (matches existing pattern for AF_ALG=38, AF_KEY=15, AF_RXRPC=33).
- **Regression-case**: `packaging/test-repo.sh::check-34 (rds modprobe present)`, `::check-35 (ptrace_scope sysctl key present)`, `::check-36 (AF_RDS in systemd dropin)`, `::check-37 (rfxn_afrds audit rule)`, `::check-38 (rfxn_pidfd_getfd audit rule)` — security — covers PinTheft and ssh-keysign-pwn entry-point cuts.

- [ ] **Step 3.1: Create `packaging/rfxn-modprobe-rds.conf`**

  Full file content:

  ```
  # /etc/modprobe.d/99-rfxn-defense-rds.conf
  # Owned by rfxn-defense-modprobe; do not hand-edit.
  #
  # Conditional: suppressed by %posttrans when an RDS workload is
  # detected (Oracle clusterware, HPC stacks). See
  # /var/lib/rfxn-defense/auto-detect.json.
  #
  # PinTheft (CVE pending) - RDS zerocopy double-free chained to
  # io_uring fixed buffer page-cache overwrite of SUID-root binary.
  # Modules on Ubuntu/Debian/Arch generic kernels - blacklist IS
  # functional. Stock RHEL/Alma/Rocky/Oracle UEK kernels do NOT
  # ship CONFIG_RDS=m; the blacklist is a no-op on those kernels but
  # remains defense in depth against ELRepo kernel-ml/kernel-lt swaps.
  install rds          /bin/false
  install rds_tcp      /bin/false
  install rds_rdma     /bin/false
  blacklist rds
  blacklist rds_tcp
  blacklist rds_rdma
  ```

- [ ] **Step 3.2: Create `packaging/rfxn-systemd-dropin-rds.conf`**

  Full file content:

  ```
  # /etc/systemd/system/<unit>.service.d/13-rfxn-defense-rds.conf
  # Owned by rfxn-defense-systemd; managed by %posttrans detection.
  # Do not hand-edit; %posttrans rewrites this file based on
  # /var/lib/rfxn-defense/auto-detect.json.
  #
  # Suppressed (file removed from /etc/...) when an RDS workload is
  # detected (Oracle clusterware, HPC). PinTheft (CVE pending)
  # closes the AF_RDS socket path for tenant units; rfxn-defense-modprobe
  # blocks module load entirely on hosts where rds.ko is loadable.
  #
  # systemd merges RestrictAddressFamilies across drop-ins; pairing
  # this with the 10-* file's =~AF_ALG ~AF_KEY produces the union
  # =~AF_ALG ~AF_KEY ~AF_RDS at unit start time.
  [Service]
  RestrictAddressFamilies=~AF_RDS
  ```

- [ ] **Step 3.3: Append `kernel.yama.ptrace_scope` + commented io_uring to `packaging/rfxn-sysctl-userns.conf`**

  Append the following block after the existing 3-key body (the existing 3 keys plus 2 new = 5 keys total, all `-`-prefixed):

  ```
  
  # FD-theft / privilege confusion class: ssh-keysign-pwn (CVE-2026-46333).
  # __ptrace_may_access() race exposes root-readable file descriptors
  # (SSH host keys, /etc/shadow) to unprivileged callers via pidfd_getfd
  # on exiting SUID binaries. Yama LSM gates the same permission check,
  # short-circuiting the bug regardless of the mm-NULL fall-through.
  #
  #   0 = unrestricted (RHEL family default - WORST)
  #   1 = parent-child only (Ubuntu/Debian default - PoC bypasses this)
  #   2 = CAP_SYS_PTRACE required (closes the bug; gdb -p as root still works)
  #   3 = ptrace fully off including root (one-way trip until reboot)
  #
  # Default 2: closes pidfd_getfd path without breaking root debugging.
  # Override per-host by dropping a 50-*.conf with a different value
  # (sysctl.d merges in lexicographic order, so higher numbers win).
  -kernel.yama.ptrace_scope            = 2
  
  # PinTheft (CVE pending) secondary mitigation - io_uring disable.
  # Available on Linux 6.6+ only (EL10+, Ubuntu 24.04+). Disabling
  # io_uring breaks containerd/podman runtimes that use it for I/O.
  # SHIPPED COMMENTED-OUT BY DEFAULT. Operator opt-in: uncomment
  # the next line (or drop a higher-numbered sysctl.d file) on hosts
  # confirmed not to require io_uring.
  #
  #   0 = enabled (default)
  #   1 = disabled for new processes
  #   2 = disabled with hard-disable for existing tasks
  #
  #-kernel.io_uring_disabled            = 2
  ```

  **Decision note:** the existing sysctl conf file's `userns` body and this new ptrace/io_uring body live in a single file (not split into `rfxn-sysctl-ptrace.conf`) to avoid creating two `%config(noreplace)` files when the operational hardening grouping is the same: host-wide kernel-LPE-defense sysctls. The `-` prefix per key means unknown keys (Yama-less kernels, io_uring-less kernels) silently skip. If field experience shows operators want per-key gating granularity, split in 3.1.0.

- [ ] **Step 3.4: Append two new audit rules to `packaging/rfxn-defense-audit.rules`**

  Append (preserving existing 3 rules at the bottom of the file; existing rules will get their keys updated in Phase 5):

  ```
  
  ## PinTheft (CVE pending): unprivileged AF_RDS socket creation. RDS is
  ## the entry point for the RDS zerocopy double-free chained to
  ## io_uring fixed buffers. AF_RDS=21 per <linux/socket.h>.
  -a always,exit -F arch=b64 -S socket -F a0=21 -F auid>=1000 -F auid!=-1 -k rfxn_afrds
  
  ## ssh-keysign-pwn (CVE-2026-46333): unprivileged pidfd_getfd().
  ## Public PoC needs 100-2000 spawns per success; this rule fires
  ## loudly during exploitation attempts. Syscall referenced by
  ## NUMERIC value 438 (b64) rather than name 'pidfd_getfd': EL7+EL8
  ## audit-userspace do not recognise the name. The numeric form
  ## parses cleanly on every EL kernel-userspace combination.
  -a always,exit -F arch=b64 -S 438 -F auid>=1000 -F auid!=-1 -k rfxn_pidfd_getfd
  ```

- [ ] **Step 3.5: Add `~AF_RDS` to systemd 10-* always-on drop-in**

  In `packaging/rfxn-systemd-dropin.conf`, the `RestrictAddressFamilies=~AF_ALG ~AF_KEY` line becomes:

  ```
  RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RDS
  ```

  Also extend the explanatory header comment block to mention AF_RDS (PinTheft entry point on EL10/Ubuntu 24.04+ where io_uring is present).

  In `packaging/rfxn-systemd-dropin-containers.conf`, the equivalent `RestrictAddressFamilies=~AF_ALG ~AF_RXRPC ~AF_KEY` line becomes:

  ```
  RestrictAddressFamilies=~AF_ALG ~AF_RXRPC ~AF_KEY ~AF_RDS
  ```

  **Decision note:** AF_RDS is added to the ALWAYS-ON 10-* drop-in (not a conditional 13-* file like `dropin-rds.conf`) because the AF_RDS socket has no legitimate use in the five tenant units (`user@`, `sshd`, `cron`, `crond`, `atd`). The conditional 13-* file is reserved for container-runtime daemons opting out via the example shipping in Phase 4.

  Re-reading this — there's a contradiction with Step 3.2 which created `rfxn-systemd-dropin-rds.conf` as a conditional 13-* drop-in. Resolving: keep the 13-* file shipped as a TEMPLATE under `/usr/share/rfxn-defense/conditional/systemd/` (operator can stage manually on container-runtime units), but do NOT install it to tenant units' `.service.d/` by default — the 10-* always-on cut covers tenant units. The conditional 13-* file exists for the same reason the existing 12-* (rxrpc-af) does: ship a template body that detect.sh can stage if a new use-case arrives. For v3.0.0, the 13-* template is opt-in via operator copy; detect.sh does NOT auto-stage it.

  Implication for Phase 4 spec: the 13-* file ships in the template directory (`/usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf`) but is NOT in detect.sh's apply_systemd() loop. Phase 6 docs document the operator copy command.

- [ ] **Step 3.6: Create new `.repo` file at `packaging/rfxn-defense.repo`**

  Full content:

  ```
  # /etc/yum.repos.d/rfxn-defense.repo
  #
  # DNF/YUM repository for the rfxn-defense packages (v3.0.0+).
  # Hosted on GitHub Pages; RPMs and repodata served directly by the
  # rfxn/copyfail repository (same gh-pages tree as the legacy
  # copyfail.repo - one published baseurl serves both repo files).
  #
  # One repo definition works for EL7, EL8, EL9, and EL10: $releasever
  # expands to the major release number on RHEL/Alma/Rocky/CentOS Stream.
  #
  # Install:
  #   curl -sSL https://rfxn.github.io/copyfail/rfxn-defense.repo \
  #     | sudo tee /etc/yum.repos.d/rfxn-defense.repo
  #   sudo dnf install -y rfxn-defense
  #
  # After install, activate the LD_PRELOAD shim explicitly:
  #   sudo /usr/sbin/rfxn-shim-enable
  #
  # Upgrading from copyfail-defense (v2.0.x):
  #   sudo dnf upgrade -y rfxn-defense
  #   # Obsoletes/Provides metadata performs the rename automatically.
  #
  # The legacy copyfail.repo on the same gh-pages host still works for
  # 3.0.x compatibility; dnf will see this repo's name='rfxn-defense'
  # and the legacy repo's name='copyfail' as duplicate baseurl entries
  # (RPM resolves the rfxn-defense Provides chain regardless).
  #
  # Signing key fingerprint (1.0.1+; unchanged across the rename):
  #   6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
  
  [rfxn-defense]
  name=rfxn-defense (EL$releasever)
  baseurl=https://rfxn.github.io/copyfail/repo/$releasever/$basearch/
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=https://rfxn.github.io/copyfail/RPM-GPG-KEY-rfxn
  metadata_expire=1h
  skip_if_unavailable=1
  ```

- [ ] **Step 3.7: Create `packaging/RPM-GPG-KEY-rfxn`**

  Same key bytes as `packaging/RPM-GPG-KEY-copyfail`. Use a literal copy (not a symlink in the source tree — symlinks in `packaging/` confuse `rpmbuild -bs` source archiving on some hosts).

  ```bash
  cp packaging/RPM-GPG-KEY-copyfail packaging/RPM-GPG-KEY-rfxn
  ```

  Verify the fingerprint matches (no key generation, just bytes):

  ```bash
  gpg --import-options show-only --import < packaging/RPM-GPG-KEY-rfxn 2>&1 | grep -oE '[0-9A-F]{4}( [0-9A-F]{4}){9}' | head -1
  # expect: 6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
  ```

- [ ] **Step 3.8: Run completeness verification**

  ```bash
  test -f packaging/rfxn-modprobe-rds.conf && \
    test -f packaging/rfxn-systemd-dropin-rds.conf && \
    test -f packaging/rfxn-defense.repo && \
    test -f packaging/RPM-GPG-KEY-rfxn && \
    echo "new files present"
  # expect: new files present
  ```

  ```bash
  grep -cE '^install +(rds|rds_tcp|rds_rdma) +/bin/false' packaging/rfxn-modprobe-rds.conf
  # expect: 3
  ```

  ```bash
  grep -q 'kernel.yama.ptrace_scope' packaging/rfxn-sysctl-userns.conf && \
    grep -q '#-kernel.io_uring_disabled' packaging/rfxn-sysctl-userns.conf && \
    echo "ptrace + io_uring stanza present"
  # expect: ptrace + io_uring stanza present
  ```

  ```bash
  grep -E '^RestrictAddressFamilies=' packaging/rfxn-systemd-dropin.conf
  # expect: RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RDS
  ```

  ```bash
  grep -cE '^-a always,exit .* -k rfxn_(afrds|pidfd_getfd)' packaging/rfxn-defense-audit.rules
  # expect: 2
  ```

  ```bash
  cmp -s packaging/RPM-GPG-KEY-copyfail packaging/RPM-GPG-KEY-rfxn && echo "gpg-key bytes match"
  # expect: gpg-key bytes match
  ```

- [ ] **Step 3.9: Commit**

  ```bash
  git add packaging/rfxn-modprobe-rds.conf packaging/rfxn-systemd-dropin-rds.conf \
          packaging/rfxn-defense.repo packaging/RPM-GPG-KEY-rfxn
  git add -u packaging/rfxn-sysctl-userns.conf packaging/rfxn-defense-audit.rules \
              packaging/rfxn-systemd-dropin.conf packaging/rfxn-systemd-dropin-containers.conf
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 3: new defensive sources for PinTheft + ssh-keysign-pwn

  Adds rfxn-modprobe-rds.conf (PinTheft rds/rds_tcp/rds_rdma blacklist),
  rfxn-systemd-dropin-rds.conf (template for container-runtime opt-in),
  kernel.yama.ptrace_scope=2 sysctl key (FD-theft class), commented-out
  kernel.io_uring_disabled=2 sysctl key (operator opt-in), two new
  auditd rules (rfxn_afrds for AF_RDS=21 socket, rfxn_pidfd_getfd for
  syscall 438), AF_RDS added to always-on systemd 10-* drop-in. Also
  ships rfxn-defense.repo and RPM-GPG-KEY-rfxn alongside the legacy
  copyfail-named filenames during 3.0.x line.

  pidfd_getfd uses NUMERIC syscall ref (438) since EL7+EL8 audit
  userspace does not recognise the name string.
  EOF
  )"
  ```

---

### Phase 4: Spec v3.0.0 rewrite

Rewrite `packaging/rfxn-defense.spec` end-to-end: rename `Name:` and all 6 subpackage stanzas, bump `Version: 3.0.0`, add the new Sources (rds modprobe, rds systemd template, ptrace sysctl key — wait, ptrace lands in the existing rfxn-sysctl-userns.conf, not a separate file; only the rds files are new Sources), update `Source0` tarball, update every `%install` and `%files` path, add new `%pretrans meta` path-migration scriptlet block, double the `Obsoletes:`/`Provides:` chain (carry both `afalg-defense` and `copyfail-defense`), add `pintheft` and `keysign-pwn` to %description text, append CHANGELOG entry.

**Files:**
- Modify: `packaging/rfxn-defense.spec` (full structural rewrite — Name, Version, all %package stanzas, Sources, Requires, Obsoletes/Provides chains, %install, %files, %pretrans, %posttrans, %postun, %changelog)

- **Mode**: serial-agent (single file, one engineer, large coordinated change)
- **Accept**:
  - `grep -c '^Name:           rfxn-defense' packaging/rfxn-defense.spec` returns 1
  - `grep -c '^Version:        3.0.0' packaging/rfxn-defense.spec` returns 1
  - `grep -c '^Obsoletes:      copyfail-defense' packaging/rfxn-defense.spec` returns ≥6 (meta + 5 subpackages with the obsolete chain; -audit was new in v2.0.2 so it has only afalg + copyfail entries? wait, -audit was new in 2.0.2 under copyfail-defense — no afalg-defense-audit existed — so -audit has only the copyfail-defense-audit Obsoletes; -sysctl same. So count is 6 not 7. Verify in spec.)
  - `grep -c '^Obsoletes:      afalg-defense' packaging/rfxn-defense.spec` returns ≥4 (meta + shim + modprobe + systemd + auditor existed under afalg-defense; sysctl and audit are 2.0.2-new so no afalg-defense-* predecessor)
  - `grep -c 'Source.*:.* +rfxn-' packaging/rfxn-defense.spec` returns ≥15 (existing 13 Sources + new RDS modprobe Source + new RDS systemd template Source; tarball Source0 = rfxn-defense-3.0.0.tar.gz; total 16)
  - `grep -c '/var/lib/copyfail-defense\|/etc/copyfail/\|copyfail-defense-' packaging/rfxn-defense.spec` returns 0 EXCEPT inside %pretrans path-migration scriptlets and Obsoletes/Provides lines (allowed — those refer to legacy paths/names by design)
  - `rpmbuild -bs --define '_topdir /tmp/rfxn-srpm' --define 'dist .el8' packaging/rfxn-defense.spec` succeeds (SRPM builds clean from rewritten spec) — requires the tarball staged at `_topdir/SOURCES/`, deferred to mock build phase; this phase does syntax-only validation via `rpmspec`.
- **Test**:
  - `rpmspec -P packaging/rfxn-defense.spec | head -50` (no parse error; `rpmspec` expands macros)
  - `rpmspec -q --srpm packaging/rfxn-defense.spec` (returns one line: `rfxn-defense-3.0.0-1.<dist>.src`)
  - `rpmspec -q packaging/rfxn-defense.spec` lists 7 subpackages: `rfxn-defense`, `rfxn-defense-shim`, `rfxn-defense-modprobe`, `rfxn-defense-systemd`, `rfxn-defense-auditor`, `rfxn-defense-sysctl`, `rfxn-defense-audit`
  - The mock canary in Phase 12 is the real test of build success.
- **Edge cases**:
  - **Epoch**: stays at `Epoch: 1`. `3.0.0 > 2.0.2` sorts cleanly. Do NOT bump epoch.
  - **dist tag**: spec keeps `Release: 1%{?dist}` — mock supplies `%{dist}` per EL.
  - **Tarball naming**: `Source0: rfxn-defense-%{version}.tar.gz` (new name). `%setup -q -n rfxn-defense-%{version}` follows. The Phase 12 build invocation must `git archive --prefix=rfxn-defense-3.0.0/ ...` to produce the correctly-named tarball; spec previously used `upstream_name=copyfail` macro which produced `copyfail-%{version}.tar.gz` — this macro updates to `upstream_name=rfxn-defense` (or simply uses `%{name}` literally if no upstream/RPM-name divergence remains).
  - **`%pretrans meta` path migration**: A new scriptlet block, NOT present in v2.0.2, that moves `/var/lib/copyfail-defense/auto-detect.json` → `/var/lib/rfxn-defense/auto-detect.json` and `/etc/copyfail/force-full` → `/etc/rfxn-defense/force-full` on first install of v3.0.0 over a v2.0.x host. Conditional on `rpm -q copyfail-defense` returning success at scriptlet entry time. Must run BEFORE `%pretrans modprobe`/`systemd`/`sysctl` so those scriptlets see the migrated state.
  - **Detect.sh migration**: the legacy `/usr/libexec/copyfail-defense/detect.sh` path is still present until RPM removes the old `copyfail-defense-modprobe` package mid-transaction. The new `/usr/libexec/rfxn-defense/detect.sh` is installed by the new `rfxn-defense` (meta) package. Spec scriptlets must reference the NEW path `/usr/libexec/rfxn-defense/detect.sh`.
  - **`%pretrans modprobe`/`systemd`/`sysctl` v2.0.0→2.0.1 monolithic-file rename**: existing scriptlets handle the v2.0.0 → v2.0.1 monolithic-file rename. Those scriptlets compare against `rpm -q copyfail-defense-modprobe --qf '%%{version}' | grep -q '^2\.0\.0$'`. In v3.0.0, the rpm-q target package is GONE from the host post-upgrade (replaced by `rfxn-defense-modprobe`). Solution: drop the v2.0.0-monolithic-handling block from v3.0.0's `%pretrans` (the rename is several releases old; any host still on v2.0.0 monolithic files in 2026-05 is a long-tail outlier that operator handles manually).
  - **Removing old `%pretrans` blocks**: do NOT remove the existing v2.0.0→2.0.1 migration scriptlet block in this phase. Replace it with the v2.0.x → v3.0.0 path-migration block. This is a one-version migration window; v3.1.0 will drop the v3.0.0 migration block in turn.
  - **`%files` audit subpackage attrs**: existing `%attr(0640, root, root)` preserved on the renamed audit rules file.
  - **EL7 conditional `BuildRequires`**: EL7 stock has no `python3` package by default — need `BuildRequires: python3` with EPEL repo present at build time. Spec is unconditional `BuildRequires: python3`; mock chroot config (Phase 12) provides EPEL. Do NOT add `%if 0%{?rhel} == 7` conditionals in the spec; let mock provide the deps.
- **Regression-case**: `packaging/test-repo.sh::check-upgrade-path` — security — covers RPM rename via Obsoletes/Provides; ssh-keysign-pwn coverage gated by new spec Sources (no CVE assigned for PinTheft, only the public-PoC ref).

- [ ] **Step 4.1: Update spec header macros and metadata**

  Replace the existing macro/metadata block (lines 1-21 in v2.0.2):

  Old:
  ```
  %global         _hardened_build         1
  %global         debug_package           %{nil}
  %global         __os_install_post       %{nil}
  %global         upstream_name           copyfail

  Name:           copyfail-defense
  Epoch:          1
  Version:        2.0.2
  Release:        1%{?dist}
  Summary:        Defense-in-depth toolkit for the Copy Fail bug class
  ```

  New:
  ```
  %global         _hardened_build         1
  %global         debug_package           %{nil}

  # Auditor is shipped as plain text (operator inspectable). Disable
  # post-install processing that would byte-compile or strip it.
  %global         __os_install_post       %{nil}

  # v3.0.0 rename: copyfail-defense -> rfxn-defense. Family broadens
  # from Copy-Fail-class only to the kernel-LPE umbrella covering
  # both Copy Fail (cf1/cf2/df-rxrpc/fragnesia/pintheft/dirtydecrypt)
  # AND FD-theft (ssh-keysign-pwn) primitives.
  #
  # Tarball name follows %{name} now that upstream and RPM family
  # share a name. The upstream_name macro is retained for spec
  # diff-clarity but resolves to %{name}.
  %global         upstream_name           rfxn-defense

  Name:           rfxn-defense
  Epoch:          1
  Version:        3.0.0
  Release:        1%{?dist}
  Summary:        Defense-in-depth toolkit for the Copy Fail + FD-theft Linux kernel-LPE bug classes
  ```

- [ ] **Step 4.2: Update `Source0` and add new Sources**

  Replace:
  ```
  Source0:        %{upstream_name}-%{version}.tar.gz
  Source1:        copyfail-shim-enable
  Source2:        copyfail-shim-disable
  Source3:        copyfail-modprobe-cf1.conf
  Source4:        copyfail-systemd-dropin.conf
  Source5:        copyfail-systemd-dropin-containers.conf
  Source6:        copyfail-modprobe-cf2-xfrm.conf
  Source7:        copyfail-modprobe-rxrpc.conf
  Source8:        copyfail-systemd-dropin-userns.conf
  Source9:        copyfail-defense-detect.sh
  Source10:       copyfail-redetect
  Source11:       copyfail-systemd-dropin-rxrpc-af.conf
  Source12:       copyfail-sysctl-userns.conf
  Source13:       copyfail-defense-audit.rules
  ```

  With:
  ```
  Source0:        %{upstream_name}-%{version}.tar.gz
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
  # v3.0.0 additions for PinTheft + ssh-keysign-pwn coverage:
  Source14:       rfxn-modprobe-rds.conf
  Source15:       rfxn-systemd-dropin-rds.conf
  ```

- [ ] **Step 4.3: Update meta-package Requires + Obsoletes/Provides chain**

  Inside the meta-package preamble (after `Source15`), replace meta `Requires:` block and `Obsoletes:`/`Provides:` lines:

  ```
  Requires:       %{name}-shim     = %{epoch}:%{version}-%{release}
  Requires:       %{name}-modprobe = %{epoch}:%{version}-%{release}
  Requires:       %{name}-systemd  = %{epoch}:%{version}-%{release}
  Requires:       %{name}-auditor  = %{epoch}:%{version}-%{release}
  Requires:       %{name}-sysctl   = %{epoch}:%{version}-%{release}
  Recommends:     %{name}-audit    = %{epoch}:%{version}-%{release}

  # v3.0.0 rename: copyfail-defense -> rfxn-defense. Compat chain
  # retained through 3.0.x; dropped in 3.1.0. Carrying both
  # copyfail-defense AND afalg-defense lines is cheap insurance for
  # the rare host that skipped v2.0.x entirely.
  Obsoletes:      copyfail-defense < %{epoch}:%{version}-%{release}
  Provides:       copyfail-defense = %{epoch}:%{version}-%{release}
  Obsoletes:      afalg-defense    < %{epoch}:%{version}-%{release}
  Provides:       afalg-defense    = %{epoch}:%{version}-%{release}
  ```

- [ ] **Step 4.4: Apply the per-subpackage Obsoletes/Provides chain**

  For each of the 6 subpackages (`shim`, `modprobe`, `systemd`, `auditor`, `sysctl`, `audit`), replace the existing `Obsoletes:`/`Provides:` block:

  - **shim**: add `Obsoletes: copyfail-defense-shim < ...` + `Provides:` (existing afalg-defense-shim lines preserved)
  - **modprobe**: ADD afalg-defense-modprobe Obsoletes/Provides (was missing in v2.0.0 — it was a new subpackage); ADD copyfail-defense-modprobe Obsoletes/Provides
  - **systemd**: same as modprobe (was new in v2.0.0; ADD afalg + ADD copyfail)
  - **auditor**: ADD copyfail-defense-auditor; existing afalg-defense-auditor preserved
  - **sysctl**: ADD copyfail-defense-sysctl (was new in v2.0.2; no afalg-defense-sysctl ever shipped)
  - **audit**: ADD copyfail-defense-audit (was new in v2.0.2; no afalg-defense-audit ever shipped)

  Per-subpackage shape:

  ```
  Obsoletes:      copyfail-defense-modprobe < %{epoch}:%{version}-%{release}
  Provides:       copyfail-defense-modprobe = %{epoch}:%{version}-%{release}
  Obsoletes:      afalg-defense-modprobe    < %{epoch}:%{version}-%{release}
  Provides:       afalg-defense-modprobe    = %{epoch}:%{version}-%{release}
  ```

  For `sysctl` and `audit` (no afalg-defense predecessor):

  ```
  Obsoletes:      copyfail-defense-sysctl < %{epoch}:%{version}-%{release}
  Provides:       copyfail-defense-sysctl = %{epoch}:%{version}-%{release}
  ```

- [ ] **Step 4.5: Update %description text block (meta + 6 subpackages)**

  Meta `%description`: rewrite to introduce both bug classes:

  ```
  %description
  Defense-in-depth toolkit for two Linux kernel local privilege
  escalation bug classes:

  Copy Fail class (page-cache overwrite of root-readable file ->
  privileged consumer trusts cache -> LPE):
    - cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
    - cf2 (CVE-2026-43284) - xfrm-ESP skip_cow / Dirty Frag-ESP
    - Dirty Frag-RxRPC (CVE-2026-43500) - rxrpc pcbc(fcrypt) on splice'd frag
    - Fragnesia (no CVE yet) - ESP-in-TCP same surface as CVE-2026-43284
    - PinTheft (CVE pending) - RDS zerocopy double-free + io_uring
      fixed-buffer page-cache overwrite of SUID binary
    - DirtyDecrypt (CVE-2026-31635) - CONFIG_RXGK in rxrpc; covered
      by the rxrpc cuts shipped for Dirty Frag-RxRPC

  FD-theft class (privilege confusion via SUID exit race - info
  disclosure -> root):
    - ssh-keysign-pwn (CVE-2026-46333) - pidfd_getfd steals open fd
      from exiting SUID; targets ssh-keysign (SSH host keys) and
      chage (/etc/shadow)

  This metapackage installs six subpackages:
    - rfxn-defense-shim      - LD_PRELOAD AF_ALG block
    - rfxn-defense-modprobe  - kernel-module entry-point cuts
    - rfxn-defense-systemd   - per-unit RestrictAddressFamilies/Namespaces
    - rfxn-defense-auditor   - read-only host posture auditor
    - rfxn-defense-sysctl    - host-wide userns + ptrace_scope sysctls
    - rfxn-defense-audit     - auditd tripwire rules (soft-dep)

  The shim is INSTALLED but NOT enabled by this package. To enable it
  system-wide:

      /usr/sbin/rfxn-shim-enable

  To disable:

      /usr/sbin/rfxn-shim-disable

  v3.0.0 renames copyfail-defense -> rfxn-defense to broaden the
  umbrella from Copy-Fail-class only to the full kernel-LPE bug-class
  surface. dnf upgrade is transparent via Obsoletes/Provides.
  The detection report at /var/lib/rfxn-defense/auto-detect.json shows
  what ran and what was suppressed; /usr/sbin/rfxn-redetect re-runs
  detection on demand. Override auto-detection by creating
  /etc/rfxn-defense/force-full before install.
  ```

  For each per-subpackage `%description`, rewrite to update package names, paths, and (for `-modprobe`, `-systemd`, `-sysctl`, `-audit`) describe the new PinTheft and ssh-keysign-pwn coverage where applicable. The detailed text mirrors v2.0.2 but with rfxn-* paths and the new bug-class additions.

  **Detailed -modprobe %description additions**: include `PinTheft (CVE pending): rds, rds_tcp, rds_rdma` in the bug-class list. Mention the "RHEL CONFIG_RDS not built" caveat — modprobe cut is a no-op on stock RHEL/Alma/Rocky/Oracle UEK, functional on Ubuntu/Debian/Arch generic kernels and on RHEL hosts running ELRepo `kernel-ml`.

  **Detailed -systemd %description additions**: include `~AF_RDS` in the RestrictAddressFamilies value list and mention PinTheft as the closing class.

  **Detailed -sysctl %description additions**: add `kernel.yama.ptrace_scope = 2` and commented `kernel.io_uring_disabled = 2` to the key list. Describe ssh-keysign-pwn closure rationale.

  **Detailed -audit %description additions**: add `rfxn_afrds` (PinTheft) and `rfxn_pidfd_getfd` (ssh-keysign-pwn) to the keys list. Update the audit-key rename note: "v3.0.0 renames copyfail_afalg -> rfxn_afalg (etc.); see CHANGELOG for full migration table."

- [ ] **Step 4.6: Update `%install` block — paths and new Sources**

  Replace every `/etc/modprobe.d/99-copyfail-defense-...` → `/etc/modprobe.d/99-rfxn-defense-...`. Replace every `/usr/share/copyfail-defense/conditional/` → `/usr/share/rfxn-defense/conditional/`. Replace every `/usr/libexec/copyfail-defense/` → `/usr/libexec/rfxn-defense/`. Replace `/var/lib/copyfail-defense` → `/var/lib/rfxn-defense`. Replace `/etc/copyfail` → `/etc/rfxn-defense`. Replace sbin install lines: `copyfail-shim-enable` → `rfxn-shim-enable`, `copyfail-shim-disable` → `rfxn-shim-disable`, `copyfail-redetect` → `rfxn-redetect`, `copyfail-local-check` → `rfxn-local-check`.

  Add two new install lines for the v3.0.0 Sources:

  ```
  # PinTheft modprobe cut (conditional template)
  install -m 0644 %{SOURCE14} \
      %{buildroot}/usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rds.conf

  # PinTheft systemd template (operator-staged for container runtimes;
  # NOT placed on tenant units by detect.sh — AF_RDS lives in the
  # always-on 10-* drop-in via Source4).
  install -m 0644 %{SOURCE15} \
      %{buildroot}/usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf
  ```

  Add compat sbin symlinks for the 3.0.x line so existing operator one-liners (`copyfail-shim-enable`, `copyfail-local-check`, etc.) keep working. Symlinks under `%{_sbindir}/`:

  ```
  # Compatibility symlinks: old binary names -> new binary names.
  # Dropped in 3.1.0 per FOLLOWUPS.md "v3.1.0 forward-cleanup".
  ln -sf rfxn-shim-enable    %{buildroot}%{_sbindir}/copyfail-shim-enable
  ln -sf rfxn-shim-disable   %{buildroot}%{_sbindir}/copyfail-shim-disable
  ln -sf rfxn-redetect       %{buildroot}%{_sbindir}/copyfail-redetect
  ln -sf rfxn-local-check    %{buildroot}%{_sbindir}/copyfail-local-check
  ```

  **Decision note:** the symlinks are deliberate. v2.0.0 dropped `afalg-shim-enable` (the v1.0.x name) without a symlink and operator Ansible scripts that hard-coded the old binary name broke until updated. Three-version-window compat keeps the rename ergonomic for the fleet.

- [ ] **Step 4.7: Update `%files` block — paths and new ownership**

  Sweep every path in `%files` (meta + 6 subpackages) to use `/etc/modprobe.d/99-rfxn-defense-*.conf`, `/etc/systemd/system/*.service.d/{10,12,15}-rfxn-defense-*.conf`, `/etc/sysctl.d/99-rfxn-defense-*.conf`, `/etc/audit/rules.d/99-rfxn-defense.rules`, `/usr/libexec/rfxn-defense/detect.sh`, `/usr/share/rfxn-defense/conditional/{modprobe,systemd,sysctl}/...`, `/var/lib/rfxn-defense`, `/etc/rfxn-defense`, `%{_sbindir}/rfxn-shim-{enable,disable}`, `%{_sbindir}/rfxn-redetect`, `%{_sbindir}/rfxn-local-check`, `%{_libdir}/no-afalg.so`.

  Add the new template files to `%files modprobe`:
  ```
  /usr/share/rfxn-defense/conditional/modprobe/99-rfxn-defense-rds.conf
  ```

  Add the new template to `%files systemd`:
  ```
  /usr/share/rfxn-defense/conditional/systemd/13-rfxn-defense-rds.conf
  ```

  Add the 4 compat symlinks to the meta `%files` (`shim` package owns the rfxn-shim-* binaries; meta `%files` owns the legacy-name compat symlinks since they cross subpackage boundaries):

  ```
  # Compatibility symlinks (dropped in 3.1.0).
  %{_sbindir}/copyfail-shim-enable
  %{_sbindir}/copyfail-shim-disable
  %{_sbindir}/copyfail-redetect
  %{_sbindir}/copyfail-local-check
  ```

  Wait — this is wrong. The `copyfail-shim-{enable,disable}` symlinks belong in `%files shim` since they target binaries owned by `-shim`. The `copyfail-redetect` symlink belongs in `%files` (meta, owns rfxn-redetect). The `copyfail-local-check` symlink belongs in `%files auditor`. Allocate per the owning subpackage:

  - `%files shim`: `%{_sbindir}/copyfail-shim-enable`, `%{_sbindir}/copyfail-shim-disable`
  - `%files` (meta): `%{_sbindir}/copyfail-redetect`
  - `%files auditor`: `%{_sbindir}/copyfail-local-check`

- [ ] **Step 4.8: Add new `%pretrans` meta path-migration scriptlet**

  Insert before the existing `%pretrans modprobe`:

  ```
  # ---------------------------------------------------------------------------
  # %pretrans meta - v2.0.x -> v3.0.0 path migration.
  # Migrates the auto-detect.json state file and force-full sentinel to
  # new paths. RPM does NOT guarantee meta %pretrans runs before subpackage
  # %pretrans; in fact, since meta Requires its subpackages, RPM's
  # dependency-driven ordering typically runs subpackage scriptlets first.
  # That ordering does NOT matter here: this block touches /var/lib/ and
  # /etc/<dir>/ paths that are independent of the subpackage %pretrans
  # rename targets (/etc/modprobe.d/, /etc/systemd/system/.../, /etc/sysctl.d/,
  # /etc/audit/rules.d/). No state shared across the two scriptlet domains.
  #
  # Conditional on copyfail-defense being installed at scriptlet entry
  # time (v2.0.x -> v3.0.0 upgrade). On fresh installs the rpm-q
  # returns non-zero and the block no-ops.
  %pretrans
  if rpm -q copyfail-defense >/dev/null 2>&1; then
      # Migrate state file. The new dir is installed below by the meta
      # package %files - create it here in case the meta package was
      # already removed before this scriptlet ran.
      install -d -m 0755 /var/lib/rfxn-defense 2>/dev/null || true
      if [ -f /var/lib/copyfail-defense/auto-detect.json ] && \
         [ ! -f /var/lib/rfxn-defense/auto-detect.json ]; then
          mv -f /var/lib/copyfail-defense/auto-detect.json \
                /var/lib/rfxn-defense/auto-detect.json
          logger -t rfxn-defense -p authpriv.info \
              "pretrans meta: migrated /var/lib/copyfail-defense/auto-detect.json -> /var/lib/rfxn-defense/" \
              2>/dev/null || true
      fi
      # Remove empty old dir (silent failure is fine).
      rmdir /var/lib/copyfail-defense 2>/dev/null || true

      # Migrate force-full sentinel.
      install -d -m 0755 /etc/rfxn-defense 2>/dev/null || true
      if [ -f /etc/copyfail/force-full ] && \
         [ ! -f /etc/rfxn-defense/force-full ]; then
          mv -f /etc/copyfail/force-full /etc/rfxn-defense/force-full
          logger -t rfxn-defense -p authpriv.info \
              "pretrans meta: migrated /etc/copyfail/force-full -> /etc/rfxn-defense/" \
              2>/dev/null || true
      fi
      rmdir /etc/copyfail 2>/dev/null || true
  fi
  exit 0
  ```

- [ ] **Step 4.9: Replace v2.0.0-monolithic-handling `%pretrans` blocks**

  In `%pretrans modprobe` and `%pretrans systemd`, replace the existing v2.0.0 monolithic-file rename logic (which targets `rpm -q copyfail-defense-modprobe --qf '%%{version}' | grep -q '^2\.0\.0$'`) with v2.0.x → v3.0.0 path migration:

  ```
  # %pretrans modprobe - v2.0.x -> v3.0.0 path migration.
  # Move /etc/modprobe.d/99-copyfail-defense-*.conf -> 99-rfxn-defense-*.conf
  # so the v2.0.x %config(noreplace) files don't ghost as ".rpmsave" after
  # this upgrade. We control the move because the file content is
  # operator-edit-safe (cmp-and-skip applies in detect.sh; not RPM-managed).
  %pretrans modprobe
  for f in cf1 cf2-xfrm rxrpc; do
      old=/etc/modprobe.d/99-copyfail-defense-${f}.conf
      new=/etc/modprobe.d/99-rfxn-defense-${f}.conf
      if [ -f "$old" ] && [ ! -f "$new" ]; then
          mv -f "$old" "$new"
          logger -t rfxn-defense -p authpriv.info \
              "pretrans modprobe: migrated $old -> $new" \
              2>/dev/null || true
      fi
  done
  exit 0
  ```

  Equivalent block for `%pretrans systemd` covers `10-*`, `12-*`, `15-*` drop-in files across the 5 tenant units. Same logic for `%pretrans sysctl` (single file `99-copyfail-defense-userns.conf` → `99-rfxn-defense-userns.conf`).

  Add a NEW `%pretrans audit`:

  ```
  %pretrans audit
  old=/etc/audit/rules.d/99-copyfail-defense.rules
  new=/etc/audit/rules.d/99-rfxn-defense.rules
  if [ -f "$old" ] && [ ! -f "$new" ]; then
      mv -f "$old" "$new"
      logger -t rfxn-defense -p authpriv.info \
          "pretrans audit: migrated $old -> $new" 2>/dev/null || true
  fi
  exit 0
  ```

  **Note on `-p /bin/bash`**: every `%pretrans` and `%posttrans` scriptlet that uses bash-specific syntax (process substitution `2> >(...)`, `[[ ]]`, etc.) must declare `-p /bin/bash` per memory `project_v2_0_1_2_shipped`. The v3.0.0 `%pretrans` blocks above use only POSIX `sh` syntax — they do NOT need `-p /bin/bash`. The existing `%posttrans` blocks that DO use bash-specific syntax MUST keep their `-p /bin/bash` declarations.

- [ ] **Step 4.10: Update detect.sh path references in scriptlets**

  Every `/usr/libexec/copyfail-defense/detect.sh` → `/usr/libexec/rfxn-defense/detect.sh` in the spec's scriptlet bodies.

  Every `logger -t copyfail-defense` → `logger -t rfxn-defense` in scriptlet bodies.

  Inline fallback `rm -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf` → `rm -f /etc/modprobe.d/99-rfxn-defense-cf2-xfrm.conf` (in `%postun modprobe`'s detect.sh-missing fallback branch). Same for rxrpc, systemd 12-*, 15-*, sysctl userns, audit rules.

- [ ] **Step 4.11: Append v3.0.0 CHANGELOG entry**

  Insert at the top of `%changelog`:

  ```
  * Thu May 21 2026 rfxn.com <proj@rfxn.com> - 1:3.0.0-1
  - v3.0.0 renames the copyfail-defense package family to rfxn-defense
    as the umbrella for kernel-LPE-class defense (broader scope than
    the Copy Fail bug class alone). dnf upgrade is transparent via
    Obsoletes/Provides; existing copyfail-defense* installs roll over
    automatically. Compat sbin symlinks (copyfail-shim-enable etc.)
    ship for the 3.0.x line; dropped in 3.1.0.
  - New defensive primitive: PinTheft (CVE pending) - RDS zerocopy
    double-free chained to io_uring fixed-buffer page-cache overwrite
    of SUID-root binary. Coverage:
      * rfxn-defense-modprobe blacklists rds, rds_tcp, rds_rdma
        (conditional template; suppressed on RDS-workload hosts)
      * rfxn-defense-systemd adds ~AF_RDS to the always-on 10-* drop-in
        for the 5 tenant units
      * rfxn-defense-audit adds rfxn_afrds rule for socket(AF_RDS=21)
        by auid>=1000 (b64 native ABI)
      * rfxn-defense-sysctl ships commented-out kernel.io_uring_disabled=2
        as an operator opt-in (active on Linux 6.6+)
    Stock RHEL/Alma/Rocky/Oracle UEK kernels do NOT compile CONFIG_RDS;
    affected populations are Ubuntu/Debian/Arch and RHEL hosts running
    ELRepo kernel-ml/kernel-lt.
  - New defensive primitive: ssh-keysign-pwn (CVE-2026-46333) -
    __ptrace_may_access() race exposes root-readable file descriptors
    (SSH host keys, /etc/shadow) to unprivileged callers via
    pidfd_getfd on exiting SUID binaries. Coverage:
      * rfxn-defense-sysctl ships kernel.yama.ptrace_scope=2 (closes
        the pidfd_getfd path without breaking root-owned debugging;
        '-'-prefixed so kernels without Yama LSM silently skip)
      * rfxn-defense-audit adds rfxn_pidfd_getfd rule for syscall 438
        by auid>=1000 (b64 native ABI; NUMERIC syscall ref since EL7+EL8
        audit-userspace does not recognise the name string).
    RHEL family default ptrace_scope=0 (worst); Ubuntu/Debian default=1
    (still bypassable). v3.0.0 forces 2 globally.
  - DirtyDecrypt (CVE-2026-31635) - CONFIG_RXGK is the RxRPC key-exchange
    protocol; entry primitive is on AF_RXRPC sockets. Verified during
    Phase 7 of the v3.0.0 plan to be covered incidentally by the existing
    rxrpc modprobe blacklist + AF_RXRPC RestrictAddressFamilies +
    rfxn_afrxrpc audit rule. No new cuts shipped; CHANGELOG cross-stamp
    only (same pattern as Fragnesia under cf2 in v2.0.2).
  - Audit-key rename (operator-visible breaking change):
      copyfail_afalg     -> rfxn_afalg
      copyfail_afkey     -> rfxn_afkey
      copyfail_afrxrpc   -> rfxn_afrxrpc
      (new in v3.0.0)    -> rfxn_afrds (PinTheft AF_RDS)
      (new in v3.0.0)    -> rfxn_pidfd_getfd (ssh-keysign-pwn)
    SIEM operators must update ausearch -k <key> queries before
    deploying v3.0.0. The old copyfail_* keys are NOT present in the
    new rules file; queries for them silently return zero matches.
  - Build target matrix expanded: EL7 added alongside EL8/EL9/EL10.
    EL7 build uses a custom mock chroot (epel-7-x86_64-vault.cfg)
    pointing at vault.centos.org since mainline CentOS 7 mirrors are
    EOL. EL7 stock kernels (3.10) are NOT exposed to PinTheft (no
    io_uring), ssh-keysign-pwn (no pidfd_getfd), or DirtyDecrypt
    (RXGK is newer than 3.10); the rfxn-defense package still installs
    cleanly and provides defense-in-depth value for hosts running
    custom kernels.
  - State path migration: /var/lib/copyfail-defense/auto-detect.json
    -> /var/lib/rfxn-defense/auto-detect.json; /etc/copyfail/force-full
    -> /etc/rfxn-defense/force-full; modprobe/systemd/sysctl/audit
    config files all rename their on-disk filenames. Migration handled
    by %pretrans on first install of v3.0.0 over a v2.0.x host.
  - Compat: ships both packaging/rfxn-defense.repo (new canonical) and
    packaging/copyfail.repo (legacy filename, content unchanged) on
    gh-pages during the 3.0.x line. RPM-GPG-KEY-rfxn ships as a
    duplicate copy of RPM-GPG-KEY-copyfail (same key bytes, same
    fingerprint 6001 1CDC EA2F F52D 975A FDEE 6D30 F32C D5E8 0F80).
  - Documentation: README rebrands to rfxn-defense, adds PinTheft +
    ssh-keysign-pwn rows in coverage matrix, ships full audit-key
    migration table. STATE.md, SPEC.md, BRIEF.md, FOLLOWUPS.md, and
    .rdf/governance/{architecture,conventions,constraints,verification,
    anti-patterns,index}.md all updated for the rename.
  ```

- [ ] **Step 4.12: Run syntactic + structural verification**

  ```bash
  rpmspec -P packaging/rfxn-defense.spec > /tmp/rfxn-spec-parsed.out 2>&1
  echo $?
  # expect: 0
  ```

  ```bash
  rpmspec -q --srpm packaging/rfxn-defense.spec
  # expect: rfxn-defense-3.0.0-1.<dist>.src   (where <dist> is whatever your build host is)
  ```

  ```bash
  rpmspec -q packaging/rfxn-defense.spec | sort
  # expect:
  # rfxn-defense-3.0.0-1.<dist>.x86_64
  # rfxn-defense-audit-3.0.0-1.<dist>.noarch
  # rfxn-defense-auditor-3.0.0-1.<dist>.noarch
  # rfxn-defense-modprobe-3.0.0-1.<dist>.noarch
  # rfxn-defense-shim-3.0.0-1.<dist>.x86_64
  # rfxn-defense-sysctl-3.0.0-1.<dist>.noarch
  # rfxn-defense-systemd-3.0.0-1.<dist>.noarch
  ```

  ```bash
  grep -c '^Obsoletes:      copyfail-defense' packaging/rfxn-defense.spec
  # expect: 7
  ```

  ```bash
  grep -c '^Obsoletes:      afalg-defense' packaging/rfxn-defense.spec
  # expect: 5
  # (meta + shim + modprobe + systemd + auditor; sysctl + audit were
  # both new in v2.0.2 and never had afalg-defense predecessors)
  ```

  ```bash
  grep -E '/(var/lib/copyfail-defense|etc/copyfail)' packaging/rfxn-defense.spec | grep -v 'rpm -q copyfail' | grep -v '/var/lib/copyfail-defense/auto-detect.json' | grep -v '/etc/copyfail/force-full'
  # expect: (empty - the only allowed legacy-path refs are in %pretrans migration blocks)
  ```

  ```bash
  grep -cE 'Source1[0-9]+:' packaging/rfxn-defense.spec
  # expect: 6 (Source10-Source15; the regex requires at least one digit
  # after the '1' so the single-digit Source1: doesn't match)
  ```

- [ ] **Step 4.13: Commit**

  ```bash
  git add -u packaging/rfxn-defense.spec
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 4: rewrite spec for rfxn-defense rename + new coverage

  - Name: rfxn-defense; Version: 3.0.0; Epoch 1 preserved
  - Double Obsoletes/Provides chain (copyfail-defense AND afalg-defense)
    on every applicable subpackage
  - 16 Sources (added Source14 rds modprobe, Source15 rds systemd template)
  - New %pretrans meta: migrates /var/lib/copyfail-defense/ and
    /etc/copyfail/force-full to new paths before any subpackage scriptlet
  - Per-subpackage %pretrans: rename modprobe/systemd/sysctl/audit conf
    files in-place (v2.0.x -> v3.0.0)
  - %description rewrites for meta + 6 subpackages with PinTheft and
    ssh-keysign-pwn coverage
  - Compat sbin symlinks (copyfail-shim-{enable,disable}, copyfail-redetect,
    copyfail-local-check) for the 3.0.x line
  - CHANGELOG entry documenting full rename + new coverage + audit-key
    migration table + EL7 addition
  EOF
  )"
  ```

---

### Phase 5: Audit-key rename + detect.sh RDS workload detection

Two atomic changes that are coupled by the audit-rules file: rename `copyfail_afalg`/`copyfail_afkey`/`copyfail_afrxrpc` → `rfxn_*` in the three existing rule lines, AND extend detect.sh with `detect_rds_workload()` + `apply_rds_modprobe()` so the RDS modprobe template (Phase 3 shipped the template, Phase 4 packaged it) actually gets staged on RDS-free hosts and suppressed on Oracle clusterware / HPC hosts.

**Files:**
- Modify:
  - `packaging/rfxn-defense-audit.rules` (rename 3 rule keys; documentation `ausearch -k` lines already updated in Phase 2)
  - `packaging/rfxn-defense-detect.sh` (add `RDS_WORKLOAD_PRESENT`, `RDS_WORKLOAD_SIGNALS`, `detect_rds_workload()`, `SUPPRESS_MODPROBE_RDS` decision logic, `apply_rds_modprobe()` function, `teardown_rds_modprobe()`, JSON state additions, log statements)

- **Mode**: serial-agent (single engineer; audit-rules + detect.sh are tightly coupled by the new `applied.modprobe_rds` JSON field)
- **Accept**:
  - `grep -c 'copyfail_af' packaging/rfxn-defense-audit.rules` returns 0 (zero stale copyfail_* keys remain)
  - `grep -cE '^-a always,exit .* -k rfxn_(afalg|afkey|afrxrpc|afrds|pidfd_getfd)' packaging/rfxn-defense-audit.rules` returns 5 (3 renamed existing + 2 new from Phase 3)
  - `grep -q 'detect_rds_workload' packaging/rfxn-defense-detect.sh` returns rc=0
  - `grep -q 'apply_rds_modprobe' packaging/rfxn-defense-detect.sh` returns rc=0
  - `grep -q 'SUPPRESS_MODPROBE_RDS' packaging/rfxn-defense-detect.sh` returns rc=0
  - `bash -n packaging/rfxn-defense-detect.sh` returns rc=0
- **Test**:
  - Detect.sh standalone test in a chroot mock (Phase 12): assert clean host applies rds modprobe; pre-stage Oracle Grid signal and assert suppression; pre-stage `/var/lib/rfxn-defense/auto-detect.json` post-run contains `applied.modprobe_rds: true` (clean) or `suppressed.modprobe_rds: true` (Oracle host).
  - `packaging/test-repo.sh` (Phase 9): new `rds_host` scenario pre-stages an Oracle clusterware signal (e.g., `/etc/oratab` exists, or `/u01/app/oracle/`); assert `modprobe_rds: suppressed` in auto-detect.json post-install.
- **Edge cases**:
  - **RDS workload signals — what counts?** Three signals chosen:
    1. `/etc/oratab` exists with at least one non-comment non-blank line (Oracle Grid Infrastructure marker)
    2. `/u01/app/oracle/product/*/grid` or similar `**/grid/bin/crsctl` exists (Oracle Clusterware install)
    3. Any of `/sys/module/rds`, `/sys/module/rds_tcp`, `/sys/module/rds_rdma` currently present in running kernel (module already loaded = workload in active use)
  - **False positives**: `/etc/oratab` may exist on a host that previously ran Oracle but no longer uses RDS. Acceptable conservative bias: if the file exists with non-comment content, assume RDS workload. Operator override via `/etc/rfxn-defense/force-full`.
  - **Stock RHEL builtin check**: RHEL/Alma/Rocky kernels do NOT ship `CONFIG_RDS=m`. The blacklist is a no-op there. Detection bias: even on RHEL, ship the conditional drop file by default (no harm if module doesn't exist) so the host is protected against ELRepo kernel-ml swaps. Suppression triggers ONLY when an RDS workload signal fires.
  - **Audit-key migration is breaking change for SIEM**: SIEM operators running `ausearch -k copyfail_afalg --start today` will get zero results after upgrade. CHANGELOG entry from Phase 4 documents migration table; that's the only mitigation. Do NOT ship dual-keyed rules (both `copyfail_*` and `rfxn_*` on the same syscall) — auditctl would emit duplicate records, doubling auditd load.
- **Regression-case**: `packaging/test-repo.sh::check-rds-host-suppression` — security — covers PinTheft cut suppression on RDS workloads (CVE pending).

- [ ] **Step 5.1: Rename audit-rule keys**

  In `packaging/rfxn-defense-audit.rules`, the three existing rule lines (added in v2.0.2 at file end):

  Old:
  ```
  -a always,exit -F arch=b64 -S socket -F a0=38 -F auid>=1000 -F auid!=-1 -k copyfail_afalg
  -a always,exit -F arch=b64 -S socket -F a0=15 -F auid>=1000 -F auid!=-1 -k copyfail_afkey
  -a always,exit -F arch=b64 -S socket -F a0=33 -F auid>=1000 -F auid!=-1 -k copyfail_afrxrpc
  ```

  New:
  ```
  -a always,exit -F arch=b64 -S socket -F a0=38 -F auid>=1000 -F auid!=-1 -k rfxn_afalg
  -a always,exit -F arch=b64 -S socket -F a0=15 -F auid>=1000 -F auid!=-1 -k rfxn_afkey
  -a always,exit -F arch=b64 -S socket -F a0=33 -F auid>=1000 -F auid!=-1 -k rfxn_afrxrpc
  ```

- [ ] **Step 5.2: Add RDS workload detection to detect.sh**

  Add globals after the existing `USERNS_CONSUMERS_*` block (around line 173):

  ```bash
  RDS_WORKLOAD_PRESENT="false"
  RDS_WORKLOAD_SIGNALS=()
  ```

  Add the detection function after `detect_userns_consumers()`:

  ```bash
  # v3.0.0: PinTheft mitigation gate. RDS modprobe blacklist is suppressed
  # when an Oracle Grid / clusterware / HPC workload is detected. Stock
  # RHEL/Alma/Rocky/Oracle UEK kernels do not ship CONFIG_RDS=m, so the
  # blacklist is a no-op there - we ship it anyway for defense in depth
  # against ELRepo kernel-ml/kernel-lt swaps, but suppress on Oracle hosts
  # where rds.ko might be needed.
  detect_rds_workload() {
      # Signal 1: /etc/oratab with non-comment, non-blank entries.
      # Canonical marker for any Oracle product install (Grid, RAC, DB).
      if [ -f /etc/oratab ] && \
         grep -qE '^[[:space:]]*[^#[:space:]]' /etc/oratab 2>/dev/null; then
          RDS_WORKLOAD_PRESENT="true"
          RDS_WORKLOAD_SIGNALS+=("/etc/oratab: non-comment entry present")
      fi

      # Signal 2: Oracle Clusterware control binary. Path conventional but
      # version-dependent; use a bounded find to catch /u01/app/.../grid/bin/crsctl.
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
  ```

- [ ] **Step 5.3: Add SUPPRESS_MODPROBE_RDS and decision wiring**

  Add to the `SUPPRESS_*` globals block (around line 232):

  ```bash
  SUPPRESS_MODPROBE_RDS="false"
  ```

  Extend `decide_suppressions()` after the existing IPSEC/AFS/ROOTLESS/USERNS_CONSUMERS decisions:

  ```bash
      [ "${RDS_WORKLOAD_PRESENT}" = "true" ] && SUPPRESS_MODPROBE_RDS="true"
  ```

- [ ] **Step 5.4: Add apply_rds_modprobe + teardown_rds_modprobe**

  Add after `apply_modprobe()` (around line 330):

  ```bash
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
  }
  ```

  Add after `teardown_modprobe()`:

  ```bash
  teardown_rds_modprobe() {
      rm -f "${ETC_MODPROBE}/99-rfxn-defense-rds.conf"
      log "modprobe rds teardown: removed /etc/modprobe.d/99-rfxn-defense-rds.conf"
  }
  ```

  Extend the existing `apply_modprobe()` function to call `apply_rds_modprobe` at the end:

  ```bash
  apply_modprobe() {
      # ... existing cf2-xfrm + rxrpc body ...
      # v3.0.0: PinTheft rds modprobe (always-shipped, suppressed on RDS workloads)
      apply_rds_modprobe
  }
  ```

  Extend `teardown_modprobe()`:

  ```bash
  teardown_modprobe() {
      rm -f "${ETC_MODPROBE}/99-rfxn-defense-cf2-xfrm.conf"
      rm -f "${ETC_MODPROBE}/99-rfxn-defense-rxrpc.conf"
      rm -f "${ETC_MODPROBE}/99-rfxn-defense-rds.conf"
      log "modprobe teardown: removed conditional /etc/modprobe.d/* files"
  }
  ```

- [ ] **Step 5.5: Extend JSON state output**

  In `write_state_json()` python emitter:

  Add environment variable carry-through:
  ```bash
          CFD_RDS_WORKLOAD_PRESENT="${RDS_WORKLOAD_PRESENT}" \
          CFD_SUP_MODPROBE_RDS="${SUPPRESS_MODPROBE_RDS}" \
  ```

  Add signal-array printf line and end marker (parallel to the existing 4 arrays):
  ```bash
          printf '%s\0' "${RDS_WORKLOAD_SIGNALS[@]+${RDS_WORKLOAD_SIGNALS[@]}}"
          printf 'CFD_END_RDS_WORKLOAD\0'
  ```

  In the python emitter body, parse the new array:
  ```python
  rds_workload_signals = take_until("CFD_END_RDS_WORKLOAD")
  ```

  Extend the `doc` dict:
  ```python
      "detected": {
          # ... existing keys ...
          "rds_workload":        {"present": b("CFD_RDS_WORKLOAD_PRESENT"),     "signals": rds_workload_signals},
      },
      "suppressed": {
          # ... existing keys ...
          "modprobe_rds":           b("CFD_SUP_MODPROBE_RDS"),
      },
      "applied": {
          # ... existing keys ...
          "modprobe_rds":           (not b("CFD_SUP_MODPROBE_RDS")) and modprobe_rds_template_present,
      },
  ```

  Add the corresponding template-present probe (parallel to `sysctl_template_present`):
  ```bash
      local modprobe_rds_template_present="false"
      if [ -f "${TEMPLATE_DIR}/modprobe/99-rfxn-defense-rds.conf" ]; then
          modprobe_rds_template_present="true"
      fi
  ```

  And carry it through:
  ```bash
          CFD_MODPROBE_RDS_TEMPLATE_PRESENT="${modprobe_rds_template_present}" \
  ```

  Python parse:
  ```python
  modprobe_rds_template_present = b("CFD_MODPROBE_RDS_TEMPLATE_PRESENT")
  ```

  **Schema bump:** `schema_version` stays at `"2"` since this is a backward-compatible addition (new keys; consumers ignore unknown keys per existing protocol).

- [ ] **Step 5.6: Wire detect_rds_workload into main()**

  In `main()`'s `apply` branch, add the new detection call after `detect_userns_consumers`:

  ```bash
              detect_ipsec
              detect_afs
              detect_rootless_containers
              detect_userns_consumers
              detect_rds_workload
              decide_suppressions
  ```

  Extend the `case "${scope}"` final apply branch to include `rds` as a scope (operator-driven scope refresh) and have `modprobe` + `all` invoke apply_rds_modprobe via the extended `apply_modprobe`:

  No additional case needed since `apply_rds_modprobe` is called via the extended `apply_modprobe` (Step 5.4). For operator-explicit invocation, `rfxn-redetect` already passes `apply all` which fans out via `apply_modprobe` → including `apply_rds_modprobe`.

  Update the final log line:
  ```bash
              log "apply ${scope} complete: ipsec=${IPSEC_PRESENT} afs=${AFS_PRESENT} rootless=${ROOTLESS_PRESENT} userns_consumers=${USERNS_CONSUMERS_PRESENT} rds_workload=${RDS_WORKLOAD_PRESENT}"
  ```

- [ ] **Step 5.7: Verify**

  ```bash
  grep -c 'copyfail_af' packaging/rfxn-defense-audit.rules
  # expect: 0
  ```

  ```bash
  grep -cE '^-a always,exit .* -k rfxn_(afalg|afkey|afrxrpc|afrds|pidfd_getfd)' packaging/rfxn-defense-audit.rules
  # expect: 5
  ```

  ```bash
  grep -c 'detect_rds_workload\|apply_rds_modprobe\|SUPPRESS_MODPROBE_RDS\|RDS_WORKLOAD_PRESENT' packaging/rfxn-defense-detect.sh
  # expect: >=8 (function defs + variable refs)
  ```

  ```bash
  bash -n packaging/rfxn-defense-detect.sh && echo OK
  # expect: OK
  ```

  ```bash
  grep 'TOOL_VERSION=' packaging/rfxn-defense-detect.sh
  # expect: TOOL_VERSION="3.0.0"
  ```

- [ ] **Step 5.8: Commit**

  ```bash
  git add -u packaging/rfxn-defense-audit.rules packaging/rfxn-defense-detect.sh
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 5: audit-key rename + detect.sh RDS workload detection

  Renames audit-rule -k tags copyfail_{afalg,afkey,afrxrpc} -> rfxn_*
  (atomic break for SIEM; CHANGELOG documents old->new migration).

  Adds detect_rds_workload() to detect.sh: signals are /etc/oratab,
  Oracle crsctl binary, or rds*.ko already loaded in running kernel.
  apply_rds_modprobe() ships /etc/modprobe.d/99-rfxn-defense-rds.conf
  when no workload detected; teardown_rds_modprobe() removes on erase.
  JSON state file gains detected.rds_workload + suppressed.modprobe_rds
  + applied.modprobe_rds; schema_version stays "2" (backward compat).
  EOF
  )"
  ```

---

### Phase 6: Auditor extension (rfxn-local-check)

Add four new checks to the auditor and update the posture map for the two new bug-class entries. Reads rely on the rfxn_* audit-key naming established in Phase 5 and the path migration from Phase 4.

**Files:**
- Modify: `rfxn-local-check.py` (new check functions + posture map additions + remediation strings + JSON schema)

- **Mode**: serial-agent (single file, multiple coordinated changes)
- **Accept**:
  - `python3 -c 'import py_compile; py_compile.compile("rfxn-local-check.py", doraise=True)'` returns rc=0 (syntax clean)
  - `grep -c 'def check_ptrace_scope' rfxn-local-check.py` returns 1
  - `grep -c 'def check_pidfd_getfd_auditd_rule' rfxn-local-check.py` returns 1
  - `grep -c 'def check_rds_modprobe' rfxn-local-check.py` returns 1
  - `grep -c 'def check_af_rds_restrict' rfxn-local-check.py` returns 1
  - `grep -E '"pintheft"|"keysign-pwn"' rfxn-local-check.py | wc -l` returns ≥4 (posture map entries + bug_classes_covered list)
  - `grep -c "rfxn_afrds\|rfxn_pidfd_getfd" rfxn-local-check.py` returns ≥2 (audit-key references for the extended audit_rules check)
  - Old audit-key refs `copyfail_af{alg,key,rxrpc}` updated to `rfxn_af*` in `check_audit_rules_extended` (or equivalent)
- **Test**:
  - Standalone in container: `./rfxn-local-check.py --json --skip-trigger --no-progress` returns valid JSON with `posture.bug_classes_covered` array including `pintheft` and `keysign-pwn`; `posture.bug_classes.pintheft` and `posture.bug_classes.keysign-pwn` present.
  - `packaging/test-repo.sh` (Phase 9) extends auditor JSON assertions.
- **Edge cases**:
  - **`check_ptrace_scope` on EL7**: Yama is built into EL7 stock kernels. The sysctl exists. Default value on RHEL is 0 (unrestricted). After install, `kernel.yama.ptrace_scope` should be 2 unless the operator overrode it. Check parses `/proc/sys/kernel/yama/ptrace_scope`.
  - **`check_pidfd_getfd_auditd_rule` on EL7**: the syscall doesn't exist, but the rule is loaded (numeric form `-S 438`). The check reads `auditctl -l` output looking for `key=rfxn_pidfd_getfd` (or `-k rfxn_pidfd_getfd`); presence in loaded rules = OK regardless of whether the syscall would ever fire.
  - **`check_rds_modprobe`**: parses `/etc/modprobe.d/99-rfxn-defense-rds.conf` if present. On RDS-workload hosts where detect.sh suppressed the file, this check returns INFO (suppression is the correct posture).
  - **`check_af_rds_restrict`**: parses `systemctl cat sshd.service | grep RestrictAddressFamilies` for `~AF_RDS` presence. Falls back to reading the static drop-in if systemctl unavailable.
  - **Bug-class posture map keys**: add `pintheft` and `keysign-pwn` (note hyphen-keysign — matches the CVE codename). The existing keys `cf1`, `cf2`, `dirtyfrag-esp`, `dirtyfrag-rxrpc` stay. Total 6 classes.
  - **`bug_classes_covered` SIEM array**: appears in `posture.bug_classes_covered` as a sorted list of class identifiers where `applicable AND mitigated`. The set semantics ensure dedup. SIEM consumers that parse v2.0.x JSON will not see new entries unless they widen their match — but adding entries is non-breaking (existing keys preserved).
- **Regression-case**: `packaging/test-repo.sh::check-auditor-bug-classes` — security — covers PinTheft + ssh-keysign-pwn surface visibility from auditor JSON (used by fleet posture dashboards).

- [ ] **Step 6.1: Extend `_aggregate_bug_classes()` with pintheft + keysign-pwn entries**

  The auditor has no `BUG_CLASSES` dict — the posture map is constructed inside `_aggregate_bug_classes(by_name)` at line ~2190 of `copyfail-local-check.py` (now `rfxn-local-check.py` post-Phase 1). It uses two closures (`is_ok(name)`, `status_of(name)`) over the by-name check results and returns a 4-key dict (`cf1`, `cf2`, `dirtyfrag-esp`, `dirtyfrag-rxrpc`).

  Extend the function with two new bug-class entries following the exact existing pattern. Add the applicability + mitigation closures inline (before the `return {...}` statement):

  ```python
      # PinTheft (CVE pending) - RDS zerocopy + io_uring fixed-buffer
      # page-cache overwrite of SUID binary. Applicable when any RDS
      # module is reachable (modprobe doesn't fully cut the path on
      # already-loaded kernels). Mitigated when modprobe_rds blocks
      # future loads, OR systemd_af_rds restricts tenant units, OR
      # the auditd tripwire is loaded as a fallback.
      pintheft_app = (status_of("modprobe_rds") not in (Status.OK, None))
      pintheft_mit = is_ok("modprobe_rds") or is_ok("systemd_af_rds") or \
                     is_ok("auditd_pidfd_getfd")  # auditd is detection, not mitigation
      # Re-think: auditd is detection. Real mitigations are modprobe + systemd.
      pintheft_mit = is_ok("modprobe_rds") or is_ok("systemd_af_rds")
      pintheft_layers = {
          "modprobe_rds":           is_ok("modprobe_rds"),
          "systemd_af_rds":         is_ok("systemd_af_rds"),
          "auditd_rfxn_afrds":      is_ok("package_audit_rules"),
          "kernel_io_uring_off":    False,  # operator opt-in; checked separately
      }

      # ssh-keysign-pwn (CVE-2026-46333) - pidfd_getfd steals open fd
      # from exiting SUID. Applicable when ptrace_scope < 2 (default
      # 0 on RHEL family). Mitigated when ptrace_scope >= 2.
      keysign_app = (status_of("ptrace_scope") in (Status.WARN, None))
      keysign_mit = is_ok("ptrace_scope")
      keysign_layers = {
          "sysctl_ptrace_scope":    is_ok("ptrace_scope"),
          "auditd_pidfd_getfd":     is_ok("auditd_pidfd_getfd"),
          "package_audit_rules":    is_ok("package_audit_rules"),
      }
  ```

  Then extend the returned dict (the existing 4 entries `cf1`, `cf2`, `dirtyfrag-esp`, `dirtyfrag-rxrpc` remain unchanged):

  ```python
      return {
          # ... existing 4 entries ...
          "pintheft": {
              "applicable": bool(pintheft_app),
              "mitigated":  bool(pintheft_mit) if pintheft_app else None,
              "kernel_sink": "RDS zerocopy + io_uring fixed-buffer page-cache overwrite of SUID binary (CVE pending)",
              "layers": {k: bool(v) for k, v in pintheft_layers.items()},
          },
          "keysign-pwn": {
              "applicable": bool(keysign_app),
              "mitigated":  bool(keysign_mit) if keysign_app else None,
              "kernel_sink": "__ptrace_may_access race + pidfd_getfd FD theft (CVE-2026-46333)",
              "layers": {k: bool(v) for k, v in keysign_layers.items()},
          },
      }
  ```

  `_aggregate_bug_classes` is consumed by `determine_posture()` (line ~2148); that caller's `bug_classes_covered` aggregation (line ~2150 area) already iterates over the returned dict keys, so the new entries automatically appear in `posture.bug_classes_covered` when applicable+mitigated.

- [ ] **Step 6.2: Add `check_ptrace_scope` (category="HARDENING")**

  Uses the actual auditor API: `Check(name, category, status, message, details=None, remediation=None)` where category is a STRING literal. Check functions take zero parameters (no `state` object). `Status` is a class with string-typed members (`Status.OK`, `Status.WARN`, `Status.INFO`).

  ```python
  def check_ptrace_scope():
      """v3.0.0: kernel.yama.ptrace_scope (ssh-keysign-pwn CVE-2026-46333).

      ptrace_scope >= 2 closes the pidfd_getfd path. Yama LSM is present
      in all EL7+ kernels.

        2 or 3 -> OK (closes ssh-keysign-pwn)
        1      -> WARN (Ubuntu/Debian default; PoC bypasses)
        0      -> WARN (RHEL family default; worst case)
        no Yama -> INFO (rare; kernel built without CONFIG_SECURITY_YAMA)
      """
      val = read_text_safe("/proc/sys/kernel/yama/ptrace_scope")
      if val is None:
          return Check("ptrace_scope", "HARDENING", Status.INFO,
                       "Yama LSM not loaded (no /proc/sys/kernel/yama/ptrace_scope)")
      val = val.strip()
      try:
          n = int(val)
      except ValueError:
          return Check("ptrace_scope", "HARDENING", Status.WARN,
                       "unparseable: {!r}".format(val),
                       remediation="dnf install rfxn-defense-sysctl")
      if n >= 2:
          return Check("ptrace_scope", "HARDENING", Status.OK,
                       "kernel.yama.ptrace_scope={} (closes ssh-keysign-pwn)".format(n),
                       details={"value": n})
      return Check("ptrace_scope", "HARDENING", Status.WARN,
                   "kernel.yama.ptrace_scope={} (insufficient for CVE-2026-46333)".format(n),
                   details={"value": n},
                   remediation="Install rfxn-defense-sysctl, OR set "
                               "kernel.yama.ptrace_scope=2 via sysctl.d")
  ```

  Wire the check into the per-category dispatch loop. Find the existing HARDENING bucket (search for `category="HARDENING"` in the run-checks driver around `def run_checks` or `def main`) and append `check_ptrace_scope` alongside the existing HARDENING entries (`check_suid_inventory`, `check_page_cache_integrity`, etc.).

- [ ] **Step 6.3: Add `check_pidfd_getfd_auditd_rule` (category="DETECTION")**

  Real API: `run_cmd(cmd, timeout=5)` returns a `(rc, stdout, stderr)` tuple where stdout/stderr are bytes. Decode via `.decode('utf-8', errors='replace')`. Uses the same pattern as `check_auditd()` at line ~1166.

  ```python
  def check_pidfd_getfd_auditd_rule():
      """v3.0.0: auditd tripwire for ssh-keysign-pwn (CVE-2026-46333).
      PoC needs 100-2000 spawns per success; this rule fires loudly.
      Rule uses NUMERIC syscall 438 since EL7+EL8 audit-userspace does
      not recognise the name 'pidfd_getfd'.
      """
      rc, out, _err = run_cmd(["auditctl", "-l"], timeout=2)
      if rc != 0:
          return Check("auditd_pidfd_getfd", "DETECTION", Status.INFO,
                       "auditctl -l unavailable (auditd not running?)")
      out_text = out.decode("utf-8", errors="replace")
      if "rfxn_pidfd_getfd" in out_text:
          return Check("auditd_pidfd_getfd", "DETECTION", Status.OK,
                       "rule loaded; ausearch -k rfxn_pidfd_getfd")
      return Check("auditd_pidfd_getfd", "DETECTION", Status.WARN,
                   "rfxn_pidfd_getfd rule not loaded",
                   remediation="Install rfxn-defense-audit, OR add "
                               "'-a always,exit -F arch=b64 -S 438 "
                               "-F auid>=1000 -F auid!=-1 -k rfxn_pidfd_getfd' "
                               "to /etc/audit/rules.d/ + augenrules --load")
  ```

- [ ] **Step 6.4: Add `check_rds_modprobe` and `check_af_rds_restrict` (category="MITIGATION")**

  Real API: zero-parameter check functions, `read_text_safe(path)` returns the decoded string or `None`, direct `json.load(open(AUTO_DETECT_PATH))` for auto-detect state (mirroring `check_auto_detect_state()` at line ~1420). Python 3.6 floor — NO f-strings (use `.format()` per existing code style).

  ```python
  def check_rds_modprobe():
      """v3.0.0: PinTheft (CVE pending) rds/rds_tcp/rds_rdma modprobe
      blacklist. Functional on Ubuntu/Debian/Arch and on RHEL+ELRepo
      kernel-ml/lt. No-op on stock RHEL/Alma/Rocky/Oracle UEK
      (CONFIG_RDS not set; modules don't exist; blacklist is harmless).
      """
      path = "/etc/modprobe.d/99-rfxn-defense-rds.conf"
      body = read_text_safe(path)
      if body is None:
          # Distinguish "subpackage not installed" from "detect.sh-suppressed".
          suppressed = False
          try:
              with open(AUTO_DETECT_PATH, "r") as f:
                  ad = json.load(f)
              if isinstance(ad, dict):
                  suppressed = bool(ad.get("suppressed", {}).get("modprobe_rds"))
          except (OSError, json.JSONDecodeError):
              pass
          if suppressed:
              return Check("modprobe_rds", "MITIGATION", Status.INFO,
                           "suppressed (RDS workload detected by detect.sh)")
          return Check("modprobe_rds", "MITIGATION", Status.WARN,
                       "not present",
                       remediation="dnf install rfxn-defense-modprobe")
      mods = {"rds", "rds_tcp", "rds_rdma"}
      present = set()
      for m in mods:
          if ("install " + m + " ") in body or ("blacklist " + m) in body:
              present.add(m)
      if present == mods:
          return Check("modprobe_rds", "MITIGATION", Status.OK,
                       "rds/rds_tcp/rds_rdma blacklisted",
                       details={"modules": sorted(mods)})
      return Check("modprobe_rds", "MITIGATION", Status.WARN,
                   "partial: missing {}".format(sorted(mods - present)),
                   details={"missing": sorted(mods - present)},
                   remediation="reinstall rfxn-defense-modprobe")


  def check_af_rds_restrict():
      """v3.0.0: systemd RestrictAddressFamilies=~AF_RDS for PinTheft
      (CVE pending). Checks the always-on 10-* drop-in across the 5
      tenant units. AF_RDS is merged into the existing ~AF_ALG ~AF_KEY
      restriction line so this scan looks for the token literal.
      """
      missing = []
      for unit in ("user@", "sshd", "cron", "crond", "atd"):
          path = "/etc/systemd/system/{}.service.d/10-rfxn-defense.conf".format(unit)
          body = read_text_safe(path)
          if body is None:
              missing.append(unit + " (drop-in absent)")
              continue
          if "~AF_RDS" not in body:
              missing.append(unit + " (~AF_RDS absent)")
      if not missing:
          return Check("systemd_af_rds", "MITIGATION", Status.OK,
                       "~AF_RDS present on all 5 tenant units")
      return Check("systemd_af_rds", "MITIGATION", Status.WARN,
                   "missing on: {}".format(", ".join(missing)),
                   details={"missing_units": missing},
                   remediation="reinstall rfxn-defense-systemd")
  ```

  Wire all four new checks into the per-category dispatch loop. The driver (search for `category="MITIGATION"` in the check-runner section) groups checks by category; append `check_rds_modprobe` and `check_af_rds_restrict` to MITIGATION, `check_ptrace_scope` to HARDENING, `check_pidfd_getfd_auditd_rule` to DETECTION.

- [ ] **Step 6.5: Add `check_package_audit_rules` — do NOT overwrite existing `check_audit_rules_extended`**

  The existing `check_audit_rules_extended` watches the operator-emitted IOC keys (`afalg_attempt`, `cf_userns`, `cf_addkey`, `cf_xfrm_nl`, `splice_tenant`) that `--emit-remediation` writes. Those keys are NOT the same as the new package-shipped `rfxn_*` keys. Replacing the watched set would silently break the auditor for hosts using the emit-remediation flow.

  Solution: leave `check_audit_rules_extended` semantically unchanged (its key set monitors operator IOC rules), and add a NEW check `check_package_audit_rules` that watches the five package-shipped keys (`rfxn_afalg`, `rfxn_afkey`, `rfxn_afrxrpc`, `rfxn_afrds`, `rfxn_pidfd_getfd`).

  ```python
  def check_package_audit_rules():
      """v3.0.0: presence of the rfxn-defense-audit ruleset's tripwire keys.

      Distinct from check_audit_rules_extended, which watches operator-emitted
      IOC keys (afalg_attempt, etc.) from --emit-remediation. The package-shipped
      keys cover socket(AF_*) + pidfd_getfd primitives directly:
        rfxn_afalg       -> cf1 (CVE-2026-31431) AF_ALG
        rfxn_afkey       -> cf2 / DF-ESP / Fragnesia AF_KEY
        rfxn_afrxrpc     -> Dirty Frag-RxRPC + DirtyDecrypt AF_RXRPC
        rfxn_afrds       -> PinTheft AF_RDS
        rfxn_pidfd_getfd -> ssh-keysign-pwn pidfd_getfd
      """
      rc, out, _err = run_cmd(["auditctl", "-l"], timeout=2)
      if rc != 0:
          return Check("package_audit_rules", "DETECTION", Status.INFO,
                       "auditctl -l unavailable (auditd not running?)")
      out_text = out.decode("utf-8", errors="replace")
      expected = ["rfxn_afalg", "rfxn_afkey", "rfxn_afrxrpc",
                  "rfxn_afrds", "rfxn_pidfd_getfd"]
      missing = [k for k in expected if k not in out_text]
      if not missing:
          return Check("package_audit_rules", "DETECTION", Status.OK,
                       "all 5 rfxn_* tripwires loaded",
                       details={"keys": expected})
      return Check("package_audit_rules", "DETECTION", Status.WARN,
                   "missing {} of 5 rfxn_* tripwires".format(len(missing)),
                   details={"missing": missing},
                   remediation="dnf install rfxn-defense-audit && augenrules --load")
  ```

  Wire `check_package_audit_rules` into the DETECTION dispatch loop alongside `check_audit_rules_extended` (both run; complementary).

- [ ] **Step 6.6: Update `bug_classes_covered` aggregation logic**

  The auditor's posture rollup determines which entries land in `bug_classes_covered`. The exact aggregation depends on the existing implementation; the rule is "bug class X is covered iff its `primary_layer_keys` are all OK in the layer-check results."

  Read the existing aggregator (likely in the `_emit_posture` or `_compute_posture` function). Confirm the new `pintheft` and `keysign-pwn` entries flow through it.

- [ ] **Step 6.7: Verify**

  ```bash
  python3 -c 'import py_compile; py_compile.compile("rfxn-local-check.py", doraise=True)' && echo OK
  # expect: OK
  ```

  ```bash
  grep -c 'def check_ptrace_scope\|def check_pidfd_getfd_auditd_rule\|def check_rds_modprobe\|def check_af_rds_restrict\|def check_package_audit_rules' rfxn-local-check.py
  # expect: 5
  ```

  ```bash
  grep -c '"pintheft"\|"keysign-pwn"' rfxn-local-check.py
  # expect: >=4
  ```

  ```bash
  grep -c 'rfxn_afrds\|rfxn_pidfd_getfd' rfxn-local-check.py
  # expect: >=4
  ```

  ```bash
  grep -c 'copyfail_af' rfxn-local-check.py
  # expect: 0
  # (Note: this counts only the unhyphenated audit-key prefix; the
  # operator-emitted IOC keys watched by check_audit_rules_extended
  # — afalg_attempt, cf_userns, cf_addkey, cf_xfrm_nl, splice_tenant —
  # are intentionally preserved and don't match this grep.)
  ```

  Optional smoke test (on the build host, no RPM install needed):
  ```bash
  python3 rfxn-local-check.py --json --skip-trigger --skip-hardening --no-progress 2>/dev/null \
    | python3 -c "import json, sys; d=json.load(sys.stdin); bc=d['posture'].get('bug_classes',{}); print('classes:', sorted(bc.keys()))"
  # expect: classes: ['cf1', 'cf2', 'dirtyfrag-esp', 'dirtyfrag-rxrpc', 'keysign-pwn', 'pintheft']
  ```

- [ ] **Step 6.8: Commit**

  ```bash
  git add -u rfxn-local-check.py
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 6: auditor extensions for PinTheft + ssh-keysign-pwn

  Adds 5 new checks:
  - check_ptrace_scope (HARDENING): reads kernel.yama.ptrace_scope,
    OK at >=2, WARN at 0/1
  - check_pidfd_getfd_auditd_rule (DETECTION): looks for rfxn_pidfd_getfd
    in auditctl -l output
  - check_rds_modprobe (MITIGATION): verifies 99-rfxn-defense-rds.conf
    blacklists rds/rds_tcp/rds_rdma; recognises detect.sh suppression
  - check_af_rds_restrict (MITIGATION): verifies ~AF_RDS in the 10-*
    drop-in across 5 tenant units
  - check_package_audit_rules (DETECTION): NEW check that monitors the
    rfxn_* package-shipped audit keys (afalg/afkey/afrxrpc/afrds/pidfd_getfd).
    The pre-existing check_audit_rules_extended is UNCHANGED - it
    continues to monitor the distinct operator-emitted IOC key set
    (afalg_attempt / cf_userns / cf_addkey / cf_xfrm_nl / splice_tenant)
    written by --emit-remediation. Two separate checks for two separate
    audit-key namespaces.

  _aggregate_bug_classes() gains pintheft + keysign-pwn entries that
  mirror the existing 4-class applicable/mitigated/layers pattern.
  bug_classes_covered automatically picks them up via the existing
  aggregation loop in determine_posture(). Removes copyfail-defense
  path/binary string refs from remediation messages; audit-key strings
  unchanged in this phase (Phase 5 owns that swap in the rules file).
  EOF
  )"
  ```

---

### Phase 7: DirtyDecrypt CVE-2026-31635 verification + cross-stamp

Independent verification: read the DirtyDecrypt advisory and confirm the entry primitive is on AF_RXRPC sockets. If yes (expected), cross-stamp under existing rxrpc cuts. If no, return to planning to add specific cuts.

**Files:**
- Modify: `BRIEF.md` (add DirtyDecrypt + PinTheft + ssh-keysign-pwn sections); `packaging/rfxn-defense.spec` (CHANGELOG already covers DirtyDecrypt in Phase 4 — no edit needed); the actual `rxrpc` module + `AF_RXRPC` systemd + `rfxn_afrxrpc` audit rule from existing v2.0.2 work transparently cover DirtyDecrypt if verification succeeds.

- **Mode**: serial-context (research + 1-file write; no agent dispatch needed)
- **Accept**:
  - DirtyDecrypt advisory primitive confirmed (entry point = AF_RXRPC socket creation, kernel sink = `rxgk_*` handler in `net/rxrpc/`)
  - Verification result written to BRIEF.md
  - Decision documented: either "covered by existing rxrpc cuts" (expected) or "additional cut needed" (back to planning)
- **Test**:
  - `grep -E 'DirtyDecrypt|CVE-2026-31635' BRIEF.md | wc -l` returns ≥3 (header + body + cross-link)
  - `grep -q 'covered by the rxrpc cuts' BRIEF.md` returns rc=0 (assuming verification result is positive)
  - Read advisory: at minimum The Hacker News (https://thehackernews.com/2026/05/dirtydecrypt-poc-released-for-linux.html) and the cybersecuritynews.com mirror.
- **Edge cases**:
  - **If DirtyDecrypt primitive is NOT AF_RXRPC-socket-mediated**: the rxrpc cuts may not cover it. Plan re-opens: add a separate Phase 7a to ship a new cut. Most likely scenario: primitive is rxrpc-related (RXGK is the RxRPC Generic Security mechanism — every RXGK invocation requires an active rxrpc session via an `AF_RXRPC` socket). Confidence: 90%+ that existing cuts cover.
  - **If advisory is paywalled / can't be read**: defer cross-stamp to a later release; document the deferral in FOLLOWUPS.md instead of BRIEF.md. v3.0.0 does NOT block on DirtyDecrypt verification — CHANGELOG note in Phase 4 already calls out the cross-stamp as based on rxrpc-class primitive.
  - **Scope creep guard**: if PoC writeup reveals DirtyDecrypt's primitive is via a userspace AFS tool (e.g., `kinit -A`, `aklog`), the cf-class systemd `RestrictAddressFamilies=~AF_RXRPC` is suppressed on AFS-detected hosts, which means DirtyDecrypt is NOT mitigated on those hosts. Document this in BRIEF.md and FOLLOWUPS.md if it materializes.
- **Regression-case**: N/A — docs — verification + documentation phase only; no code changes.

- [ ] **Step 7.1: Read DirtyDecrypt advisory**

  Use WebFetch on:
  - https://thehackernews.com/2026/05/dirtydecrypt-poc-released-for-linux.html
  - https://cybersecuritynews.com/dirtydecrypt-linux-kernel-vulnerability/

  Extract from each source:
  1. The exact kernel sink (function name, file path in net/rxrpc/)
  2. The userspace entry primitive (which syscall, which socket family)
  3. Whether the published PoC needs anything beyond the AF_RXRPC socket

- [ ] **Step 7.2: Cross-check against existing coverage matrix**

  For each layer in v3.0.0:

  | Layer | Coverage of DirtyDecrypt? |
  |---|---|
  | `rfxn-defense-modprobe` (`rxrpc` blacklisted) | YES if entry requires loading rxrpc.ko; CONDITIONAL if rxrpc is already loaded on host |
  | `rfxn-defense-systemd` (`~AF_RXRPC` on 10-* or 12-*) | YES if entry path goes through tenant unit; NO if direct user-shell exploit (12-* is the suppressible variant) |
  | `rfxn-defense-audit` (`rfxn_afrxrpc` socket rule) | YES — detection-only, fires on socket creation |

  Determine the verdict. Most likely: "covered when rxrpc is not loaded AND when entry is via a tenant unit; auditd fires regardless."

- [ ] **Step 7.3: Update BRIEF.md**

  Append a new section:

  ```markdown
  ## DirtyDecrypt (CVE-2026-31635)

  CONFIG_RXGK Linux LPE — RXGK is the RxRPC Generic Security (kerberos5-based)
  protocol used by the rxrpc subsystem. PoC released 2026-05 by [...].

  **Entry primitive:** socket(AF_RXRPC, ...) + RXGK-flavored key install.

  **Coverage verdict:** covered incidentally by existing rxrpc cuts.
    - rfxn-defense-modprobe blocks rxrpc.ko load on non-AFS hosts
    - rfxn-defense-systemd ~AF_RXRPC on tenant units (5-unit body in 10-*
      always-on drop-in)
    - rfxn-defense-audit rfxn_afrxrpc rule fires on socket(AF_RXRPC=33)
      creation by auid>=1000

  **Caveat:** on AFS-detected hosts, detect.sh suppresses the rxrpc
  modprobe cut + the 12-* RestrictAddressFamilies=~AF_RXRPC drop-in
  (AFS userspace tools open AF_RXRPC sockets). DirtyDecrypt is NOT
  mitigated on AFS-detected hosts; the rfxn_afrxrpc audit rule remains
  the only tripwire there. Document this gap explicitly for AFS-running
  operators.
  ```

  Also add the PinTheft and ssh-keysign-pwn sections to BRIEF.md (parallel structure):

  ```markdown
  ## PinTheft (CVE pending; disclosed 2026-05)

  RDS zerocopy double-free + io_uring fixed-buffer page-cache overwrite
  of SUID binary. Direct successor to cf1's primitive: same outcome
  (page-cache overwrite of suid binary), different entry path.

  Affected populations: Ubuntu/Debian/Arch + RHEL hosts on ELRepo
  kernel-ml. Stock RHEL/Alma/Rocky/Oracle UEK not affected (no CONFIG_RDS).

  Mitigation in rfxn-defense (3.0.0+):
    - modprobe rds/rds_tcp/rds_rdma blacklist (conditional, suppressed
      on Oracle Grid + RDS-workload hosts)
    - RestrictAddressFamilies=~AF_RDS on 5 tenant units
    - auditd rule rfxn_afrds on socket(AF_RDS=21)
    - operator opt-in: kernel.io_uring_disabled=2 (Linux 6.6+)

  ## ssh-keysign-pwn (CVE-2026-46333)

  __ptrace_may_access() race exposes root-readable file descriptors via
  pidfd_getfd on exiting SUID. Targets ssh-keysign (SSH host private
  keys) and chage (/etc/shadow).

  Affected: Linux kernels with pidfd_getfd (added in 5.6). EL7+EL8
  stock not exposed via public PoC; defense-in-depth still valuable
  on those hosts.

  Mitigation in rfxn-defense (3.0.0+):
    - kernel.yama.ptrace_scope = 2 (closes pidfd_getfd path without
      breaking root debugging)
    - auditd rule rfxn_pidfd_getfd (numeric syscall 438; PoC needs
      100-2000 spawns per success - fires loudly)
  ```

- [ ] **Step 7.4: Verify**

  ```bash
  grep -cE 'DirtyDecrypt|CVE-2026-31635' BRIEF.md
  # expect: >=3
  ```

  ```bash
  grep -cE 'PinTheft|ssh-keysign-pwn|CVE-2026-46333' BRIEF.md
  # expect: >=4
  ```

- [ ] **Step 7.5: Commit**

  ```bash
  git add -u BRIEF.md
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 7: DirtyDecrypt verification + BRIEF.md updates

  DirtyDecrypt (CVE-2026-31635) entry primitive confirmed as AF_RXRPC
  socket creation + RXGK key install. Covered incidentally by existing
  rxrpc cuts (modprobe blacklist + RestrictAddressFamilies + auditd
  rule). AFS-detected hosts have rxrpc cuts suppressed - DirtyDecrypt
  is NOT mitigated there; rfxn_afrxrpc audit rule is the only tripwire.

  Also adds PinTheft and ssh-keysign-pwn brief sections matching the
  existing Copy Fail framing.
  EOF
  )"
  ```

---

### Phase 8: test-repo.sh extension + EL7 image + new check assertions

Sweep `packaging/test-repo.sh` to rename every `copyfail-defense*` subpackage reference to `rfxn-defense*`, every on-disk path, the assertions, plus add EL7 support (new image, default ELS, mock chroot config invocation note), plus add new assertions for PinTheft and ssh-keysign-pwn coverage.

**Files:**
- Modify: `packaging/test-repo.sh` (bulk rename + new assertions + EL7 image + new upgrade-path test v2.0.2 → v3.0.0)

- **Mode**: serial-agent (single 700+ line file, multiple coordinated edits)
- **Accept**:
  - `grep -c 'copyfail-defense' packaging/test-repo.sh` returns ≤2 (only legacy upgrade-path test references — see below)
  - `grep -c 'rfxn-defense' packaging/test-repo.sh` returns >40 (subpackage references throughout)
  - `grep -c 'IMAGE\[7\]' packaging/test-repo.sh` returns 1
  - `grep -q 'rfxn_afrds\|rfxn_pidfd_getfd' packaging/test-repo.sh` returns rc=0
  - `bash -n packaging/test-repo.sh` returns rc=0
- **Test**:
  - Phase 12 mock build + test-repo.sh against staged gh-pages is the integration test for this phase.
  - Local syntax check + dry-run of test functions (without running containers) verifies structural correctness.
- **Edge cases**:
  - **EL7 image availability**: `quay.io/centos/centos:7` was deprecated 2024 but as of 2026-05 still serves. Phase 12 verifies availability via `podman pull` before declaring EL7 shippable.
  - **EL7 dnf vs yum**: EL7 uses `yum` natively; `dnf` is available via EPEL as `dnf`. The test script uses `dnf install` everywhere — works on EL7 with EPEL.
  - **EL7 systemd `RestrictAddressFamilies` syntax**: works on EL7 systemd 219+. EL7 ships systemd 219 baseline (RHEL 7.0) → 219.69+ (RHEL 7.9). Confirmed working.
  - **EL7 audit-userspace numeric syscall**: `-S 438` parses cleanly on EL7's audit-2.8.x. Tested manually.
  - **EL7 Python 3**: EL7's `dnf install python3` (with EPEL) pulls `python3-3.6.8`. Auditor requires 3.6+; baseline satisfied. No `dnf install python36` distinction in 2026; EPEL has consolidated.
  - **Upgrade-path test v2.0.2 → v3.0.0**: the existing v1.0.1 → v2.0.0 upgrade-path test demonstrates the Obsoletes/Provides chain. Phase 8 ADDS a parallel `run_upgrade_test_v2_to_v3_in()` that starts from a fresh container, `dnf install copyfail-defense=1:2.0.2-1`, then `dnf upgrade rfxn-defense`. Asserts: (a) every copyfail-defense* package gone, (b) rfxn-defense + 6 subpackages present, (c) `/var/lib/rfxn-defense/auto-detect.json` exists with `tool_version: 3.0.0` (proves migration ran), (d) `/var/lib/copyfail-defense/` either gone or empty (rmdir succeeded post-migration). Requires the gh-pages repo to still serve v2.0.2 RPMs (per existing `[D-22]` retention policy).
- **Regression-case**: `packaging/test-repo.sh::check-rfxn-rename-roundtrip` + `::check-v2-to-v3-upgrade-path` — security — covers the entire rename + new coverage in a real `dnf install` flow.

- [ ] **Step 8.1: Bulk rename `copyfail-defense*` → `rfxn-defense*`**

  Most occurrences are mechanical:
  - `dnf install -y copyfail-defense` → `dnf install -y rfxn-defense`
  - `rpm -q copyfail-defense copyfail-defense-shim ...` → `rpm -q rfxn-defense rfxn-defense-shim ...` (all 7 subpackages)
  - `dnf remove -y copyfail-defense ...` → `dnf remove -y rfxn-defense ...`
  - `/etc/modprobe.d/99-copyfail-defense-${f}.conf` → `/etc/modprobe.d/99-rfxn-defense-${f}.conf`
  - `/etc/systemd/system/sshd.service.d/10-copyfail-defense.conf` → `10-rfxn-defense.conf`
  - `/etc/sysctl.d/99-copyfail-defense-userns.conf` → `99-rfxn-defense-userns.conf`
  - `/etc/audit/rules.d/99-copyfail-defense.rules` → `99-rfxn-defense.rules`
  - `/usr/sbin/copyfail-shim-enable` → `/usr/sbin/rfxn-shim-enable`
  - `/usr/sbin/copyfail-local-check` → `/usr/sbin/rfxn-local-check`
  - `/var/lib/copyfail-defense` → `/var/lib/rfxn-defense`
  - `/etc/copyfail` → `/etc/rfxn-defense`

  **Exception**: the existing `run_upgrade_test_in` function (v1.0.1 → v2.0.0 test) MUST keep `copyfail-defense` and `afalg-defense` references — it's testing the existing Obsoletes/Provides chain.

- [ ] **Step 8.2: Update audit-rule key assertions**

  Find lines (currently around line 180-185):

  Old:
  ```
  grep -qE 'a0=38 .* -k copyfail_afalg' /etc/audit/rules.d/99-copyfail-defense.rules \
      || fail "audit rules missing AF_ALG (a0=38) tag"
  grep -qE 'a0=15 .* -k copyfail_afkey' ...
  grep -qE 'a0=33 .* -k copyfail_afrxrpc' ...
  ```

  New:
  ```
  grep -qE 'a0=38 .* -k rfxn_afalg' /etc/audit/rules.d/99-rfxn-defense.rules \
      || fail "audit rules missing AF_ALG (a0=38) tag"
  grep -qE 'a0=15 .* -k rfxn_afkey' /etc/audit/rules.d/99-rfxn-defense.rules \
      || fail "audit rules missing AF_KEY (a0=15) tag"
  grep -qE 'a0=33 .* -k rfxn_afrxrpc' /etc/audit/rules.d/99-rfxn-defense.rules \
      || fail "audit rules missing AF_RXRPC (a0=33) tag"
  # v3.0.0 additions:
  grep -qE 'a0=21 .* -k rfxn_afrds' /etc/audit/rules.d/99-rfxn-defense.rules \
      || fail "audit rules missing AF_RDS (a0=21) tag"
  grep -qE '-S 438 .* -k rfxn_pidfd_getfd' /etc/audit/rules.d/99-rfxn-defense.rules \
      || fail "audit rules missing pidfd_getfd (syscall 438) rule"
  ```

- [ ] **Step 8.3: Add RestrictAddressFamilies AF_RDS assertion**

  After the AF_KEY assertion (line ~190):

  ```
  # v3.0.0: AF_RDS in always-on 10-* drop-in (PinTheft entry point).
  grep -qE 'RestrictAddressFamilies=.*~AF_RDS' \
      /etc/systemd/system/sshd.service.d/10-rfxn-defense.conf \
      || fail "systemd 10-* drop-in missing ~AF_RDS restriction (PinTheft)"
  ```

- [ ] **Step 8.4: Add ptrace_scope sysctl assertion**

  After the userns sysctl assertion (line ~175):

  ```
  # v3.0.0: kernel.yama.ptrace_scope key in sysctl drop-in (ssh-keysign-pwn).
  grep -q '^-kernel.yama.ptrace_scope' /etc/sysctl.d/99-rfxn-defense-userns.conf \
      || fail "sysctl drop-in lacks kernel.yama.ptrace_scope key"
  ```

- [ ] **Step 8.5: Add RDS modprobe assertion (clean host scenario)**

  In the clean-host check block (around line 153-156):

  ```
  # v3.0.0: rds modprobe drop-in on a clean host (no Oracle/RDS workload).
  test -f /etc/modprobe.d/99-rfxn-defense-rds.conf \
      || fail "rds modprobe drop file missing on clean host (PinTheft)"
  grep -qE '^install +rds_tcp +/bin/false' /etc/modprobe.d/99-rfxn-defense-rds.conf \
      || fail "rds modprobe missing rds_tcp install line"
  ```

  Also update the modprobe drop-file count assertion (around line 198-201):

  Old:
  ```
  mp_count=$(cat /etc/modprobe.d/99-copyfail-defense-{cf1,cf2-xfrm,rxrpc}.conf 2>/dev/null \
      | grep -cE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false')
  [ "$mp_count" -eq 9 ] \
      || fail "modprobe drop file has $mp_count install lines, expected 9"
  ```

  New:
  ```
  mp_count=$(cat /etc/modprobe.d/99-rfxn-defense-{cf1,cf2-xfrm,rxrpc,rds}.conf 2>/dev/null \
      | grep -cE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc|rds|rds_tcp|rds_rdma) +/bin/false')
  [ "$mp_count" -eq 12 ] \
      || fail "modprobe drop files have $mp_count install lines, expected 12 (9 cf-class + 3 rds)"
  ```

- [ ] **Step 8.6: Add v3.0.0 rename roundtrip assertion**

  In the clean-host check, add a new block verifying the rename worked from the operator side:

  ```
  # v3.0.0: rename roundtrip - compat symlinks still resolve to new binaries
  test -L /usr/sbin/copyfail-shim-enable \
      || fail "copyfail-shim-enable compat symlink missing"
  test "$(readlink /usr/sbin/copyfail-shim-enable)" = rfxn-shim-enable \
      || fail "copyfail-shim-enable does not point to rfxn-shim-enable"
  test -L /usr/sbin/copyfail-local-check \
      || fail "copyfail-local-check compat symlink missing"
  test -L /usr/sbin/copyfail-redetect \
      || fail "copyfail-redetect compat symlink missing"
  # State path post-install (no migration scenario): new path exists
  test -d /var/lib/rfxn-defense \
      || fail "/var/lib/rfxn-defense state dir missing"
  test -d /etc/rfxn-defense \
      || fail "/etc/rfxn-defense sentinel dir missing"
  ok "v3.0.0 rename surfaces present (state dirs + compat symlinks)"
  ```

- [ ] **Step 8.7: Add new `rds_host` scenario**

  After the existing `flatpak_host` scenario, add a parallel `rds_host`:

  ```
  test_rds_host() {
      local image="$1" el="$2"
      podman run --rm -i --network=host \
          -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
          "$image" /bin/bash <<'INNER'
      set -euo pipefail
      fail() { echo "FAIL: $*" >&2; exit 1; }
      ok()   { echo "ok:   $*"; }
      # Pre-stage Oracle Grid signal: /etc/oratab with a non-comment line.
      mkdir -p /etc
      cat > /etc/oratab <<'OEOF'
  # Comment header
  ORCL:/u01/app/oracle/product/19c:N
  OEOF
      # Add the repo and install.
      curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/rfxn-defense.repo
      dnf install -y rfxn-defense >/tmp/dnf.log 2>&1
      # rds modprobe MUST be suppressed by detect.sh
      [ ! -f /etc/modprobe.d/99-rfxn-defense-rds.conf ] \
          || fail "rds modprobe NOT suppressed on Oracle-detected host"
      # auto-detect.json must show suppression
      python3 -c '
  import json
  d = json.load(open("/var/lib/rfxn-defense/auto-detect.json"))
  assert d["detected"]["rds_workload"]["present"] is True, d
  assert d["suppressed"]["modprobe_rds"] is True, d
  assert d["applied"]["modprobe_rds"] is False, d
  print("ok: detect.sh suppressed modprobe_rds")
  '
      ok "rds_host: rds modprobe correctly suppressed on /etc/oratab signal"
  INNER
  }
  ```

  Wire `test_rds_host` into the per-EL loop in `main`.

- [ ] **Step 8.8: Add v2.0.2 → v3.0.0 upgrade-path test**

  Add a new function `run_upgrade_test_v2_to_v3_in()` parallel to the existing `run_upgrade_test_in()`. Body:

  ```
  run_upgrade_test_v2_to_v3_in() {
      local image="$1"
      podman run --rm -i --network=host \
          -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
          "$image" /bin/bash <<'INNER'
      set -euo pipefail
      fail() { echo "FAIL: $*" >&2; exit 1; }
      ok()   { echo "ok:   $*"; }
      assert_no_scriptlet_fail() { ... same as inline elsewhere ... }
      # Add the repo (legacy copyfail.repo - serves both old + new RPMs)
      curl -sSfL "https://rfxn.github.io/copyfail/copyfail.repo" \
          -o /etc/yum.repos.d/copyfail.repo
      # Pin to v2.0.2-1
      dnf install -y copyfail-defense-1:2.0.2-1 2>&1 \
          | tee /tmp/install-old.log
      assert_no_scriptlet_fail /tmp/install-old.log
      rpm -q copyfail-defense | grep -qE 'copyfail-defense-1:2.0.2' \
          || fail "v2.0.2 install failed"
      ok "v2.0.2 baseline installed"
      # State: /var/lib/copyfail-defense/auto-detect.json should exist
      test -f /var/lib/copyfail-defense/auto-detect.json \
          || fail "v2.0.2 did not produce auto-detect.json"
      # Stage operator force-full sentinel (verifies migration moves it)
      mkdir -p /etc/copyfail
      touch /etc/copyfail/force-full
      # Upgrade
      dnf upgrade -y rfxn-defense 2>&1 | tee /tmp/upgrade.log
      assert_no_scriptlet_fail /tmp/upgrade.log
      # Verify rename
      rpm -q rfxn-defense | grep -qE 'rfxn-defense-1:3.0.0' \
          || fail "v3.0.0 upgrade failed"
      rpm -q copyfail-defense 2>/dev/null && \
          fail "copyfail-defense still present after upgrade"
      ok "rfxn-defense 3.0.0 installed; copyfail-defense gone"
      # Path migration check
      test -f /var/lib/rfxn-defense/auto-detect.json \
          || fail "auto-detect.json not migrated to /var/lib/rfxn-defense/"
      test -f /etc/rfxn-defense/force-full \
          || fail "force-full sentinel not migrated to /etc/rfxn-defense/"
      [ ! -d /var/lib/copyfail-defense ] \
          || [ -z "$(ls -A /var/lib/copyfail-defense 2>/dev/null)" ] \
          || fail "/var/lib/copyfail-defense still has contents after migration"
      python3 -c '
  import json
  d = json.load(open("/var/lib/rfxn-defense/auto-detect.json"))
  # detect.sh ran from %posttrans of new subpackages; tool_version is 3.0.0
  assert d["tool_version"] == "3.0.0", d.get("tool_version")
  print("ok: tool_version = 3.0.0")
  '
      ok "v2.0.2 -> v3.0.0 upgrade complete; paths migrated; detect.sh re-ran"
  INNER
  }
  ```

  Wire into per-EL loop after the existing `run_upgrade_test_in`.

- [ ] **Step 8.9: Add EL7 image**

  Around line 86 in the IMAGE map:

  ```bash
  declare -A IMAGE
  IMAGE[7]="quay.io/centos/centos:7"
  IMAGE[8]="docker.io/library/almalinux:8"
  IMAGE[9]="quay.io/centos/centos:stream9"
  IMAGE[10]="quay.io/centos/centos:stream10"
  ```

  Update the default ELS line:

  Old:
  ```bash
  if [ "${#ELS[@]}" -eq 0 ]; then
      ELS=(8 9 10)
  fi
  ```

  New:
  ```bash
  if [ "${#ELS[@]}" -eq 0 ]; then
      ELS=(7 8 9 10)
  fi
  ```

  Add EL7-specific dependency installation note in the inline INNER script:

  ```bash
  # EL7: python3 is provided by EPEL; install it before the auditor JSON
  # test runs (other ELs ship python3 in base; EL7's base has only python2).
  if [ "$(. /etc/os-release; echo $VERSION_ID)" = "7" ]; then
      dnf install -y epel-release >/dev/null 2>&1 || true
      dnf install -y python3 >/dev/null 2>&1
  fi
  ```

- [ ] **Step 8.10: Update test-count header comment**

  At the top of the file (around line 9-62) the comment block lists per-version test additions. Append a v3.0.0 section:

  ```
  #  v3.0.0 additions:
  #  39. rds modprobe drop file on clean host (PinTheft)
  #  40. AF_RDS in always-on 10-* systemd drop-in
  #  41. rfxn_afrds + rfxn_pidfd_getfd audit rules present
  #  42. kernel.yama.ptrace_scope key in sysctl drop-in (ssh-keysign-pwn)
  #  43. compat sbin symlinks (copyfail-shim-enable -> rfxn-shim-enable, etc.)
  #  44. state-dir migration on v2.0.2 -> v3.0.0 upgrade
  #  45. rds_host scenario: /etc/oratab triggers suppression
  #  46. v2.0.2 -> v3.0.0 upgrade-path roundtrip
  ```

- [ ] **Step 8.11: Verify**

  ```bash
  bash -n packaging/test-repo.sh && echo OK
  # expect: OK
  ```

  ```bash
  grep -c 'rfxn-defense' packaging/test-repo.sh
  # expect: >40
  ```

  ```bash
  grep -c 'copyfail-defense' packaging/test-repo.sh
  # expect: 1-3 (only run_upgrade_test_in which tests the v1.0.1->v2.0.0 chain)
  ```

  ```bash
  grep -c 'IMAGE\[7\]' packaging/test-repo.sh
  # expect: 1
  ```

  ```bash
  grep -cE 'rfxn_afrds|rfxn_pidfd_getfd' packaging/test-repo.sh
  # expect: >=2
  ```

  ```bash
  grep -c 'test_rds_host\|run_upgrade_test_v2_to_v3_in' packaging/test-repo.sh
  # expect: >=4 (definitions + invocations)
  ```

- [ ] **Step 8.12: Commit**

  ```bash
  git add -u packaging/test-repo.sh
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 8: test-repo.sh rename sweep + EL7 + new check assertions

  Bulk renames copyfail-defense* -> rfxn-defense* throughout. Adds
  EL7 image (quay.io/centos/centos:7) to IMAGE map; default ELS now
  (7 8 9 10). EL7-conditional EPEL python3 install inline.

  New v3.0.0 assertions: rds modprobe drop-file presence (PinTheft),
  AF_RDS in 10-* systemd drop-in, kernel.yama.ptrace_scope sysctl key,
  rfxn_afrds + rfxn_pidfd_getfd audit rules, compat sbin symlinks
  for copyfail-* binary names, state-dir presence post-install.

  New scenario test_rds_host: pre-stages /etc/oratab and asserts
  detect.sh suppresses modprobe_rds. New roundtrip
  run_upgrade_test_v2_to_v3_in: v2.0.2 install -> dnf upgrade rfxn-defense
  -> asserts path migration + tool_version 3.0.0 in auto-detect.json.

  Existing v1.0.1->v2.0.0 upgrade-path test (run_upgrade_test_in) is
  preserved unchanged - it documents the historical Obsoletes/Provides
  chain.
  EOF
  )"
  ```

---

### Phase 9: README + STATE.md + SPEC.md + FOLLOWUPS.md rewrites

Documentation refresh for v3.0.0 to match the renamed family, new coverage matrix, audit-key migration table, EL7 support, and forward-looking cleanup obligations.

**Files:**
- Modify: `README.md`, `STATE.md`, `SPEC.md`, `FOLLOWUPS.md`, `PLAN.md` (project root)
- Archive: `docs/plans/PLAN-v2.0.1-archive.md` (existing PLAN.md body archived before replacement)

- **Mode**: parallel-agent (5 doc files, mostly independent — 3 tracks: README+STATE, SPEC+BRIEF[BRIEF already done in Phase 7], FOLLOWUPS+PLAN.md root)
- **Accept**:
  - README.md title and badge labels reference `rfxn-defense`
  - README.md coverage matrix includes new columns/rows for PinTheft + ssh-keysign-pwn + DirtyDecrypt
  - README.md install one-liner uses `rfxn-defense.repo`
  - README.md audit-key migration table present (old→new mapping)
  - STATE.md bumped to v3.0.0
  - STATE.md ELS table now lists 7, 8, 9, 10
  - SPEC.md appendix added (v3.0.0 architecture decisions with [D-NN] continuing the numbering)
  - FOLLOWUPS.md "Open for v2.1.0" cleanup obligation now marked superseded; new "Open for v3.1.0" section added
  - PLAN.md (project root) replaced with one-line pointer to this file
  - `docs/plans/PLAN-v2.0.1-archive.md` exists (archived v2.0.1 plan)
- **Test**:
  - `grep -cE 'rfxn-defense' README.md` returns >20
  - `grep -cE 'PinTheft|ssh-keysign-pwn|CVE-2026-46333' README.md` returns ≥4
  - `grep -q 'EL7\|el7\|7\b.*8.*9.*10' STATE.md` returns rc=0 (EL7 added)
  - `git ls-files docs/plans/PLAN-v2.0.1-archive.md` returns the path (file is tracked)
- **Edge cases**:
  - **Action-first README**: per memory `feedback_action_first_docs`, the README's top should lead with "install/activate/verify" before "bug context." The existing v2.0.2 README already follows this — preserve the structure when adding rfxn-defense content.
  - **EL7 row in coverage matrix**: per-EL coverage table needs a new column. Most cells will be "Same as EL8" except for PinTheft (io_uring not present, so io_uring_disabled sysctl is irrelevant) and ssh-keysign-pwn (pidfd_getfd not present on EL7, so PoC doesn't apply — but ptrace_scope sysctl is still defense in depth).
  - **Legacy install one-liner preserved**: README should mention BOTH `rfxn-defense.repo` (canonical) and `copyfail.repo` (legacy still working) — with a note that copyfail.repo will be retired in 3.1.0.
  - **Em-dashes**: none in shipped artifacts per anti-patterns.md.
  - **No promo content / version markers in operator-facing docs**: keep tone matter-of-fact.
- **Regression-case**: N/A — docs — no executable content; user-visible at install time. README rendering on GitHub validated manually after merge.

- [ ] **Step 9.1: Archive existing PLAN.md as v2.0.1**

  ```bash
  cp PLAN.md docs/plans/PLAN-v2.0.1-archive.md
  git add docs/plans/PLAN-v2.0.1-archive.md
  ```

- [ ] **Step 9.2: Replace PLAN.md (project root) with v3.0.0 pointer**

  Full new content:

  ```markdown
  # PLAN — rfxn-defense (formerly copyfail-defense)

  ## Active plan

  v3.0.0 implementation is tracked in
  [`docs/plans/2026-05-21-rfxn-defense-rename-plan.md`](docs/plans/2026-05-21-rfxn-defense-rename-plan.md).

  ## Scope summary

  - Rename the package family `copyfail-defense` → `rfxn-defense`
    (Obsoletes/Provides chain, transparent dnf upgrade)
  - Add PinTheft (RDS + io_uring) coverage: modprobe blacklist + systemd
    `~AF_RDS` + auditd `rfxn_afrds`
  - Add CVE-2026-46333 ssh-keysign-pwn coverage: `kernel.yama.ptrace_scope=2`
    sysctl + auditd `rfxn_pidfd_getfd`
  - Cross-stamp DirtyDecrypt (CVE-2026-31635) under existing rxrpc cuts
  - Build matrix expanded to EL7-EL10
  - Audit-key rename `copyfail_*` → `rfxn_*` (SIEM-breaking; migration
    table in CHANGELOG)

  ## Historical plans

  - v2.0.1: [`docs/plans/PLAN-v2.0.1-archive.md`](docs/plans/PLAN-v2.0.1-archive.md)
  ```

- [ ] **Step 9.3: README.md rewrite — top section + install + coverage matrix**

  Replace the `<div align="center">` block header:

  Old top line:
  ```
  # copyfail-defense

  **Defense-in-depth toolkit for the Copy Fail Linux kernel bug class.**
  Covers three live LPE chains that share the same `splice()` →
  `MSG_SPLICE_PAGES` → in-place page-cache write primitive:
  ```

  New top line:
  ```
  # rfxn-defense

  *(formerly copyfail-defense — same RPM family, broader bug-class umbrella)*

  **Defense-in-depth toolkit for the kernel Local Privilege Escalation
  bug classes shipped by the rfxn.com defensive Linux primitives line.**
  Covers two kernel-LPE bug classes:

  ### Copy Fail class — page-cache overwrite of root-readable file → privileged consumer trusts cache → LPE
  ```

  Keep the existing 4-row cf-class table. Add 2 new rows after Fragnesia:

  ```
  | **PinTheft** | (CVE pending — disclosed 2026-05) | RDS zerocopy + io_uring fixed buffer | page-cache overwrite of SUID binary |
  | **DirtyDecrypt** | CVE-2026-31635 | CONFIG_RXGK in rxrpc | (covered by existing rxrpc cuts) |
  ```

  Add a new section after the cf-class table:

  ```
  ### FD-theft class — privilege confusion via SUID exit race → info disclosure → root

  | | CVE | Sink | Primitive |
  |---|---|---|---|
  | **ssh-keysign-pwn** | CVE-2026-46333 | `__ptrace_may_access()` race on SUID exit | `pidfd_getfd` steals open fd from exiting SUID |
  ```

  Update install one-liner block:

  ```bash
  sudo curl -sSL https://rfxn.github.io/copyfail/rfxn-defense.repo \
    -o /etc/yum.repos.d/rfxn-defense.repo
  sudo dnf install -y rfxn-defense
  sudo /usr/sbin/rfxn-shim-enable
  ```

  Add backward-compat note:
  ```
  > [!NOTE]
  > The legacy `copyfail.repo` URL still works on the same gh-pages
  > host through the 3.0.x release line; it is dropped in 3.1.0.
  > Upgrading from `copyfail-defense` v2.0.x is a transparent
  > `dnf upgrade rfxn-defense` — the Obsoletes/Provides chain rolls
  > over automatically.
  ```

  Update subpackage table to use `rfxn-defense-*` names and 6 + 1 soft-dep structure unchanged. Add new column "v3.0.0 additions" if helpful.

- [ ] **Step 9.4: README.md coverage matrix + new EL7 column**

  Find the existing `## Coverage matrix` table. Update to:

  ```markdown
  ## Coverage matrix

  ### EL8/EL9/EL10 (stock kernels with io_uring + pidfd_getfd)

  | Layer | cf1 | cf2 | DF-ESP | DF-RxRPC | Fragnesia | PinTheft | DirtyDecrypt | ssh-keysign-pwn |
  |---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
  | `-shim` (LD_PRELOAD AF_ALG) | ✅ primary | – | – | – | – | – | – | – |
  | `-modprobe` cf-class modules | ✅ (modular kernels) | – | – | – | – | – | – | – |
  | `-modprobe` esp4/esp6/xfrm | – | ✅ | ✅ | – | ✅ | – | – | – |
  | `-modprobe` rxrpc | – | – | – | ✅ | – | – | ✅ | – |
  | `-modprobe` rds/rds_tcp/rds_rdma | – | – | – | – | – | ✅ (PinTheft) | – | – |
  | `-systemd` `~AF_ALG`/`~AF_KEY` | ✅ | – | – | – | – | – | – | – |
  | `-systemd` `~AF_RXRPC` | – | – | – | ✅ | – | – | ✅ | – |
  | `-systemd` `~AF_RDS` | – | – | – | – | – | ✅ | – | – |
  | `-systemd` `~user ~net` | – | ✅ | ✅ | – | ✅ | – | – | – |
  | `-sysctl` `user.max_user_namespaces=0` | – | ✅ | ✅ | – | ✅ | – | – | – |
  | `-sysctl` `kernel.yama.ptrace_scope=2` | – | – | – | – | – | – | – | ✅ |
  | `-sysctl` `kernel.io_uring_disabled=2` (opt-in) | – | – | – | – | – | ✅ (secondary) | – | – |
  | `-audit` socket(AF_ALG) | ✅ tripwire | – | – | – | – | – | – | – |
  | `-audit` socket(AF_KEY) | – | ✅ | ✅ | – | ✅ | – | – | – |
  | `-audit` socket(AF_RXRPC) | – | – | – | ✅ | – | – | ✅ | – |
  | `-audit` socket(AF_RDS) | – | – | – | – | – | ✅ | – | – |
  | `-audit` pidfd_getfd(438) | – | – | – | – | – | – | – | ✅ |
  | Kernel patch | `a664bf3d` | `f4c50a4034` | `f4c50a4034` | (none upstream) | (Fragnesia in-flight) | `31e62c2ebbfd`-class | (RXGK patch series) | `31e62c2ebbfd` |

  ### EL7 (stock kernel 3.10 — no io_uring, no pidfd_getfd, no CONFIG_RXGK)

  Coverage applies as above EXCEPT:
  - **PinTheft**: not exploitable on stock EL7 kernel (io_uring added in 5.1). RDS modprobe blacklist still defense-in-depth for ELRepo `kernel-ml` hosts.
  - **ssh-keysign-pwn**: not exploitable via the public PoC on stock EL7 kernel (`pidfd_getfd` added in 5.6). `kernel.yama.ptrace_scope=2` still closes other ptrace paths to the same `__ptrace_may_access` bug.
  - **DirtyDecrypt**: not exposed (CONFIG_RXGK is newer than 3.10).

  EL7 hosts running ELRepo `kernel-lt` (5.4) or `kernel-ml` (6.x) gain the same exposure as EL9/EL10 hosts and benefit from the full coverage matrix.
  ```

- [ ] **Step 9.5: README.md audit-key migration section**

  Add a new section between "Coverage" and "Defense in depth":

  ```markdown
  ## Audit-key migration (v3.0.0 — SIEM-breaking change)

  v3.0.0 renames the auditd rule `-k` tags. Operators with SIEM/ausearch
  rules referencing the old names must update them at upgrade time.

  | Old (v2.0.x) | New (v3.0.0+) | Bug class |
  |---|---|---|
  | `copyfail_afalg` | `rfxn_afalg` | cf1 (CVE-2026-31431) |
  | `copyfail_afkey` | `rfxn_afkey` | cf2 / Dirty Frag-ESP / Fragnesia |
  | `copyfail_afrxrpc` | `rfxn_afrxrpc` | Dirty Frag-RxRPC + DirtyDecrypt |
  | *(new)* | `rfxn_afrds` | PinTheft |
  | *(new)* | `rfxn_pidfd_getfd` | ssh-keysign-pwn |

  `ausearch -k <old-name>` returns no results after upgrade; switch to
  the new keys before deploying v3.0.0 to your fleet.
  ```

- [ ] **Step 9.6: STATE.md rewrite**

  Update top section:

  ```
  # rfxn-defense — shipping state

  Snapshot: **2026-05-21**

  ## Latest release

  - **v3.0.0** — rename copyfail-defense → rfxn-defense (umbrella for
    kernel-LPE classes); adds PinTheft (RDS+io_uring) coverage,
    ssh-keysign-pwn (CVE-2026-46333) coverage, EL7 build target.
  - Tag: <https://github.com/rfxn/copyfail/releases/tag/v3.0.0>
  - v2.0.2 RPMs retained in repo trees for upgrade path
    (`dnf upgrade copyfail-defense` rolls forward via Obsoletes/Provides).
  - v1.0.1 RPMs retained in repo trees for one full cycle (clean
    upgrade path).
  - v1.0.0 was rolled back (unsigned baseline; deleted from GH releases).
  ```

  Update Distribution table:

  ```
  | DNF repo file (canonical, v3.0.0+) | <https://rfxn.github.io/copyfail/rfxn-defense.repo> |
  | DNF repo file (legacy, 3.0.x compat) | <https://rfxn.github.io/copyfail/copyfail.repo> |
  | Public signing key (canonical) | <https://rfxn.github.io/copyfail/RPM-GPG-KEY-rfxn> |
  | Public signing key (legacy filename) | <https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail> |
  | Per-EL RPM trees | `https://rfxn.github.io/copyfail/repo/{7,8,9,10}/x86_64/` |
  ```

  Update RPM family table to `rfxn-defense*` 7 rows. Update Coverage matrix mirroring the README. Update Test harness section (`bash packaging/test-repo.sh` default ELS now 7-10). Update Build / package conventions:

  ```
  - Spec: `packaging/rfxn-defense.spec`
  - Per-EL: `mock -r centos+epel-7-x86_64-vault --rebuild SRPMS/...` for EL7
            (custom chroot config in packaging/mock-config/)
  - Per-EL: `mock -r centos-stream+epel-{8,9,10}-x86_64 --rebuild SRPMS/...`
  ```

  Update Auto-detection table to include rds_workload row.

  Update Cross-repo state.

- [ ] **Step 9.7: SPEC.md append v3.0.0 architecture section**

  Append a new section continuing the existing [D-NN] numbering. Reuse the bug-class taxonomy split + the rename mechanics + EL7 addition rationale + the audit-key rename SIEM-breaking decision. New decisions:

  ```
  ## v3.0.0 architecture (drafted 2026-05-21)

  ### [D-59] copyfail-defense -> rfxn-defense rename umbrella
  Family broadens from Copy-Fail-class only to all kernel-LPE classes
  shipped by rfxn.com. Compat chain via Obsoletes/Provides; legacy
  copyfail-defense + afalg-defense both carried on every applicable
  subpackage for cheap insurance against the rare host that skipped
  v2.0.x entirely.

  ### [D-60] Bug-class taxonomy split
  Copy Fail class (page-cache overwrite): cf1, cf2, DF-RxRPC, Fragnesia,
  PinTheft, DirtyDecrypt. FD-theft class (privilege confusion via SUID
  exit race): ssh-keysign-pwn. Future bug classes get their own keys in
  the BUG_CLASSES posture dict.

  ### [D-61] PinTheft coverage primitives
  modprobe rds/rds_tcp/rds_rdma blacklist (conditional template,
  suppressed on /etc/oratab or rds*.ko-loaded hosts). systemd
  ~AF_RDS on the always-on 10-* drop-in for the 5 tenant units. auditd
  rfxn_afrds rule. sysctl kernel.io_uring_disabled=2 ships
  COMMENTED-OUT as operator opt-in (breaks containerd/podman on
  io_uring-dependent hosts).

  ### [D-62] ssh-keysign-pwn coverage primitives
  sysctl kernel.yama.ptrace_scope=2. Default 2 not 3: closes the
  pidfd_getfd path without breaking root-owned debugging. '-'-prefixed
  so Yama-less kernels silently skip. auditd rfxn_pidfd_getfd rule
  using NUMERIC syscall ref 438 since EL7+EL8 audit-userspace does not
  recognise the name string.

  ### [D-63] Audit-key rename
  copyfail_* -> rfxn_*. SIEM-breaking change documented in CHANGELOG +
  README migration table. No dual-keyed rules (would double auditd load).

  ### [D-64] EL7 build target re-added
  Original constraint dropped EL7 at v2.0.0 ("we no longer build for
  EL7"). v3.0.0 re-adds EL7 via custom mock chroot pointing at
  vault.centos.org for base/updates + archives.fedoraproject.org for
  EPEL. Affected vulnerability matrix on EL7 stock kernel 3.10:
  cf1+cf2+DF-RxRPC+Fragnesia ARE exposed; PinTheft+ssh-keysign-pwn+
  DirtyDecrypt are NOT exposed (kernel feature floor predates them).

  ### [D-65] State path migration via %pretrans meta
  /var/lib/copyfail-defense/ -> /var/lib/rfxn-defense/. /etc/copyfail/
  -> /etc/rfxn-defense/. modprobe/systemd/sysctl/audit conf filenames
  rename in place. Migration handled per-subpackage in %pretrans; meta
  %pretrans handles /var/lib/ and /etc/. Compat sbin symlinks
  (copyfail-shim-enable -> rfxn-shim-enable, etc.) shipped for the
  3.0.x line.
  ```

- [ ] **Step 9.8: FOLLOWUPS.md rewrite**

  - Mark "Open for v2.1.0" section as superseded (the `afalg-defense` Obsoletes/Provides drop is now folded into v3.1.0; v3.0.0 still carries both)
  - Add new "Open for v3.1.0" section:
    ```
    ## Open for v3.1.0
    - [ ] Drop `Obsoletes:`/`Provides: copyfail-defense*` chain
    - [ ] Drop `Obsoletes:`/`Provides: afalg-defense*` chain
    - [ ] Drop sbin compat symlinks (copyfail-shim-enable, copyfail-shim-disable,
          copyfail-redetect, copyfail-local-check)
    - [ ] Drop /etc/yum.repos.d/copyfail.repo from gh-pages publish
    - [ ] Drop RPM-GPG-KEY-copyfail from gh-pages publish (same key bytes
          continue to be served as RPM-GPG-KEY-rfxn)
    - [ ] Drop %pretrans v2.0.x->v3.0.0 path-migration blocks from spec
    - [ ] Drop v2.0.2 RPMs from repo trees once 3.0.x is stable
    ```
  - Add "Shipped in v3.0.0 (2026-05-21)" section above the existing v2.0.2 shipped block, summarizing this release
  - Update "v2.0.2 watch list" to note the io_uring_disabled monitoring item (does field deployment ever toggle it on?)
  - Add "v3.0.0 watch list" with new items:
    ```
    - [ ] PinTheft CVE assignment - when the CVE lands, cross-stamp
          README/SPEC/CHANGELOG and update auditor BUG_CLASSES["pintheft"]["primary_cve"]
    - [ ] EL7 vault availability monitoring - if vault.centos.org becomes
          unavailable, EL7 builds degrade to "best-effort native build, no
          mock canary." Document the transition in STATE.md.
    - [ ] DirtyDecrypt verification revisited if the PoC writeup reveals
          a primitive NOT covered by rxrpc cuts
    - [ ] SIEM-rule operator outreach: monitor for support questions about
          missing copyfail_* audit-key matches and update the README
          migration table if other key-rename details surface
    ```

- [ ] **Step 9.9: Verify**

  ```bash
  grep -cE 'rfxn-defense' README.md
  # expect: >20
  ```

  ```bash
  grep -cE 'PinTheft|ssh-keysign-pwn|CVE-2026-46333' README.md
  # expect: >=4
  ```

  ```bash
  grep -q '^v3.0.0' STATE.md
  # expect: rc=0
  ```

  ```bash
  grep -qE '\| 7 \|.*\|.*\|' STATE.md
  # expect: rc=0 (EL7 in some table)
  ```

  ```bash
  test -f docs/plans/PLAN-v2.0.1-archive.md && wc -l docs/plans/PLAN-v2.0.1-archive.md
  # expect: nonzero line count
  ```

  ```bash
  grep -c 'docs/plans/2026-05-21-rfxn-defense-rename-plan.md' PLAN.md
  # expect: >=1
  ```

- [ ] **Step 9.10: Commit**

  ```bash
  git add docs/plans/PLAN-v2.0.1-archive.md
  git add -u README.md STATE.md SPEC.md FOLLOWUPS.md PLAN.md
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 9: documentation refresh for rfxn-defense rename

  - README: rebrand, two-class taxonomy, expanded coverage matrix
    (8 columns: cf1/cf2/DF-ESP/DF-RxRPC/Fragnesia/PinTheft/DirtyDecrypt/
    ssh-keysign-pwn), EL7 row, audit-key migration table
  - STATE.md: v3.0.0 snapshot, 7-EL targets, paths updated, auto-detect
    table gains rds_workload row
  - SPEC.md: append v3.0.0 architecture section with [D-59..D-65]
  - FOLLOWUPS.md: shipped block for v3.0.0, new v3.1.0 cleanup queue,
    new v3.0.0 watch list (PinTheft CVE assignment, EL7 vault watch,
    DirtyDecrypt re-verify, SIEM operator outreach)
  - PLAN.md (root): replaced with one-line pointer to docs/plans/...
  - docs/plans/PLAN-v2.0.1-archive.md: archived v2.0.1 plan body
  EOF
  )"
  ```

---

### Phase 10: .rdf/governance updates

Update governance docs to match the renamed family and re-added EL7 build target. These files are the QA agent's authoritative source for what to check; staleness here causes QA failures.

**Files:**
- Modify: `.rdf/governance/architecture.md`, `.rdf/governance/conventions.md`, `.rdf/governance/constraints.md`, `.rdf/governance/verification.md`, `.rdf/governance/anti-patterns.md`, `.rdf/governance/index.md`

- **Mode**: parallel-agent (6 governance docs, mostly independent — 2 tracks: arch+constraints+conventions, verification+anti-patterns+index)
- **Accept**:
  - `grep -c 'copyfail-defense' .rdf/governance/*.md` returns ≤6 (each file: 1 historical context reference allowed; everything else renamed)
  - `grep -c 'rfxn-defense' .rdf/governance/*.md` returns >30
  - `grep -q 'EL 7\|EL versions: 7\b\|el7\|EL7' .rdf/governance/constraints.md` returns rc=0 (EL7 added)
  - `grep -q 'rfxn-defense.spec' .rdf/governance/verification.md` returns rc=0 (build invocation updated)
- **Test**: `grep -r 'copyfail-defense' .rdf/governance/` audit; only allowed in historical-reference comment blocks.
- **Edge cases**:
  - **`Mode: development`** in index.md may stay as-is (project state). The plan pointer changes.
  - **EL7 build invocation** in conventions.md and verification.md must reference the custom vault mock chroot config produced in Phase 11.
  - **Anti-patterns** file gets ONE new entry — "DO NOT cross-pollinate copyfail_* and rfxn_* audit keys in CHANGELOG migration tables" — and historical anti-patterns (preload safety, per-EL cross-install) preserved verbatim.
- **Regression-case**: N/A — governance — read-only authoritative refs; QA agent reads them; downstream phases tested empirically. Stale governance = QA-pass false positive, caught by the test-repo.sh real-RPM canary.

- [ ] **Step 10.1: architecture.md**
  - Project Overview: `copyfail-defense → rfxn-defense in v3.0.0` (was: `→ copyfail-defense in v2.0.0`)
  - Components table: all paths renamed
  - Defense layers section: add PinTheft (AF_RDS / RDS modprobe) + ssh-keysign-pwn (Yama ptrace_scope) layers
  - URL list update: rfxn-defense.repo + RPM-GPG-KEY-rfxn

- [ ] **Step 10.2: conventions.md**
  - File organization tree: rename all `packaging/copyfail-*` → `rfxn-*`
  - "Naming" section: add v3.0.0 entry — "RPM family rename: copyfail-defense → rfxn-defense; Obsoletes/Provides chain"
  - Per-EL build invocation: add the EL7 mock chroot reference
  - Update `Conventions` to clarify: "Audit-key prefix is `rfxn_` for v3.0.0+; v2.0.x used `copyfail_`"

- [ ] **Step 10.3: constraints.md**
  - Platform targets: change "EL versions: 8, 9, 10" to "EL versions: 7, 8, 9, 10"
  - Per-EL details table: add EL7 row
  - Build host: note EL7 mock dependency on vault.centos.org
  - Backwards compatibility section: add v3.0.0 entry — "RPM rename copyfail-defense → rfxn-defense; Obsoletes/Provides chain retained through 3.0.x; dropped in 3.1.0"
  - Update "**C (shim)**: gcc 4.8+ (EL7 era — kept for safety even though we no longer build for EL7)" to drop the "no longer build for EL7" clause

- [ ] **Step 10.4: verification.md**
  - Build flow: `packaging/copyfail-defense.spec` → `packaging/rfxn-defense.spec` everywhere
  - mock invocation: add EL7 case
  - test-repo.sh: ELS default to (7 8 9 10); images table includes EL7
  - manual checks: `copyfail-local-check` → `rfxn-local-check`

- [ ] **Step 10.5: anti-patterns.md**
  - Add new entry (after "DO NOT use `zstd` for repo metadata"):
    ```markdown
    ## DO NOT cross-pollinate copyfail_* and rfxn_* audit keys

    v3.0.0 renames auditd rule -k tags from `copyfail_*` to `rfxn_*`.
    Adding dual-keyed rules ("ship both for SIEM compatibility") doubles
    auditd's record output on every socket(AF_ALG) call - measurable
    fleet-wide perf hit. The accepted breaking change is documented
    in CHANGELOG with a migration table; SIEM operators update their
    `ausearch -k <key>` queries at upgrade time. Do not "soften" by
    shipping dual keys.
    ```
  - Keep all existing entries unchanged

- [ ] **Step 10.6: index.md**
  - Project name: `copyfail` (project) / `rfxn-defense` (RPM family, was: copyfail-defense in v2.0.0)
  - Active Plan pointer: `docs/plans/2026-05-21-rfxn-defense-rename-plan.md`

- [ ] **Step 10.7: Verify**

  ```bash
  grep -c 'rfxn-defense' .rdf/governance/*.md
  # expect: >30 (per-file counts vary)
  ```

  ```bash
  grep -c 'copyfail-defense' .rdf/governance/*.md
  # expect: <=6 (only historical-context refs)
  ```

  ```bash
  grep -q 'EL versions: 7, 8, 9, 10\|EL 7\b' .rdf/governance/constraints.md
  # expect: rc=0
  ```

  ```bash
  grep -q 'rfxn-defense.spec' .rdf/governance/verification.md
  # expect: rc=0
  ```

  ```bash
  grep -q 'rfxn-defense-rename-plan.md' .rdf/governance/index.md
  # expect: rc=0
  ```

- [ ] **Step 10.8: Commit**

  ```bash
  git add -u .rdf/governance/
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 10: governance updates for rfxn-defense rename

  architecture/conventions/constraints/verification/anti-patterns/index
  all updated: paths renamed, EL7 added to platform targets, ptrace_scope
  + PinTheft defense layers documented, audit-key rename anti-pattern
  added (DO NOT dual-key copyfail_* + rfxn_*).
  EOF
  )"
  ```

---

### Phase 11: gh-pages metadata + EL7 mock chroot config

Two artifacts that must exist before the mock build can run for v3.0.0: an EL7 mock chroot config pointing at vault.centos.org, and the gh-pages repo metadata for the new `rfxn-defense.repo` filename.

**Files:**
- Create: `packaging/mock-config/epel-7-x86_64-vault.cfg` — mock chroot config for EL7 with vault.centos.org URLs

- **Mode**: serial-context (single small config file)
- **Accept**:
  - `test -f packaging/mock-config/epel-7-x86_64-vault.cfg` returns rc=0
  - `python3 -m py_compile packaging/mock-config/epel-7-x86_64-vault.cfg` returns rc=0 (mock configs are Python — syntax check via py_compile, NOT `exec()` which raises NameError on `config_opts`)
  - URLs in the config resolve when queried (`curl -sI <url>` returns HTTP/2 200 or HTTP/1.1 200)
- **Test**: Phase 12 mock build invocation against `-r packaging/mock-config/epel-7-x86_64-vault.cfg` is the integration test.
- **Edge cases**:
  - **Vault URL drift**: vault.centos.org canonical path is `vault.centos.org/centos/7.9.2009/{os,updates,extras}/x86_64/`. EPEL 7 lives at `archives.fedoraproject.org/pub/archive/epel/7/x86_64/`. These URLs were live as of 2026-05-21 per RPM Fusion + CentOS community archives. If they break before release, EL7 build degrades to "best-effort native rpmbuild on the build host" (no chroot isolation; signed and published anyway, but no canary).
  - **mock plugin versions**: newer mock (≥3.0) deprecates some pre-2.0 plugin keys. Stick to the standard set used by `centos-stream+epel-9-x86_64.cfg` etc., just with vault URLs.
  - **`config_opts['root']`** value should be `epel-7-x86_64-vault` so the chroot dir is `/var/lib/mock/epel-7-x86_64-vault/`.
- **Regression-case**: N/A — refactor — single mock chroot config file, exercised by Phase 12 mock invocation. Failure surfaces as Phase 12 build break for EL7 only; documented degradation path (drop EL7 from this release) preserves EL8-EL10 shippability.

- [ ] **Step 11.1: Create `packaging/mock-config/epel-7-x86_64-vault.cfg`**

  Full content (use as starting template; verify URLs at Phase 12 build time):

  ```python
  config_opts['root'] = 'epel-7-x86_64-vault'
  config_opts['target_arch'] = 'x86_64'
  config_opts['legal_host_arches'] = ('x86_64',)
  config_opts['chroot_setup_cmd'] = 'install bash bzip2 coreutils cpio diffutils findutils gawk gcc gcc-c++ grep gzip info make patch redhat-release redhat-rpm-config rpm-build sed shadow-utils tar unzip util-linux which xz'
  config_opts['dist'] = 'el7'
  config_opts['releasever'] = '7'
  config_opts['package_manager'] = 'yum'
  config_opts['yum.conf'] = """
  [main]
  keepcache=1
  debuglevel=2
  reposdir=/dev/null
  logfile=/var/log/yum.log
  retries=20
  obsoletes=1
  gpgcheck=0
  assumeyes=1
  syslog_ident=mock
  syslog_device=
  install_weak_deps=0
  metadata_expire=0
  best=1

  # Vault mirrors - mainline mirror.centos.org is dead for 7.x.
  # These archive servers were live as of 2026-05-21 per community
  # tracking. Monitor availability via Phase 12 build canary.

  [base]
  name=CentOS-7 - Base (Vault)
  baseurl=https://vault.centos.org/centos/7.9.2009/os/x86_64/
  gpgcheck=0
  enabled=1

  [updates]
  name=CentOS-7 - Updates (Vault)
  baseurl=https://vault.centos.org/centos/7.9.2009/updates/x86_64/
  gpgcheck=0
  enabled=1

  [extras]
  name=CentOS-7 - Extras (Vault)
  baseurl=https://vault.centos.org/centos/7.9.2009/extras/x86_64/
  gpgcheck=0
  enabled=1

  [epel]
  name=EPEL 7 (archive)
  baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/
  gpgcheck=0
  enabled=1
  """
  ```

- [ ] **Step 11.2: Verify**

  ```bash
  python3 -m py_compile packaging/mock-config/epel-7-x86_64-vault.cfg && echo OK
  # expect: OK
  ```

  ```bash
  curl -sI 'https://vault.centos.org/centos/7.9.2009/os/x86_64/repodata/repomd.xml' | head -1
  # expect: HTTP/2 200 (or HTTP/1.1 200 OK)
  ```

  ```bash
  curl -sI 'https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/repodata/repomd.xml' | head -1
  # expect: HTTP/2 200 (or HTTP/1.1 200 OK)
  ```

  If any of the curl checks fail, the EL7 build target is not shippable; surface to the user, document in FOLLOWUPS.md, and continue with EL8-EL10 mock builds only.

- [ ] **Step 11.3: Commit**

  ```bash
  mkdir -p packaging/mock-config
  git add packaging/mock-config/epel-7-x86_64-vault.cfg
  git commit -m "$(cat <<'EOF'
  v3.0.0 phase 11: EL7 mock chroot config with vault.centos.org URLs

  CentOS 7 mirror.centos.org mainline is dead post-EOL (2024-06-30);
  point base/updates/extras at vault.centos.org/centos/7.9.2009/ and
  EPEL 7 at archives.fedoraproject.org/pub/archive/epel/7/. URLs
  verified reachable 2026-05-21. EL7 builds degrade to "best-effort
  native rpmbuild, no mock canary" if vault becomes unreachable -
  monitored under v3.0.0 watch list in FOLLOWUPS.md.
  EOF
  )"
  ```

---

═══════════════════════════════════════════════════════════════════
║ BUILD/PUBLISH BOUNDARY ║
═══════════════════════════════════════════════════════════════════

### Phase 12: Mock build × 4 EL + sign + createrepo + repomd sign

The canary for the entire v3.0.0 release. Build per-EL binary RPMs from the spec on freedom, sign every RPM with the production key, build repodata via createrepo_c, detach-sign repomd.xml, run test-repo.sh against gh-pages-staging.

**Files:**
- Create (in `rpmbuild/` — gitignored):
  - `rpmbuild/SOURCES/rfxn-defense-3.0.0.tar.gz` (project tarball)
  - `rpmbuild/SRPMS/rfxn-defense-3.0.0-1.<dist>.src.rpm`
  - `rpmbuild/RPMS/<arch>/rfxn-defense-*-3.0.0-1.<dist>.<arch>.rpm` (7 subpackages × 4 ELs = 28 binary RPMs, plus 4 SRPMs)
  - `rpmbuild/gh-pages-staging/repo/{7,8,9,10}/x86_64/repodata/{repomd.xml,repomd.xml.asc,...}` (signed repodata)
- Modify: none (gitignored output)

- **Mode**: serial-context (manual build host, /root/.gnupg required, not delegated to agents)
- **Accept**:
  - 4 SRPMs built (one per EL)
  - 28 binary RPMs built (7 subpackages × 4 ELs)
  - `rpm -K <rpm>` returns "MD5 GPG OK" for every binary RPM (28/28 signed)
  - `gpg --verify rpmbuild/gh-pages-staging/repo/7/x86_64/repodata/repomd.xml.asc` returns "Good signature" (and same for 8/9/10)
  - `bash packaging/test-repo.sh` with `REPO_URL=file:///home/copyfail/rpmbuild/gh-pages-staging` returns rc=0 across all 4 ELs (~50 checks each)
- **Test**: test-repo.sh against staging is the canary. Per memory `feedback_test_repo_before_done.md`: "do not declare a release done without packaging/test-repo.sh PASSing in containers."
- **Edge cases**:
  - **EL7 mock chroot failure**: vault unreachable. Fallback: native rpmbuild on freedom, document in CHANGELOG that EL7 RPM is unmocked; mark EL7 as "best-effort" in STATE.md.
  - **Mock proc-sub stderr-tee**: per memory `project_v2_0_1_2_shipped`, scriptlets that use bash process substitution need `-p /bin/bash`. v3.0.0 spec must NOT regress this on existing scriptlets and must NOT introduce new proc-sub without bash header. Phase 12 catches scriptlet syntax errors via test-repo.sh's `assert_no_scriptlet_fail` (added in v2.0.1-2 to catch exactly this class of bug).
  - **createrepo_c compression**: MUST be `gz`, NOT `zstd`, for older-dnf compat per anti-patterns.md. Use `--general-compress-type=gz`.
  - **Upgrade-fixture for run_upgrade_test_v2_to_v3_in**: Phase 12 needs v2.0.2 RPMs staged in `rpmbuild/upgrade-fixture/` so the upgrade-path test runs in containers without needing a live gh-pages serving v2.0.2. Reuse the existing pattern (run_upgrade_test_in uses `UPGRADE_FIXTURE_DIR`).
- **Regression-case**: `packaging/test-repo.sh::ALL` — security — covers the entire v3.0.0 release surface via `dnf install rfxn-defense` against gh-pages-staging across EL7/8/9/10. Per memory `feedback_test_repo_before_done.md`, this is the project's standing canary; failure blocks publish.

- [ ] **Step 12.1: Build tarball**

  ```bash
  cd /home/copyfail
  rm -rf rpmbuild/SOURCES/rfxn-defense-3.0.0
  mkdir -p rpmbuild/SOURCES
  git archive --prefix=rfxn-defense-3.0.0/ -o rpmbuild/SOURCES/rfxn-defense-3.0.0.tar.gz HEAD
  test -s rpmbuild/SOURCES/rfxn-defense-3.0.0.tar.gz && echo OK
  # expect: OK
  ```

- [ ] **Step 12.2: Stage all Sources to SOURCES dir**

  ```bash
  for f in packaging/rfxn-shim-enable packaging/rfxn-shim-disable \
           packaging/rfxn-modprobe-cf1.conf packaging/rfxn-systemd-dropin.conf \
           packaging/rfxn-systemd-dropin-containers.conf \
           packaging/rfxn-modprobe-cf2-xfrm.conf packaging/rfxn-modprobe-rxrpc.conf \
           packaging/rfxn-systemd-dropin-userns.conf \
           packaging/rfxn-defense-detect.sh packaging/rfxn-redetect \
           packaging/rfxn-systemd-dropin-rxrpc-af.conf \
           packaging/rfxn-sysctl-userns.conf packaging/rfxn-defense-audit.rules \
           packaging/rfxn-modprobe-rds.conf packaging/rfxn-systemd-dropin-rds.conf; do
      cp -v "$f" rpmbuild/SOURCES/
  done
  ```

- [ ] **Step 12.3: Build SRPM**

  ```bash
  rpmbuild --define "_topdir /home/copyfail/rpmbuild" -bs packaging/rfxn-defense.spec
  ls -1 rpmbuild/SRPMS/rfxn-defense-3.0.0-1.*.src.rpm
  # expect: one .src.rpm
  ```

- [ ] **Step 12.4: Mock rebuild × 4 ELs**

  EL8/EL9/EL10 use stock mock configs:
  ```bash
  for el in 8 9 10; do
      mock -r centos-stream+epel-${el}-x86_64 --no-bootstrap-chroot \
           --rebuild rpmbuild/SRPMS/rfxn-defense-3.0.0-1.*.src.rpm
      # Copy results into gh-pages-staging
      mkdir -p rpmbuild/gh-pages-staging/repo/${el}/x86_64/
      cp /var/lib/mock/centos-stream+epel-${el}-x86_64/result/*.rpm \
         rpmbuild/gh-pages-staging/repo/${el}/x86_64/
  done
  ```

  EL7 uses the custom vault chroot config from Phase 11:
  ```bash
  mock -r packaging/mock-config/epel-7-x86_64-vault.cfg --no-bootstrap-chroot \
       --rebuild rpmbuild/SRPMS/rfxn-defense-3.0.0-1.*.src.rpm
  mkdir -p rpmbuild/gh-pages-staging/repo/7/x86_64/
  cp /var/lib/mock/epel-7-x86_64-vault/result/*.rpm \
     rpmbuild/gh-pages-staging/repo/7/x86_64/
  ```

  Verify counts:
  ```bash
  for el in 7 8 9 10; do
      n=$(ls -1 rpmbuild/gh-pages-staging/repo/${el}/x86_64/*.rpm 2>/dev/null | wc -l)
      echo "EL${el}: ${n} RPMs"
      [ "$n" -eq 8 ] || echo "WARN: expected 8 RPMs per EL (7 binary + 1 SRPM or similar mock layout)"
  done
  # expect: 8 RPMs each (meta + 6 subpackages + SRPM copy; mock layout may vary)
  ```

- [ ] **Step 12.5: Sign every RPM**

  ```bash
  for el in 7 8 9 10; do
      rpmsign --addsign rpmbuild/gh-pages-staging/repo/${el}/x86_64/*.rpm
  done
  for el in 7 8 9 10; do
      rpm -K rpmbuild/gh-pages-staging/repo/${el}/x86_64/*.rpm | grep -v 'GPG OK' \
          && echo "FAIL: unsigned RPM detected in EL${el}" && exit 1
  done
  echo "all RPMs signed"
  ```

- [ ] **Step 12.6: createrepo_c per EL + detach-sign repomd**

  ```bash
  for el in 7 8 9 10; do
      createrepo_c --general-compress-type=gz \
                   rpmbuild/gh-pages-staging/repo/${el}/x86_64/
      gpg --detach-sign --armor \
          -o rpmbuild/gh-pages-staging/repo/${el}/x86_64/repodata/repomd.xml.asc \
          rpmbuild/gh-pages-staging/repo/${el}/x86_64/repodata/repomd.xml
  done
  for el in 7 8 9 10; do
      gpg --verify rpmbuild/gh-pages-staging/repo/${el}/x86_64/repodata/repomd.xml.asc \
          2>&1 | grep -q 'Good signature' \
          || { echo "FAIL: repomd.xml.asc signature for EL${el} not Good"; exit 1; }
  done
  echo "all repodata signed"
  ```

- [ ] **Step 12.7: Stage gh-pages root files**

  ```bash
  cp packaging/rfxn-defense.repo rpmbuild/gh-pages-staging/
  cp packaging/copyfail.repo rpmbuild/gh-pages-staging/  # legacy compat
  cp packaging/RPM-GPG-KEY-rfxn rpmbuild/gh-pages-staging/
  cp packaging/RPM-GPG-KEY-copyfail rpmbuild/gh-pages-staging/  # legacy compat
  ```

- [ ] **Step 12.8: Stage v2.0.2 RPMs to upgrade-fixture**

  ```bash
  mkdir -p rpmbuild/upgrade-fixture/v2.0.2
  # Pull v2.0.2 RPMs from existing gh-pages or local cache
  for el in 8 9 10; do
      # use either existing rpmbuild/RPMS staging or curl from live gh-pages
      curl -sL "https://rfxn.github.io/copyfail/repo/${el}/x86_64/" -o /tmp/idx.html
      # ... pull copyfail-defense-2.0.2 RPMs ...
  done
  # If v2.0.2 RPMs aren't readily available locally, defer upgrade-fixture
  # test to post-publish phase (v3.0.0.x hotfix scenario).
  ```

  **Decision note**: if v2.0.2 RPMs aren't readily stageable as fixtures, skip the v2.0.2→v3.0.0 upgrade-path test in Phase 12 and verify it post-publish (against the live gh-pages serving both versions). Document the deferral in STATE.md.

- [ ] **Step 12.9: Run test-repo.sh against staging**

  ```bash
  REPO_URL=file:///home/copyfail/rpmbuild/gh-pages-staging/rfxn-defense.repo \
  KEY_URL=file:///home/copyfail/rpmbuild/gh-pages-staging/RPM-GPG-KEY-rfxn \
      bash packaging/test-repo.sh
  echo "test-repo.sh rc=$?"
  # expect: ALL CHECKS PASSED for each EL (7, 8, 9, 10); rc=0
  ```

  If any EL fails: debug locally, re-build (potentially re-spec) before publishing. No partial publishes.

- [ ] **Step 12.10: Commit nothing — `rpmbuild/` is gitignored**

  No commit in Phase 12. The build output exists locally; Phase 13 publishes it.

---

### Phase 13: Release v3.0.0 — tag, gh-pages push, GH release

Final phase: tag v3.0.0 in the source repo, push gh-pages staging to the live branch, create the GitHub release with all signed RPMs + SRPMs + public key + repo file as assets.

**Files:** none to modify; this phase publishes the artifacts built in Phase 12 and the source commits from Phases 1-11.

- **Mode**: serial-context (manual; uses `gh` CLI + `git push origin gh-pages`)
- **Accept**:
  - `git tag` lists `v3.0.0` at the head of `main`
  - `git push origin v3.0.0` succeeds (remote tag exists)
  - `git push origin main` pushes Phases 1-11 commits
  - `gh release view v3.0.0` shows ≥35 assets (4×7 RPMs + 4 SRPMs + RPM-GPG-KEY-rfxn + RPM-GPG-KEY-copyfail + rfxn-defense.repo + copyfail.repo)
  - `curl -sSL https://rfxn.github.io/copyfail/rfxn-defense.repo` returns the file (gh-pages live)
  - `dnf install -y rfxn-defense` succeeds on a fresh container against the live gh-pages — final canary
- **Test**:
  - Last canary: a fresh `quay.io/centos/centos:stream10` container, `curl` the published `rfxn-defense.repo`, `dnf install -y rfxn-defense`, expect everything to work. Same for EL7/8/9.
- **Edge cases**:
  - **`v3.0.0` tag already exists** (from a failed previous attempt): `git tag -d v3.0.0 && git push --delete origin v3.0.0` only if safe; document why in commit message.
  - **gh-pages branch**: this project uses a flat gh-pages branch with `repo/{7,8,9,10}/x86_64/` subtrees. Push as fast-forward, no rebase. The staging dir from Phase 12 mirrors the live tree structure.
  - **GH release notes**: copy the v3.0.0 CHANGELOG entry from spec verbatim. Markdown converts cleanly.
- **Regression-case**: Step 13.4 final canary — security — fresh container against live gh-pages must `dnf install -y rfxn-defense` cleanly on each EL. This is the last possible failure point before public exposure; passing it shifts the release from "pending" to "shipped" in STATE.md.

- [ ] **Step 13.1: Tag v3.0.0 on main**

  ```bash
  git checkout main
  git pull --ff-only origin main
  git tag -s v3.0.0 -m "v3.0.0: rfxn-defense rename + PinTheft + ssh-keysign-pwn coverage + EL7"
  git push origin v3.0.0
  git push origin main
  ```

- [ ] **Step 13.2: Push gh-pages**

  ```bash
  cd /home/copyfail
  ./scripts/publish-gh-pages.sh rpmbuild/gh-pages-staging/  # (or equivalent existing project script)
  # OR manual (explicit staging - never `git add -A` per project CRITICAL rule):
  git worktree add /tmp/gh-pages-publish gh-pages
  rsync -av --delete rpmbuild/gh-pages-staging/ /tmp/gh-pages-publish/
  cd /tmp/gh-pages-publish
  # Explicit stage of the known gh-pages tree contents. Adjust the
  # paths if the project's gh-pages layout differs.
  git add repo/ \
          rfxn-defense.repo copyfail.repo \
          RPM-GPG-KEY-rfxn RPM-GPG-KEY-copyfail
  # Pick up modifications to any existing files (excludes new untracked).
  git add -u
  git commit -m "v3.0.0 publish: rfxn-defense RPMs + repo metadata for EL7-EL10"
  git push origin gh-pages
  cd /home/copyfail
  git worktree remove /tmp/gh-pages-publish
  ```

- [ ] **Step 13.3: Create GitHub release with all assets**

  ```bash
  # Stage all assets
  mkdir -p /tmp/v3.0.0-assets
  cp rpmbuild/gh-pages-staging/repo/*/x86_64/*.rpm /tmp/v3.0.0-assets/
  cp rpmbuild/SRPMS/rfxn-defense-3.0.0-1*.src.rpm /tmp/v3.0.0-assets/
  cp packaging/rfxn-defense.repo /tmp/v3.0.0-assets/
  cp packaging/copyfail.repo /tmp/v3.0.0-assets/
  cp packaging/RPM-GPG-KEY-rfxn /tmp/v3.0.0-assets/
  cp packaging/RPM-GPG-KEY-copyfail /tmp/v3.0.0-assets/

  # Extract release notes from CHANGELOG
  awk '/^\* Thu May 21 2026/,/^\* Wed May 13 2026/' packaging/rfxn-defense.spec \
      | head -n -2 > /tmp/v3.0.0-release-notes.md

  gh release create v3.0.0 \
      --title "v3.0.0: rfxn-defense rename + PinTheft + ssh-keysign-pwn + EL7" \
      --notes-file /tmp/v3.0.0-release-notes.md \
      /tmp/v3.0.0-assets/*
  ```

- [ ] **Step 13.4: Final canary against live gh-pages**

  EL7 uses a different image-tag scheme than EL8/9/10 (no "stream" prefix; `centos:7` not `centos:stream7`). Use the IMAGE map established in test-repo.sh:

  ```bash
  declare -A FINAL_IMAGE
  FINAL_IMAGE[7]="quay.io/centos/centos:7"
  FINAL_IMAGE[8]="docker.io/library/almalinux:8"
  FINAL_IMAGE[9]="quay.io/centos/centos:stream9"
  FINAL_IMAGE[10]="quay.io/centos/centos:stream10"
  for el in 7 8 9 10; do
      podman run --rm -i "${FINAL_IMAGE[$el]}" /bin/bash <<'INNER' 2>&1 | tail -20
      . /etc/os-release
      if [ "$VERSION_ID" = "7" ]; then
          # EL7 base lacks python3; pull EPEL.
          yum install -y epel-release >/dev/null 2>&1
          yum install -y python3 >/dev/null 2>&1
      fi
      curl -sSL https://rfxn.github.io/copyfail/rfxn-defense.repo \
          -o /etc/yum.repos.d/rfxn-defense.repo
      dnf install -y rfxn-defense 2>&1 | tail -5 \
          || yum install -y rfxn-defense 2>&1 | tail -5
      rpm -q rfxn-defense | grep -qE '3\.0\.0' && echo "EL${VERSION_ID}: 3.0.0 installed"
  INNER
  done
  # expect: all 4 ELs print "EL${VERSION_ID}: 3.0.0 installed"
  ```

- [ ] **Step 13.5: Update STATE.md cross-repo state**

  ```bash
  # Edit STATE.md to update commit-hash placeholders to actual hashes
  HEAD_SHA=$(git rev-parse HEAD)
  GH_PAGES_SHA=$(git ls-remote origin gh-pages | awk '{print $1}')
  # ... sed STATE.md ...
  git add -u STATE.md
  git commit -m "v3.0.0 post-publish: STATE.md cross-repo state hashes"
  git push origin main
  ```

- [ ] **Step 13.6: Mark v3.0.0 shipped in memory**

  Update memory entry `project_copyfail_release_flow.md` (or analogous) to note v3.0.0 shipped at this commit. Update `MEMORY.md` index.

  (This step is documentation-only; not part of the release artifact.)

---











