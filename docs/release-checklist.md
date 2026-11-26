# Release checklist (v0.1.0 and later)

**Owner actions** are marked 👤. They need the maintainer's authorization: nothing in this repository
pushes, tags or publishes on its own (REQUIREMENTS.md §17). Tick each box in the release notes, with the
date and the result.

## 1. Before the first publication: history and content audit

- [ ] **gitleaks over the full history** (the same pinned version as CI, checksum verified):
  ```bash
  gitleaks git --redact --no-banner --exit-code 1 .        # uses .gitleaks.toml and .gitleaksignore
  ```
  Expected: `no leaks found`. Every entry in `.gitleaksignore` and the `SYNTHETIC` allowlist in
  `.gitleaks.toml` must be reviewed: they cover synthetic test data only (the jwt.io sample JWT, the RFC
  6455 sample WebSocket key, hexadecimal placeholder values, stub key blocks, `SYNTHETIC…` canaries). Last
  run: 2026-11-24, gitleaks 8.30.1, 13 commits (through the M4 commit), no leaks after the review (14 reviewed fingerprints).
- [ ] **Working tree**: `gitleaks dir --redact .` reports only the reviewed synthetic test data above.
- [ ] **Manual history skim**: `git log --stat --all` and `git log -p --all -- '*.jsonl' '*.toml' '*.json' '*.md'`.
  Look for real names, e-mail addresses other than the author's, home paths, hostnames, real project
  names, real session content and tokens. Fixtures must be synthetic (`tests/fixtures/sessions/` uses
  `@HOME@` and patterned UUIDs).
- [ ] `git check-ignore` hygiene test passes (`cargo test --test hygiene`, acceptance test 9). No database,
  socket, config, state or stray `*.jsonl` is tracked: `git ls-files | grep -Ev '^tests/fixtures/' | grep -E '\.(db|sock|jsonl)$'` prints nothing.
- [ ] 👤 **Naming conflicts** (REQUIREMENTS.md §1, open item O3): check crates.io, GitHub and distribution
  package names for `ccwm` and `cc-workspace-manager`. This needs outbound requests: the owner does it.
- [ ] 👤 **Repository recreation** (recommended for the first publication): publish a **fresh**
  repository whose history starts from the audited tree, if any commit message or file in the old
  history should not become public. One way: `git checkout --orphan public && git add -A && git commit -s
  -m "Initial public release"`. Run gitleaks again on the new history. Add the remote and push only
  after that. Keep the private history locally.
- [ ] Record the audit (commands, versions, results, date) in the release notes (§17).

## 2. Every release: verification

- [ ] `Cargo.toml` `version` = the tag without `v`. `CHANGELOG.md` has the section. `README.md` status line
  is current.
- [ ] Locally green: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `CCWM_REQUIRE_LANDLOCK=1 CCWM_REQUIRE_INOTIFY=1 cargo test`, `cargo deny check`.
- [ ] CI green on the commit to be tagged: fmt, clippy, test, deny, gitleaks. 👤 Read the test job's
  summary: which of Landlock / inotify / strace the runner had, and every `NOTICE:`
  (skipped coverage). Do not claim coverage that did not run.
- [ ] Release build on the build host:
  ```bash
  cargo build --locked --release --target x86_64-unknown-linux-musl --bin ccwm
  strip -o /tmp/ccwm target/x86_64-unknown-linux-musl/release/ccwm && file /tmp/ccwm   # static-pie linked
  target/tools/bin/cargo-about generate --frozen --fail about.hbs > /tmp/THIRD_PARTY_LICENSES
  scripts/package-release.sh /tmp/ccwm "$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')" /tmp/THIRD_PARTY_LICENSES /tmp/dist
  (cd /tmp/dist && sha256sum -c SHA256SUMS)
  ```
  Smoke test the archive's binary in a synthetic environment (`ccwm-synth`): `serve`, `status`, `open
  --print`, `scan`, `doctor`.
- [ ] 👤 **Fresh account install** (M4 acceptance): on a test account, from the archive: `sha256sum -c`,
  `scripts/install.sh`, `ccwm status` shows `active (enabled)` and `fully_enforced`, `ccwm open` shows the
  projects. Log out and in: the service starts at login. With `loginctl enable-linger <user>` (may need
  an administrator), reboot: it starts at boot, before login. `scripts/uninstall.sh --purge` removes
  everything but the user's files.
- [ ] 👤 **Two-user check**: [two-user-verification.md](two-user-verification.md). Record the results.
- [ ] Benchmarks re-run if performance-relevant code changed ([benchmarks.md](benchmarks.md)).

## 3. Tag and release (owner)

- [ ] 👤 `git tag -s v<version> -m "ccwm <version>"` on the verified commit, then `git push origin v<version>`
  (the workflow refuses a tag that does not match the version in `Cargo.toml`).
- [ ] The **Release** workflow builds the musl binary and `THIRD_PARTY_LICENSES`, packages
  `ccwm-<version>-x86_64-unknown-linux-musl.tar.gz` + `SHA256SUMS`, and creates a **draft** release
  (`environment: release`; add a required reviewer in the repository settings for a further gate).
- [ ] 👤 Download the draft's assets, run `sha256sum -c SHA256SUMS`, and compare with the local build (the
  archive is reproducible for the same commit, toolchain and `SOURCE_DATE_EPOCH`).
- [ ] 👤 Write the release notes: the CHANGELOG section, the tested environments (only those actually
  tested), the history audit, known limitations. Then publish the draft.
- [ ] 👤 Publish the security contact in `SECURITY.md` (or enable private vulnerability reporting).
