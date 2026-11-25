# Contributing

Thank you for your interest in CC Workspace Manager. It is an independent, unofficial project, not affiliated with or endorsed by Anthropic.

## License of contributions

The project is licensed under the [MIT License](LICENSE). Contributions are accepted under the same license (**inbound = outbound**): by contributing, you license your contribution under the MIT License. There is **no CLA**.

## Developer Certificate of Origin

Every commit must be signed off, certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the project's license.

```bash
git commit -s    # adds "Signed-off-by: Your Name <you@example.com>"
```

The sign-off name and address must match the commit author.

## Before you open a pull request

- `REQUIREMENTS.md` is the specification; changes that contradict it need a discussion first.
- Run the checks (all must pass):
  ```bash
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test
  cargo deny check
  ```
- New dependencies need a justification in `ARCHITECTURE.md` §4. HTTP and DNS client crates are not accepted.
- Never commit real Claude Code sessions, real project content or credentials, not even redacted. Tests use synthetic data only (`ccwm-synth`, `tests/fixtures/`).
- Fake secrets in tests (redaction cases, log canaries) must contain the word `SYNTHETIC`, so the gitleaks scan in CI (`.gitleaks.toml`) recognises them as test data.
- CI (`.github/workflows/ci.yml`) also runs gitleaks over the full history and reports which sandbox features (Landlock, inotify, strace) the runner had; read its summary before claiming coverage.
- Security issues: please report them privately (see [SECURITY.md](SECURITY.md)), not in a public issue.
