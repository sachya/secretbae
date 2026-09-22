# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project intends to follow
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [0.2.0] — 2026-09-22

First public release.

### Added

- A built-in `unrestricted` policy, seeded automatically in every store alongside `root`. Grants
  read, write, delete and list on every path, but never `admin` — attach it with
  `secretbae token create --unrestricted` to get a working token without writing a policy
  document first. Seeding is insert-only, so an existing store gains it on its next restart
  without ever overwriting an operator's own customisation of the name.
- Verified support for Fedora and Arch Linux via `packaging/install.sh`, in addition to Debian
  and Ubuntu via the `.deb`. Same daemon binary, real `useradd`/`groupadd`, the exact shipped
  systemd capability set, confirmed with a full init/start/read/write/audit-verify cycle on
  each.
- `LICENSE-MIT` and `LICENSE-APACHE`, matching the dual license already declared in `Cargo.toml`
  and the README.
- `CONTRIBUTING.md` and `SECURITY.md`.
- A documentation site, published from `docs/` via GitHub Pages.
- `.gitattributes` forcing LF line endings for text files regardless of a contributor's
  platform or local `core.autocrlf` setting.

### Fixed

- `packaging/install.sh` told operators to run `secretbae init-keyfile` to generate the
  keyfile — that command has never existed. It now says `secretbaed init`, the real one.
- `packaging/install.sh` had picked up CRLF line endings, which breaks `set -eu` and every
  other line on a real POSIX shell. Would have failed for any Linux user running the script as
  shipped.
- `packaging/install.sh` now checks for `useradd`/`groupadd`/`getent`/`systemctl` up front and
  fails with a clear message naming what's missing, instead of failing confusingly partway
  through on a distribution that doesn't have them (Alpine's busybox equivalents, for
  instance).

### Changed

- README rewritten for readers who have never used a secret manager before: a plain-language
  explanation of the problem this solves, an "is this for me" checklist, a 5-minute quickstart
  using the new `unrestricted` policy, and a short glossary — ahead of the existing technical
  reference material, which is unchanged in substance.
- `docs/THREAT_MODEL.md` and `docs/OPERATIONS.md` updated for the `unrestricted` policy, with a
  new threat-model row (`T-BUILTIN-UNRESTRICTED`) and two new verification-table entries.

## [0.1.2] — 2026-09-11

### Fixed

- `rekey` was loading every version's ciphertext into memory in order to rewrite the 32-byte
  wrapped key beside it — the opposite of what envelope encryption is for. A rotation over
  1000 secrets aborted the daemon under its memlock limit. Rotation now reads no payloads at
  all; its cost scales with the number of versions, not their size.
- `LimitMEMLOCK=infinity` in the shipped systemd unit replaced with a measured `128M`, five
  times the daemon's own 64 MiB refuse-to-start floor. Measured at ~25 MiB locked at rest and
  ~27 MiB through a full write/read/rekey/audit-verify cycle over 1000 secrets — the stored
  data barely registers against the runtime baseline.

## [0.1.1] — 2026-09-11

First real-host deployment turned up three packaging defects, none of them in the daemon's own
logic, none visible from reading the source — all three surfaced only by running
`systemctl start` against a freshly installed package.

### Fixed

- `secretbaed.service`'s `ExecStart` pointed at `/usr/local/bin/secretbaed`; `cargo-deb`
  installs the binary to `/usr/sbin/secretbaed`. Standardised the `.deb`, the unit, and
  `install.sh` on the same paths (`/usr/sbin` for the daemon, `/usr/bin` for the CLI).
- `CapabilityBoundingSet` was missing `CAP_DAC_OVERRIDE` and `CAP_FOWNER`. Root's usual
  permission-check bypass is itself a capability, and opening the owner-only store directory
  as root without it is refused by the kernel regardless of uid 0 — symptom was a silent
  `exit(1)` with nothing on stdout, stderr, or the journal.
- `LimitMEMLOCK` was never set, leaving systemd's 8 MiB default (masked by the capability gap
  above until that was fixed).
- `secretbae top --once` required a controlling terminal, failing with an unhelpful
  `os error 11` over a plain non-interactive SSH command — despite being documented as the
  form to use in scripts.
- `secretbae tag rm <path> <key>` rejected a bare key, demanding `key=value` — the *current*
  value — to remove something by key.
- `ls` kept listing a path after every version had been `--destroy`ed.
- `secretbae rekey` run non-interactively without `--yes` silently consumed the next line of
  piped input as its confirmation, rather than refusing outright.

Added `packaging/tests/capability-matrix.sh`, which fails the build if the daemon can start
with any capability in the shipped set removed, or if it starts under a memlock limit below
its own floor — turning this class of defect into something CI catches before a release.

## [0.1.0] — 2026-09-10

Initial implementation.

### Added

- Seven-crate workspace: `sbae-core` (key hierarchy, envelope encryption, no I/O),
  `sbae-proto` (validated domain types and the wire contract), `sbae-store` (SQLite schema,
  versioning, retention, tags, tokens, policies), `sbae-policy` (token authentication and
  policy evaluation), `sbae-audit` (tamper-evident hash chain), `sbae-daemon` (`secretbaed`),
  `sbae-cli` (`secretbae`).
- Envelope encryption: XChaCha20-Poly1305, a fresh data key per secret version wrapped by a
  single master key, associated data binding each ciphertext to its secret and version so a
  row moved between them fails to decrypt.
- Three-gate authorization: Unix socket file permissions, a hashed bearer token, and
  `SO_PEERCRED` uid binding — a leaked token bound to one account is inert for every other
  account, including root.
- Tamper-evident audit log: a keyed BLAKE3 hash chain with an authenticated anchor recording
  chain length and tail hash, so truncating the log's tail is detectable, not just modifying an
  entry in its middle.
- `secretbae exec`: fetches a profile's secrets in one batched request and `execve`s directly
  into the target process, so a running application makes no further calls to the daemon.
- `secretbae top`: a live `top`-style metadata browser that cannot reach a value-bearing route,
  enforced by a source-level test rather than by convention.
- `secretbae rekey`: rotates the master key, rewrapping data keys without re-encrypting
  payloads, and re-keys the audit chain — refusing to run if the chain does not already verify,
  so rotation cannot be used to launder a tampered log.
- `secretbae backup` / `restore`: bundles sealed under an operator-supplied passphrase via
  Argon2id, independent of the server's own keyfile.
- Debian packaging (`cargo-deb`), a hardened systemd unit, and a generic `install.sh` for other
  systemd distributions.

[0.2.0]: https://github.com/sachya/secretbae/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sachya/secretbae/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sachya/secretbae/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sachya/secretbae/releases/tag/v0.1.0
