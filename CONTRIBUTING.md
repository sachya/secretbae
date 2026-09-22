# Contributing

## Development setup

The daemon (`sbae-daemon`) and the exec/top parts of the CLI are Linux-only — they depend on
Unix domain sockets, `SO_PEERCRED`, `mlock`, and `setresuid`. The pure-logic crates
(`sbae-core`, `sbae-proto`, `sbae-store`, `sbae-policy`, `sbae-audit`) build and test on any
platform.

On Linux:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

On macOS or Windows, build and test in a container instead of trying to make the Linux-only
crates compile natively:

```bash
docker run --rm -v "$PWD:/src" -w /src --ulimit memlock=-1 rust:1-bookworm \
  cargo test --workspace
```

`--ulimit memlock=-1` matters: the daemon calls `mlockall`, and Docker's default memlock limit
is too low for it to start.

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must be clean. CI runs the same three, plus `packaging/tests/capability-matrix.sh`
(proves the shipped systemd capability set is both sufficient and minimal) and `cargo-deny` /
`cargo-audit` for dependency hygiene.

## Code style

This codebase follows a few rules deliberately, not by convention:

- **Comments explain *why*, not *what*.** Code that needs a comment to explain what it does
  should be renamed or restructured instead. The exceptions are `unsafe` blocks (every
  invariant that makes them sound must be written down) and non-obvious cryptographic
  decisions, whose rationale isn't recoverable by reading the code alone.
- **Domain newtypes over primitives.** `SecretPath`, `Version`, `TokenId` — not `String` and
  `u32` — so a mismatched argument is a compile error, not a runtime bug.
- **A bug fix changes the design that allowed the bug**, rather than adding a special case
  beside it. If a fix wants an `if` branch for "the weird case," that's usually a sign the
  abstraction underneath is wrong.
- **Test names are full sentences** describing the property being proven
  (`a_token_bound_to_another_uid_is_refused_over_a_real_socket`, not `test_uid_binding`), so a
  failing test tells you what broke without opening the file.
- **`#![forbid(unsafe_code)]`** in every crate except `sbae-daemon::privdrop`, which is the one
  place `unsafe` is unavoidable (raw `libc` calls for privilege dropping and memory locking).
  A change that needs `unsafe` anywhere else should be reconsidered.

## Making a security-relevant change

If your change touches authentication, the crypto in `sbae-core`, the audit chain, or the
daemon's privilege model, please read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) first — it
documents which test proves which security property, and a change that weakens one of those
properties should either update the model explicitly or come with a good reason why the
property no longer needs to hold.

Found an actual vulnerability rather than a design question? See
[SECURITY.md](SECURITY.md) — please don't open a public issue for that.

## Commit messages

Describe what changed and why, in prose, the way the existing log does. A one-line "fix bug"
message with no explanation is not enough context for anyone reading the history later,
including you in six months.
