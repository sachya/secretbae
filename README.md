# secretbae

A lightweight secret manager for a single Linux host. Encrypted storage with versioning and
tags, token-authenticated access over a Unix socket, and a tamper-evident audit log.

No network listener, no cluster, no external dependencies beyond a keyfile and a SQLite file.

```
secretbae put prod/billing/db_url --value 'postgres://…' --tag env=prod
secretbae exec --profile billing -- /usr/bin/billing-server
```

## How it works

`secretbaed` starts as root, reads `/etc/secretbae/master.key` (`0400 root:root`), unseals the
master key into `mlock`ed memory, binds its socket, then **permanently drops to the
unprivileged `secretbae` account** — after which nothing short of root can re-read the keyfile.
It listens only on `/run/secretbae/sock`; the shipped systemd unit sets
`RestrictAddressFamilies=AF_UNIX`, so the absence of a network listener is kernel-enforced
rather than a promise in the code.

`secretbae` is a client of that socket. Applications never talk to it directly: `secretbae exec`
fetches a profile's secrets in **one batched request**, builds the child environment, and
`execve`s into your program. After that the wrapper is gone — serving 200 HTTP requests causes
zero daemon calls.

```
  secretbae (CLI)  ─┐
                    ├─► /run/secretbae/sock ──► secretbaed ──► store.db (encrypted)
  your app ─────────┘    0660 secretbae:secretbae   │
  (via secretbae exec)                              └── master key: mlock'd, memory only
```

## Install

```bash
sudo dpkg -i secretbae_0.1.2-1_amd64.deb
sudo secretbaed init                    # creates the keyfile, prints the root token ONCE
sudo systemctl enable --now secretbaed
```

The package does not auto-start the daemon: `secretbaed` exits until a keyfile exists, so
enabling it before `init` would only produce a failed unit. The root token is displayed once
and cannot be recovered — only its hash is stored.

On non-Debian systemd distributions use `packaging/install.sh`, which performs the same steps.
Rebuild the package with `packaging/build-deb.sh` on the target architecture.

## Quickstart

```bash
export SECRETBAE_TOKEN=…                                  # the token init printed

# Write. Every put appends an immutable version.
secretbae put prod/billing/db_url --value 'postgres://u:p@/billing' --tag env=prod --tag app=billing
secretbae put prod/billing/db_url --stdin < newpassword    # value never appears in argv

# Read, list, inspect history.
secretbae get prod/billing/db_url                          # --raw for scripting, --json for tooling
secretbae ls --tag env=prod
secretbae versions prod/billing/db_url
secretbae rollback prod/billing/db_url --to 1              # re-points current; discards nothing

# Grant an application access, bound to the uid it runs as.
secretbae policy put --file billing-policy.json
secretbae token create --name billing --policy billing --bind-uid www-data --ttl 90d
```

A policy is a JSON document; deny always wins, and `require_tags` only ever narrows a grant the
path already made:

```json
{
  "name": "billing",
  "rules": [
    { "path": "prod/billing/**", "capabilities": ["read", "list"], "require_tags": ["env=prod"] }
  ],
  "deny": [ { "path": "prod/**/admin/**" } ]
}
```

## Giving secrets to an application

Write `/etc/secretbae/profiles/billing.toml`:

```toml
token_file = "/etc/secretbae/tokens/billing.token"   # 0440 root:billing

[[env]]
name = "DATABASE_URL"
path = "prod/billing/db_url"

[[env_from]]                       # map a whole prefix to environment variables
prefix = "prod/billing/runtime/"
transform = "screaming_snake"      # …/api_key -> API_KEY
```

Then change one line in the service unit:

```ini
ExecStart=/usr/bin/secretbae exec --profile billing -- /usr/bin/billing-server
```

Secrets never touch disk. The tradeoff: because values are copied into the process once,
**rotating a secret requires restarting the consuming service.**

## `secretbae top`

A live metadata browser, in the spirit of `top`:

```
 ▍SECRETBAE top · live metadata                                       ● LIVE  12:57:26 UTC
 socket /run/secretbae/sock │ keys 6/6 │ versions 11
╭─ KEYS 6 ───────────────────────────────────────────────────────────────────────────────────╮
│  KEY ▲                         VERSIONS  CURRENT  TAGS                      UPDATED        │
│▶ dev/api/token                 1 ▮       v1       app=api  env=dev          0s ago         │
│  prod/billing/db_url           5 ▮▮▮▮▮   v5       app=billing  env=prod     2m ago         │
│  prod/billing/stripe_key       1 ▮       v1       app=billing  env=prod     2m ago         │
│  staging/api/token             2 ▮▮      v2       app=api  env=staging      5m ago         │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
 ↑↓  move   ↵  versions   /  filter   t  tag   s  sort   p  pause   q  quit
```

Production tags render red, staging amber, development green. `Enter` opens the version pane
for a key; `/` filters by path; `t` cycles the tags present in the view; `s`/`S` sorts.
`--interval <secs>` changes the 2-second refresh; `--once` prints a single frame and exits, for
scripts and cron — it needs no terminal and honours `COLUMNS`/`LINES`.

**It never shows a secret's value.** The `read` and `resolve` routes are unreachable from it and
a test enforces that — a full-screen value display would leak into terminal scrollback and any
screen share. Use `secretbae get` when you actually need a value.

## Commands

| Command | Purpose |
| :--- | :--- |
| `status` | Daemon state, schema version, master-key generation, secret count. |
| `put` / `get` | Write a new version / read one. `--stdin`, `--file`, `--value`; `--raw`, `--json`. |
| `ls [prefix]` | List secrets, filtered by path prefix and `--tag`. |
| `versions` / `rollback` | Inspect history / re-point `current` without discarding anything. |
| `rm` | Soft-delete a version, or `--destroy` to discard its ciphertext irreversibly. |
| `tag add\|rm\|ls` | Manage `key=value` labels. `rm` also takes a bare key. |
| `token create\|list\|revoke` | Issue tokens, optionally `--bind-uid` and `--ttl`. |
| `policy put\|list\|rm` | Manage access-control documents. |
| `exec --profile N -- cmd` | Batched fetch, then `execve` into the application. |
| `top` | Live metadata browser. |
| `rekey` | Rotate the master key; rewraps every data key and re-keys the audit chain. |
| `backup` / `restore` | Encrypted bundle under an independent passphrase. |
| `audit verify` | Walk the hash chain and report the first break. |
| `completions <shell>` | Shell completion script. |

## Security model

Three independent gates, all of which must pass:

1. **Filesystem** — the socket is `0660 secretbae:secretbae`; the caller's user must be in the group.
2. **Token** — valid, unexpired, unrevoked, and carrying a policy granting the capability. Only
   `SHA-256(token)` is stored, compared in constant time.
3. **Peer credentials** — the daemon reads the connecting process's real uid via `SO_PEERCRED`,
   which the kernel supplies and the caller cannot choose. A token bound to `www-data` is
   **inert for any other local account, including root**.

Supporting properties:

- **Envelope encryption.** Every version gets a fresh data key wrapped by the master key, so
  `rekey` rewrites 32-byte keys instead of re-encrypting every payload.
- **Ciphertext is bound to its slot.** The AEAD's associated data binds `(secret_uuid, version)`,
  so a row moved between secrets in the database will not decrypt.
- **Runs unprivileged.** Root is held only long enough to read the keyfile; the drop uses
  `setres*id` so the saved id cannot restore it, and the result is re-read from the kernel
  rather than trusted. The shipped unit grants five capabilities, and a test fails the build if
  the daemon can start with any one of them removed.
- **Tamper-evident audit.** A keyed BLAKE3 chain plus an authenticated anchor, detecting modified
  entries, deleted entries *and* truncation of the tail. `rekey` refuses to run on a chain that
  does not verify, so rotation cannot launder away evidence.
- **Errors reveal nothing.** A missing path, a deleted version and a denied request all answer
  `not found or not permitted`.

Explicitly out of scope: host root compromise (root can `ptrace` the daemon), kernel compromise,
physical memory attacks, and a malicious operator. See
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full analysis, including the residual risk of
keeping the keyfile on the same filesystem as the store.

## What this is not

| Non-goal | Why |
| :--- | :--- |
| **Not a network service** | Local Unix socket only. No TCP or UDP is opened, and the systemd unit enforces `AF_UNIX` at the kernel level. |
| **Not multi-host** | State is one SQLite file on one machine. No replication, no consensus, no clustering. |
| **Not a managed KMS** | The store and its keyfile share a filesystem, so disk-image or backup theft compromises both. Backups are sealed under a separate passphrase to limit this; a TPM2 seal backend would close it and is the sanctioned extension point. |

## Layout

| Crate | Responsibility |
| :--- | :--- |
| `sbae-core` | Key hierarchy, envelope encryption, seal backends, backup bundles. No I/O. |
| `sbae-proto` | Validated domain types (`SecretPath`, `Tag`, `Version`) and the wire contract. |
| `sbae-store` | SQLite schema, versioning, retention, tags, tokens, policies. No cryptography. |
| `sbae-policy` | Token authentication and policy evaluation. Pure functions, no I/O. |
| `sbae-audit` | Keyed hash chain, anchor, verification and chain re-keying. |
| `sbae-daemon` | `secretbaed`: privileged startup, privilege drop, HTTP-over-UDS handlers. |
| `sbae-cli` | `secretbae`: client, `exec` wrapper, and the `top` browser. |

`#![forbid(unsafe_code)]` holds everywhere except one reviewed module in `sbae-daemon`, which
needs `mlock`, `prctl` and `setresuid`; every block there documents its invariant.

## Building and testing

The daemon is Linux-only — it depends on Unix sockets, `SO_PEERCRED`, `mlock` and `setresuid`.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

From a non-Linux machine, build and test in a container:

```bash
docker run --rm -v "$PWD:/src" -w /src --ulimit memlock=-1 rust:1-bookworm cargo test --workspace
```

## Documentation

| Document | Contents |
| :--- | :--- |
| [OPERATIONS.md](docs/OPERATIONS.md) | Install, initialise, tokens, exec profiles, systemd wiring, rotation, backup/restore, audit verification, disaster recovery, troubleshooting. |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, attacker profiles, mitigations and residual risk. |

## Specifications

| Property | Value |
| :--- | :--- |
| AEAD | XChaCha20-Poly1305, 24-byte random nonces |
| Key derivation | HKDF-SHA256 for the KEK and audit key |
| Passphrase KDF | Argon2id — 64 MiB, 3 iterations, 4 lanes (backup bundles only) |
| Key hierarchy | Envelope: a data key per version, wrapped by the master key |
| Audit chain | Keyed BLAKE3 with an authenticated length-and-tail anchor |
| Storage | SQLite, WAL, foreign keys, `STRICT` tables |
| Paths | Lowercase `[a-z0-9._-]`, max 16 segments, max 512 bytes |
| Retention | Newest 10 versions per secret by default |
| Seal backends | Keyfile (shipped); TPM2 is the sanctioned extension point |
| Capabilities held | `CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER`, all surrendered at the privilege drop |

## Licence

MIT OR Apache-2.0.
