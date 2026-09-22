# Operations

Running secretbae on a host: install, initialise, grant access, rotate, back up, recover.

Every command here has been run against a live daemon. If something below does not work as
written, that is a bug — please report it rather than working around it.

## Layout

| Path | Mode | Owner | Purpose |
| :--- | :--- | :--- | :--- |
| `/usr/sbin/secretbaed` | `0750` | `root:root` | Daemon. Not on an unprivileged user's `PATH`. |
| `/usr/bin/secretbae` | `0755` | `root:root` | CLI. How everyone else talks to it. |
| `/etc/secretbae/master.key` | `0400` | `root:root` | The key that opens the store. 64 hex characters. |
| `/etc/secretbae/` | `0755` | `root:root` | Traversable: `secretbae exec` runs as the *application's* uid and must reach its own token. Confidentiality comes from the keyfile's own mode, not from hiding the directory. |
| `/etc/secretbae/tokens/` | `0755` | `root:root` | Service tokens, each `0440 root:<app group>`. |
| `/etc/secretbae/profiles/` | `0755` | `root:root` | `exec` profiles. |
| `/var/lib/secretbae/` | `0700` | `secretbae:secretbae` | Encrypted store. Group membership reaches the socket, never this. |
| `/run/secretbae/sock` | `0660` | `secretbae:secretbae` | The only endpoint. No TCP exists. |

## Install

```bash
sudo dpkg -i secretbae_0.1.2-1_amd64.deb
sudo secretbaed init
sudo systemctl enable --now secretbaed
```

`init` creates the keyfile, the store, the master key and a root token in one step, and prints
the token on stdout **once** — only its hash is stored. It is bound to uid 0, so it works only
from root. `init` refuses to run if a keyfile already exists: generating a second one would make
every secret in the existing store permanently unreadable.

The package deliberately does not start the daemon on install, because `secretbaed` exits until
a keyfile exists and an auto-start would only produce a failed unit.

On non-Debian systemd distributions use `packaging/install.sh`. Rebuild the package with
`packaging/build-deb.sh`, on the target architecture or in a container of it — it carries
compiled binaries.

### Verifying the install

```bash
systemctl show secretbaed -p MainPID --value | xargs -I{} grep -E '^(Uid|CapEff)' /proc/{}/status
ss -lntp | grep secretbaed          # must print nothing: there is no TCP listener
```

Expect the daemon's uid to be the `secretbae` account and `CapEff` to be all zeroes. The
privilege drop is real, not aspirational — if `CapEff` is non-zero, something is wrong.

## Tokens and policies

### The fast path: no policy document at all

Two policies exist in every store from the moment `secretbaed init` runs, before you write
anything: `root` (bound to uid 0, created for the daemon's own bootstrap token) and
`unrestricted` — read, write, delete and list on every path, attachable to any token you mint:

```bash
secretbae token create --name first-try --unrestricted --bind-uid myuser
```

No JSON, no path globs, nothing to get wrong on day one. It still goes through the same
issuance, hashing and revocation as any other token — there is no way to reach a secret
without one. What it deliberately cannot do is create or revoke other tokens or change policy
(`admin` is never included), so a leaked `unrestricted` token cannot mint itself a replacement
or escalate further than the data it already reached.

Treat it as a starting point, not a production shape: it grants everything to the one token
you handed it, so a compromise of that token is a compromise of the whole store's data plane.
Move to a scoped policy — below — once you know what a service actually needs.

### Scoped policies

A policy is a JSON document. Deny always wins, across every policy attached to a token, and
`require_tags` only ever narrows a grant the path already made — it never creates one.

```json
{
  "name": "billing",
  "rules": [
    { "path": "prod/billing/**", "capabilities": ["read", "list"], "require_tags": ["env=prod"] }
  ],
  "deny": [ { "path": "prod/**/admin/**" } ]
}
```

Path globs are segment-aware: `*` matches one segment, `**` matches zero or more, and neither
crosses a segment boundary — `prod/billing/**` does not match `prod/billing-admin/db`.

```bash
secretbae policy put --file billing-policy.json
secretbae token create --name billing --policy billing --bind-uid www-data --ttl 90d
```

**Always set `--bind-uid`.** It binds the token to a local account via `SO_PEERCRED`, which the
kernel supplies and the caller cannot choose. A token bound to `www-data` is inert for every
other uid, including root. This is the single most effective control available here, and it
costs one flag.

Install the token where only that service can read it:

```bash
install -o root -g billing -m 0440 /dev/stdin /etc/secretbae/tokens/billing.token <<< "$TOKEN"
```

`0440 root:<app group>` is the intended shape: root owns it, the service reads it, nobody else
can. The CLI refuses a token file readable by *other*, or writable by its group.

Revoke immediately on suspicion — it is instant and cheap:

```bash
secretbae token revoke <prefix>
```

## Giving secrets to an application

`/etc/secretbae/profiles/billing.toml`:

```toml
token_file = "/etc/secretbae/tokens/billing.token"

[[env]]
name = "DATABASE_URL"
path = "prod/billing/db_url"

[[env]]
name = "STRIPE_KEY"
path = "prod/billing/stripe"
version = 3                        # pin, instead of tracking current

[[env_from]]                       # map a whole prefix
prefix = "prod/billing/runtime/"
transform = "screaming_snake"      # …/api_key -> API_KEY
```

Then one line in the unit:

```ini
ExecStart=/usr/bin/secretbae exec --profile billing -- /usr/bin/billing-server
```

`exec` fetches the whole profile in a single batched request, builds the child environment and
`execve`s into your program. The wrapper is then gone — the application makes no further calls
to the daemon, so serving traffic costs nothing. It refuses to start if two entries map to the
same variable name, and strips any inherited `SECRETBAE_TOKEN` from the child.

The cost of this model: **secrets are read once, at start.** See rotation below.

## Rotating a secret

```bash
secretbae put prod/billing/db_url --stdin < newpassword
systemctl restart billing-app.service
```

The restart is not optional and not a limitation that can be configured away. `exec` copies
values into the process image at startup; nothing can rewrite another process's environment
afterwards. If you need rotation without a restart, the application must call the socket itself
at runtime rather than using `exec`.

Rolling forward and back does not destroy anything:

```bash
secretbae versions prod/billing/db_url
secretbae rollback prod/billing/db_url --to 4   # re-points current; keeps every version
```

Deletion is two-stage on purpose. `secretbae rm <path> --version N` hides a version but keeps
its ciphertext; `--destroy` discards the ciphertext irreversibly. Once nothing readable remains,
the path stops appearing in `ls`.

## Rotating the master key

```bash
secretbae rekey
```

Generates a new master key, rewraps every stored data key under it, re-seals the master key
under the same keyfile, and re-keys the audit chain. Payloads are never re-encrypted, so cost
scales with the number of versions, not their size.

Three things worth knowing:

- **It runs against a live daemon.** The store commits the rewrapped keys and the new sealed
  master key in one transaction; the daemon adopts the new key only after that commit. A failure
  anywhere leaves store and daemon agreeing on the old key.
- **It refuses to run if the audit chain does not verify.** Re-keying recomputes every entry
  hash, so rotating a tampered chain would re-authenticate the tampering into a chain that then
  verifies perfectly. Run `secretbae audit verify` and resolve the discrepancy first.
- **It does not change `/etc/secretbae/master.key`.** To replace the keyfile itself: back up,
  re-run `secretbaed init` against an empty store with the new keyfile, restore.

Use `--yes` in scripts. Without a terminal the confirmation prompt refuses to run rather than
consuming the next line of whatever is piped in.

## Backup and restore

```bash
secretbae backup /var/backups/secretbae-$(date +%F).sbk
secretbae restore /var/backups/secretbae-2026-09-11.sbk
```

The bundle is encrypted under a passphrase you supply, **not** under the server keyfile. That is
deliberate: the store and its keyfile share a filesystem, so sealing backups with the keyfile too
would mean one stolen disk image opens both. The passphrase is prompted for without echo and
asked twice; `SECRETBAE_BACKUP_PASSPHRASE` supplies it for scheduled jobs.

> Losing the passphrase means losing the backup. There is no recovery path and nobody can reissue
> it for you. Store it somewhere other than this host.

| In the bundle | Not in the bundle |
| :--- | :--- |
| Every secret, with version numbers, states, tags and provenance preserved | **Tokens.** They are bound to the uids of the machine that issued them and only their hashes are stored, so restoring them elsewhere would produce credentials nobody holds. Issue fresh ones. |
| Policy documents | **The audit log.** Its chain is keyed to the master key of the machine that wrote it. A restored store starts a new chain. |

Restore refuses a store that already holds secrets rather than merging two histories into version
numbering nobody could reason about. Restore onto a freshly initialised store.

Because the bundle carries values re-sealed under the *target's* master key, a restore works onto
a host with a completely different keyfile. **Do not copy the keyfile between hosts.**

### Disaster recovery

1. Install secretbae on the replacement host.
2. `sudo secretbaed init` — a **new** keyfile and a new root token.
3. `secretbae restore <bundle>` with the backup passphrase.
4. Re-issue service tokens: `secretbae token create --bind-uid <service user> …`.
5. Restart the consuming services so `exec` picks the secrets up.

### If the keyfile is lost and you have no backup

The secrets are gone. XChaCha20-Poly1305 has no backdoor, no escrow and no shortcut. There is
nothing to try.

Back the keyfile up to somewhere off this host, treating it as equivalent to the secrets
themselves — because it is.

## The audit log

```bash
secretbae audit verify
```

A keyed BLAKE3 chain plus an authenticated anchor recording chain length and tail hash. It
detects a modified entry, a deleted entry, and truncation of the tail — the last of which a
plain hash chain cannot catch, because a shortened chain still verifies cleanly.

| Output | Meaning |
| :--- | :--- |
| `Audit chain verified: N entries intact.` | Every entry authenticates and the anchor agrees. |
| `entry modified at seq N` | A row's contents changed after it was written. |
| `sequence gap detected: expected seq N, found M` | A row was deleted from the middle. |
| `audit chain truncated: anchor records N entries, found M` | Entries were removed from the end. |
| `audit anchor is missing or was not written by this store` | The anchor was deleted or rewritten without the audit key. |
| `corrupt entry at seq N` | A row decodes to something the schema does not allow. |

Anything other than the first means someone wrote to the database directly. Treat it as a host
compromise: the audit key lives only in daemon memory, so a valid chain cannot be forged without
already having the master key.

## Browsing the store

`secretbae top` is a live metadata table.

| Key | Action |
| :--- | :--- |
| `↑`/`↓` or `k`/`j` | Move. |
| `Enter` / `Esc` | Open the version pane for a key / go back. |
| `/` | Filter by path prefix. |
| `t` | Cycle the tags present in the current view. |
| `s` / `S` | Cycle sort column / reverse. |
| `r` / `p` | Refresh now / pause auto-refresh. |
| `q` | Quit. |

`--interval <secs>` changes the 2-second refresh; `--once` prints a single frame and exits, for
scripts and cron — it needs no terminal and honours `COLUMNS`/`LINES`.

**It never shows a value.** Use `secretbae get` when you need one.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Permission denied` connecting to the socket | Caller is not in the `secretbae` group. | `usermod -aG secretbae <user>`, then restart the service. Group membership is not retroactive for running processes. |
| `Connection refused` | Daemon not running. | `systemctl status secretbaed`, then `journalctl -u secretbaed -e`. |
| `not found or not permitted` | Deliberately ambiguous: missing path, deleted version, no grant, wrong uid. | Check `secretbae ls`, the token's policies, and whether `bind_uid` matches the calling account. The audit log records the specific reason even though the caller is not told it. |
| `unable to open database file` at startup, as root | `CapabilityBoundingSet` too narrow. Root's permission-check bypass is itself a capability. | The set needs `CAP_DAC_OVERRIDE` and `CAP_FOWNER` alongside `CAP_CHOWN CAP_SETUID CAP_SETGID`. `packaging/tests/capability-matrix.sh` proves the shipped set is sufficient and minimal. |
| `RLIMIT_MEMLOCK is N bytes, below …` | `LimitMEMLOCK` unset, so systemd's 8 MiB default applies. | The shipped unit sets `LimitMEMLOCK=128M`. If you have overridden it, see *Memory* below. |
| Keyfile rejected at startup | Wrong mode or owner. | `chmod 0400 /etc/secretbae/master.key && chown root:root` it. |
| `audit verification failed` | Direct write to the database. | See above — investigate the host. |
| `stdin is not a terminal` | A prompt with nothing to read from. | `rekey --yes`, or `SECRETBAE_BACKUP_PASSPHRASE`. The prompt refuses rather than eating the next piped line. |
| `database is locked` | Another process holds the SQLite write lock. | Normally transient; `busy_timeout` is 5 s. Check for a second daemon. |

### When the daemon will not start

Run it in the foreground as root. Startup failures print to stderr with the unit directive that
fixes them:

```bash
/usr/sbin/secretbaed /etc/secretbae/config.toml
```

## Memory

The daemon calls `mlockall(MCL_CURRENT | MCL_FUTURE)`, so no part of it — including a
decrypted secret in flight — can be written to swap. The cost is that **every allocation for
the life of the process counts against `RLIMIT_MEMLOCK`**, and `CAP_IPC_LOCK`, which would let
it exceed that limit, is surrendered at the privilege drop. A limit that is too low therefore
fails during normal request handling rather than at startup.

The requirement is bounded and measured, not open-ended:

| | Locked memory |
| :--- | :--- |
| At rest | ~25 MiB |
| 1000 secrets, ~2000 versions, through write, read, rekey and audit-verify | ~27 MiB |

The stored data barely registers next to the runtime baseline — 1000 secrets added about
1.3 MiB. Rotation does not read payloads at all; it rewrites 32-byte wrapped keys, so its cost
scales with the number of versions rather than their size.

The shipped unit grants `LimitMEMLOCK=128M` and the daemon refuses to start below 64 MiB,
naming the directive in the error. Raise it only if you store far more than a few thousand
secrets, or much larger values:

```bash
systemctl edit secretbaed     # [Service] then LimitMEMLOCK=256M
```

Check what is actually locked:

```bash
systemctl show secretbaed -p MainPID --value | xargs -I{} grep VmLck /proc/{}/status
```

## Monitoring

There is no built-in alerting. What is worth watching:

| Check | Command |
| :--- | :--- |
| Service is up | `systemctl is-active secretbaed` |
| Responds | `secretbae status` |
| Audit intact | `secretbae audit verify` — worth a scheduled run |
| Still unprivileged | `CapEff` is zero in `/proc/<pid>/status` |
| Still local-only | `ss -lntp \| grep secretbaed` prints nothing |

The daemon logs nothing during normal operation by design, so an empty journal is healthy, not
suspicious.
