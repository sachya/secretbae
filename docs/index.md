---
title: Home
nav_order: 1
description: "secretbae — a lightweight secret manager for a single Linux host."
permalink: /
---

# secretbae

A lightweight secret manager for a single Linux host. Encrypted storage with versioning and
tags, token-authenticated access over a Unix socket, and a tamper-evident audit log.

No network listener, no cluster, no external dependencies beyond a keyfile and a SQLite file.
Debian and Ubuntu get a `.deb`; Fedora, RHEL, Arch, openSUSE and other systemd distributions
install from a plain shell script — both are tested, not just assumed to work.

```
secretbae put prod/billing/db_url --value 'postgres://…' --tag env=prod
secretbae exec --profile billing -- /usr/bin/billing-server
```

## Where to start

- **New to secret managers, or to secretbae specifically?** The
  [README](https://github.com/sachya/secretbae#readme) has a plain-language explanation of the
  problem this solves, a checklist for whether it fits your setup, and a 5-minute quickstart
  that needs no policy authoring.
- **Running it on a host?** [Operations](OPERATIONS.html) covers install, tokens, giving
  secrets to an application, rotation, backup and restore, and troubleshooting.
- **Evaluating whether to trust it with something real?** [Threat Model](THREAT_MODEL.html)
  states exactly what is defended against, what mitigates each threat, what the residual risk
  is, and which test proves each claim — including what is explicitly *not* defended against.
- **Want the exact CLI surface?** `secretbae --help`, or any subcommand's `--help`, is the
  source of truth; the README's command table is a summary of it.

## The shape of it

```
  secretbae (CLI)  ─┐
                    ├─► /run/secretbae/sock ──► secretbaed ──► store.db (encrypted)
  your app ─────────┘    0660 secretbae:secretbae   │
  (via secretbae exec)                              └── master key: mlock'd, memory only
```

`secretbaed` starts as root only long enough to read a root-owned keyfile and unseal the
master key into locked memory, then drops privileges permanently. It listens on a Unix socket
only — never a network port. Applications receive their secrets once, at process start, via
`secretbae exec`, and the daemon is not involved again while they serve traffic.

Three independent gates protect every request: filesystem permissions on the socket, a hashed
bearer token, and the kernel-supplied uid of the connecting process — a token bound to one
account is inert for every other account, including root.

## Source and licence

[github.com/sachya/secretbae](https://github.com/sachya/secretbae) — dual-licensed under MIT
or Apache-2.0, at your option. See [CHANGELOG](https://github.com/sachya/secretbae/blob/master/CHANGELOG.md)
for what changed in each release.
