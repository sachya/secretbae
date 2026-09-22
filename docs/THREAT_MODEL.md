# Threat Model

What secretbae defends, against whom, and what it does not defend at all.

Every mitigation below names the code that implements it and the test that proves it. Claims
without both are marked as unverified.

## 1. System and key hierarchy

`secretbaed` starts as root, reads a root-owned keyfile, unseals the master key into `mlock`ed
memory, binds a Unix socket, then permanently drops to the unprivileged `secretbae` account.
`secretbae` is a client of that socket. State is one encrypted SQLite file.

```text
/etc/secretbae/master.key (0400 root:root)
       │
      HKDF-SHA256 (info: "secretbae/kek/v1")
       ▼
  WrapKey (KEK, 32 bytes)
       │ wraps (XChaCha20-Poly1305, AAD: [kind: u8, generation: u32])
       ▼
  MasterKey (32 bytes, mlock'ed, memory only)
       ├── wraps (XChaCha20-Poly1305, AAD: [secret_id: 16B, version: 4B, generation: 4B])
       │    ▼
       │   DataKey (32 bytes, one per secret version)
       │        │ encrypts (XChaCha20-Poly1305, AAD: [secret_id: 16B, version: 4B])
       │        ▼
       │     Payload ciphertext
       │
       └── HKDF-SHA256 (info: "secretbae/audit/v1")
            ▼
          Audit chain MAC key (keyed BLAKE3)
```

Two properties of this shape matter downstream:

- **The payload AAD omits the generation.** That is what lets `rekey` rewrap data keys without
  re-encrypting payloads. The wrap AAD includes it, so a wrapped key from before a rotation
  cannot be replayed after one.
- **The AAD binds the secret's immutable UUID, not its path.** A rename can never orphan its
  own ciphertext, and a row copied between secrets in the database will not decrypt.

## 2. Assets

| Asset | Location | Protection |
| :--- | :--- | :--- |
| Keyfile material | `/etc/secretbae/master.key`, 64 hex chars | `0400 root:root`. Read once at startup, before the privilege drop. |
| `MasterKey` | Daemon memory only | `mlock`ed, zeroized on drop, never written unsealed. |
| `WrapKey` | Transient daemon memory | Derived per unseal, zeroized on drop. |
| `DataKey` | `secret_versions.wrapped_dek` | One per version, wrapped under `MasterKey`. |
| Secret plaintext | Transient memory; child process environment | Encrypted at rest; never logged, never in argv. |
| Tokens | `tokens.hash` (SHA-256) | Only the digest is stored; compared in constant time. |
| Audit integrity | `audit` table plus `meta.audit_anchor` | Keyed BLAKE3 chain with an authenticated length-and-tail anchor. |
| Store metadata | `secrets`, `secret_versions`, `tags` | Directory `0700 secretbae:secretbae`; AEAD tags authenticate contents. |

Paths, tags and version numbers are **not** confidential to anyone who can read the database
file. Only values are encrypted.

## 3. Trust boundaries

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ Host kernel and systemd                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ Root filesystem                                                          │
│   ├── [B5] /etc/secretbae/master.key        0400 root:root               │
│   ├── [B1] /run/secretbae/sock              0660 secretbae:secretbae     │
│   ├── [B4] /var/lib/secretbae/store.db      0700 secretbae:secretbae     │
│   └── Client processes                                                   │
│        ├── Service A (uid 33 www-data, group secretbae)                  │
│        └── Service B (uid 1001 app-user,  group secretbae)               │
├──────────────────────────────────────────────────────────────────────────┤
│ [B2] secretbaed                                                          │
│   ├── [B6] privileged startup window — root, then dropped irreversibly   │
│   ├── mlock'ed: MasterKey, WrapKey, audit MAC key                        │
│   └── [B3] per-request: SO_PEERCRED → token → policy                     │
└──────────────────────────────────────────────────────────────────────────┘
```

| | Boundary | Enforced by |
| :--- | :--- | :--- |
| B1 | Socket reachability | Mode `0660`; the caller's user must be in the `secretbae` group. |
| B2 | Daemon process | Runs as `secretbae` with no capabilities after startup. `RestrictAddressFamilies=AF_UNIX` makes the absence of a network listener kernel-enforced, not a code promise. |
| B3 | Authentication and authorization | `SO_PEERCRED` uid binding, constant-time token hash comparison, policy evaluation. |
| B4 | Persistent store | Owner-only directory. Group membership reaches the socket, never the database file. |
| B5 | Keyfile | `0400 root:root`. Unreadable by the daemon itself once it has dropped. |
| B6 | Privileged startup window | See §7. This is the only window in which the process can read the keyfile. |

## 4. Adversaries

| | Adversary | Starting position |
| :--- | :--- | :--- |
| A1 | Unprivileged local user | Shell or code execution; not in the `secretbae` group. |
| A2 | Group member without a token | Can connect to the socket; holds no valid token. |
| A3 | Compromised application | Holds a legitimate scoped token; the process is compromised. |
| A4 | Cross-service impersonator | A compromised service that has obtained another service's token file. |
| A5 | Database tamperer | Read and/or write access to `store.db`, typically with the daemon stopped. |
| A6 | Offline image thief | Holds a disk image, VM snapshot or filesystem backup. |
| A7 | Token replayer | Holds an expired or revoked token. |

## 5. Threats, mitigations, residual risk

| ID | Threat | Adversary | Mitigation | Residual risk |
| :--- | :--- | :--- | :--- | :--- |
| **T-LOC-UNPRIV** | Read secrets or reach the socket without authorization | A1 | Socket `0660`, store directory `0700`. | Misconfigured group membership grants socket reachability — still gated by token and uid binding. |
| **T-BLAST-APP** | Compromised application reads beyond its scope | A3 | Segment-aware path globs and coarse capabilities (`sbae-policy`). Deny rules override grants across every attached policy. | Everything inside the token's own grant stays readable until revocation. Scope tokens narrowly. |
| **T-CROSS-TOKEN** | One service uses another service's token | A4 | `SO_PEERCRED`: the kernel supplies the caller's real uid; a token with `bound_uid` is refused for any other uid, **including root**. | Two services sharing one uid are indistinguishable. Give each service its own account. |
| **T-DB-TAMPER** | Swap or relocate ciphertext between rows | A5 | AEAD associated data binds `(secret_id, version)`; the wrap additionally binds the generation. | Corruption and deletion remain possible: this protects confidentiality and integrity, not availability. |
| **T-AUDIT-FORGE** | Forge or prune audit records | A5 | Keyed BLAKE3 chain; the MAC key is derived from the master key and exists only in daemon memory. | Cannot forge entries. Cannot hide a deletion — see T-AUDIT-TRUNC. |
| **T-AUDIT-TRUNC** | Delete recent audit entries to hide activity | A5 | A hash chain alone does not detect tail removal: a shortened chain still verifies. An authenticated anchor records chain length and tail hash, MAC'd with the same key, rewritten in the append transaction. | An attacker who reaches the master key can rewrite both. That is root-equivalent and out of scope. |
| **T-AUDIT-LAUNDER** | Tamper, then rotate the key so the chain is re-MAC'd over the forgery | A5 | `rekey` verifies the chain under the old key **first** and refuses to proceed if it does not hold. | None known within the model. |
| **T-TOK-REPLAY** | Replay an expired or revoked token | A7 | `expires_at` and `revoked_at` checked on every request; digest compared in constant time. | A live, unrevoked token is valid until revoked. Use `--ttl`. |
| **T-MEM-EXPOSURE** | Recover keys from core dumps or process inspection | A1, A2 | `LimitCORE=0`; `mlockall(MCL_CURRENT\|MCL_FUTURE)`; `prctl(PR_SET_DUMPABLE, 0)`; `zeroize` on drop. | Root can `ptrace` the daemon or read `/proc/<pid>/mem`. Out of scope. |
| **T-ENV-EXPOSURE** | Read injected secrets from another process | A1, A3 | Secrets pass in the environment, never argv, and are stripped of the caller's own token before `execve`. | `/proc/<pid>/environ` is readable by root and by the same uid. See §8. |
| **T-BACKUP-THEFT** | Open a stolen backup bundle | A6 | Bundles are sealed under an operator passphrase via Argon2id (64 MiB, 3 iterations, 4 lanes), **not** under the keyfile. | A weak passphrase is grindable offline. The bundle is an offline target with unlimited attempts. |
| **T-ERR-ORACLE** | Map the store by probing error responses | A2, A3 | Missing path, deleted version and denied request all answer `not found or not permitted`. | Timing differences are not equalised; treated as negligible for a local socket. |

## 6. Out of scope

No cryptographic or architectural defence is offered against these. They are stated plainly so
nobody deploys secretbae believing otherwise.

1. **Root compromise.** Root can `ptrace` the daemon, read `/proc/<pid>/mem`, read the keyfile,
   and rewrite the audit chain and its anchor together. Root is game over.
2. **Kernel compromise.** Ring 0 sees `mlock`ed memory, forges `SO_PEERCRED`, and intercepts
   every cryptographic operation.
3. **Physical and hardware attacks.** Cold boot, DMA over PCIe or Thunderbolt, bus snooping.
   `mlock` keeps keys out of swap; it does not protect the RAM itself.
4. **A malicious operator.** Anyone with root, an admin token or authorized SSH can destroy,
   rekey or exfiltrate the store. The design assumes operator integrity.

## 7. The privileged startup window

The daemon needs root exactly long enough to read a file the unprivileged account must never
be able to read. Everything else runs unprivileged. The ordering is the security design:

1. `prctl(PR_SET_DUMPABLE, 0)` and `mlockall` — **before** any key material exists, so no crash
   between here and the drop can write a key to disk.
2. Read and validate the keyfile: refuse it unless `0400`/`0600` and owned by root.
3. Open the store, unseal the master key, bind and hand over the socket.
4. `setresuid`/`setresgid` — real, effective **and saved** ids together, so the saved id cannot
   restore root. `setgroups` first, because after the uid drops the process can no longer change
   its groups.
5. Re-read the result from the kernel and require `setuid(0)` to fail. Historically this is the
   step whose omission turns a privilege drop into a no-op.

### Capability set

Steps 2 and 3 need more than uid 0. Under systemd's `CapabilityBoundingSet`, root's usual
permission-check bypass is itself a capability:

| Capability | Needed for |
| :--- | :--- |
| `CAP_DAC_OVERRIDE` | Opening the `0700 secretbae` store while still root. Without it the kernel refuses uid 0. |
| `CAP_FOWNER` | `chmod` on the store and socket, which after the first run are owned by `secretbae`. |
| `CAP_CHOWN` | Handing the socket and store to `secretbae` before dropping. |
| `CAP_SETUID`, `CAP_SETGID` | The drop itself. |

`CAP_IPC_LOCK` is **not** granted. `mlockall` needs it only to exceed `RLIMIT_MEMLOCK`, and that
limit must be lifted regardless: `MCL_FUTURE` keeps locking pages for the life of the process
while the capability is surrendered at the drop, so a bounded limit becomes allocation failures
during normal request handling. `LimitMEMLOCK=128M` covers both, and the daemon refuses to start
under a limit too low to serve — because the failure it prevents otherwise surfaces as a panic
inside the async runtime that never mentions memory locking. The bound is measured rather than
open-ended: ~25 MiB locked at rest and ~27 MiB through a full cycle over 1000 secrets, since
what is locked is the runtime, not the store.

`packaging/tests/capability-matrix.sh` asserts the set is both **sufficient and minimal**: the
daemon must start with it, and must fail with any single entry removed. An over-broad bounding
set is a defect, not a safety margin.

### Failure visibility

A daemon that cannot explain why it refused to start is a security problem, not just an
operability one: it pushes operators toward weakening the sandbox until something works. Fatal
startup errors are written to stderr unconditionally — not through the log subsystem, which
once filtered them out entirely and produced a silent `exit(1)` — and name the unit directive
that fixes them. These messages carry configuration and permission failures only; no secret
material reaches them.

## 8. Two accepted tradeoffs

### 8.1 The keyfile sits beside the store

The sealed database and the key that opens it live on the same filesystem. **Disk-image or
snapshot theft is therefore full compromise.** This is a deliberate choice, made for unattended
reboots, and it is the single largest residual risk in the design.

Three things limit the blast radius, none of which change it:

1. **The privilege drop.** After roughly 50 ms of uptime nothing short of root can re-read the
   keyfile — not the daemon's own account, not a compromised application.
2. **Backups are sealed separately.** A stolen bundle is not openable by the on-disk keyfile.
   This matters because backups travel and disk images usually do not.
3. **The `Seal` trait.** A TPM2 or `systemd-creds` backend is a new implementation plus a
   `rekey`, not a data migration. *(Not implemented.)*

If the threat you actually care about is disk theft, use a TPM-backed seal or full-disk
encryption with a boot-time passphrase. secretbae as shipped does not solve it.

### 8.2 Secrets reach applications through the environment

`secretbae exec` fetches a profile in one batched request, builds the child environment and
`execve`s into the target. The wrapper is then gone; serving traffic causes no further daemon
calls.

The cost: `/proc/<pid>/environ` is readable by root and by processes under the same uid. Against
the adversaries in §4 this is acceptable — A1 cannot read another uid's `environ`, A3 already
holds the secrets, and root is out of scope. It also avoids the worse alternative: a `.env` file
that persists on disk, lands in backups and eventually reaches version control.

Two mechanisms would close the gap and are **not implemented**: rendering to a tmpfs file, and
systemd `LoadCredential`, which delivers into a per-service namespace invisible in `/proc`.

## 9. How these claims are verified

A threat model is only worth the tests behind it.

| Claim | Verified by |
| :--- | :--- |
| Ciphertext cannot be relocated between secrets or versions | `sbae-core` envelope tests; `ciphertext_relocated_between_secrets_fails_to_open` in `sbae-store`. |
| A retired master key stops working after rotation | `rewrap_preserves_payload_and_invalidates_the_old_master`. |
| A uid-bound token is inert for every other uid | `a_token_bound_to_another_uid_is_refused_over_a_real_socket` — drives the real router over a real Unix socket, so peer credentials come from the kernel, not a mock. |
| Missing and forbidden are indistinguishable | `a_missing_path_answers_exactly_like_a_forbidden_one`. |
| Audit detects modification, deletion and truncation | `sbae-audit` chain and anchor tests; end-to-end tamper runs against a live daemon. |
| Rotation cannot launder a tampered chain | `a_tampered_chain_is_refused_rather_than_relaundered`. |
| Backups are not openable by the keyfile | `sbae-core::backup` tests; a full restore onto a host with a different keyfile. |
| The capability set is minimal and sufficient | `packaging/tests/capability-matrix.sh`, run in CI. |
| No value reaches the metadata browser | `the_metadata_browser_cannot_reach_a_route_that_returns_a_value` asserts against the module's own source that it references no value-bearing route or type. |
| No value reaches a response or the audit log | `a_secret_value_reaches_no_response_or_record_except_its_own_read` stores a sentinel, drives list, versions, status, tag, token, policy and audit routes, and searches every response and every audit column for it in both raw and base64 form — with an explicit read as the control, so the assertions cannot pass vacuously. |

Not verified, and worth knowing: the daemon has not been fuzzed, has had no external review,
and its timing characteristics have not been measured.
