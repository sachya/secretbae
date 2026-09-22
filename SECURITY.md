# Security Policy

## Supported versions

secretbae is pre-1.0. Only the latest released version is supported; there is no backport
policy yet. Check [CHANGELOG.md](CHANGELOG.md) for what changed between versions before
reporting an issue that might already be fixed.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately using [GitHub's private vulnerability reporting](../../security/advisories/new)
for this repository (Security tab → Report a vulnerability), or by emailing
**ajuujain99@gmail.com** with a description of the issue, the affected version, and
reproduction steps if you have them.

You should expect an acknowledgement within a few days. There is no bug bounty — this is a
personal project — but every report will be read, taken seriously, and credited in the fix
unless you ask not to be.

## What counts as in scope

Anything that breaks a claim made in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is in scope,
in particular:

- A way to read a secret's value without a valid, unrevoked, unexpired token whose policy
  grants it.
- A way for a token bound to one uid (`--bind-uid`) to be used successfully from another uid.
- A way to forge, truncate, or otherwise tamper with the audit chain such that
  `secretbae audit verify` reports it as clean.
- A way for a token attached only to the built-in `unrestricted` policy to perform an `admin`
  action (creating or revoking a token, writing a policy).
- Memory safety issues in the one `unsafe` module (`sbae-daemon::privdrop`), or a privilege
  drop that does not actually take effect.
- A way to make the daemon panic, hang, or crash from an unauthenticated connection.

## What is explicitly out of scope

Stated plainly in the threat model, and restated here so a report about one of these is not a
surprise to decline: **root compromise** of the host, **kernel compromise**, **physical memory
access** (cold boot, DMA), and **a malicious system operator**. secretbae does not attempt to
defend against any of these, and a report describing one of them will be closed as
out-of-scope rather than treated as a vulnerability.

Also out of scope on its own: the residual risk that the keyfile and the encrypted store share
a filesystem, meaning a stolen disk image is a full compromise. This is a known, documented
tradeoff (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), "Two accepted tradeoffs") — a
report proposing a hardware-backed seal (TPM2) as a mitigation is welcome as a feature request,
but the current behavior is not itself a bug.
