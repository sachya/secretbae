---
title: API
nav_order: 4
---

# API

Two ways to talk to `secretbaed` directly, without going through the `secretbae` CLI or the
`exec` wrapper. Most applications should use [`secretbae exec`](OPERATIONS.html#giving-secrets-to-an-application)
instead — it needs no code at all. These exist for the cases it doesn't cover: writing a client
in a language other than the shell, or reading a secret from a long-running process without
restarting it.

Both speak Unix domain sockets only. Neither ever listens on a network port — the shipped
systemd unit enforces this at the kernel level with `RestrictAddressFamilies=AF_UNIX`, so this
is not a promise resting on application code staying correct.

## Authentication, both protocols

Every request carries a token, and every request passes the same three gates before anything
else happens:

1. **Filesystem.** The socket is `0660`, owned by the daemon's service account; the caller's
   uid must be in that group to open the connection at all.
2. **Token.** Must be syntactically valid, unexpired, and unrevoked.
3. **`SO_PEERCRED` and policy.** If the token was created with `--bind-uid`, the kernel-reported
   uid of the connecting process must match. The token's attached policies must grant the
   capability the request needs, on the path it targets.

A request that fails any gate gets the same message either way: `not found or not permitted`.
The daemon never distinguishes "no such secret" from "you may not read this" in what it sends
back — see [THREAT_MODEL.md](THREAT_MODEL.html) (`T-ERR-ORACLE`) for why.

---

## 1. The HTTP API

JSON over HTTP/1.1, on the main socket (`/run/secretbae/sock` by default — see `socket` in
`config.toml`). This is what the `secretbae` CLI itself speaks; there is no separate protocol
the CLI gets and everyone else doesn't.

- Every route is `POST`, including reads — secret paths therefore never appear in a request
  line, where they'd end up in access logs and `ps` output.
- The token goes in the `Authorization` header: `Authorization: Bearer <token>`.
- Request and response bodies are JSON. Secret values are base64-encoded so binary payloads
  (keys, certificates) survive intact.
- Every field is validated strictly: an unrecognized field in a request body is rejected rather
  than silently ignored.
- Errors are `{"error": "<message>"}` with a `4xx`/`5xx` status. The message is deliberately
  coarse for anything permission-shaped; see above.

### Connecting

Any HTTP client capable of dialing a Unix socket path instead of a TCP host works. A few
examples fetching `GET /v1/status`'s equivalent (`POST` with an empty body):

```bash
curl -s --unix-socket /run/secretbae/sock \
  -H "Authorization: Bearer $(cat token)" \
  -H "Content-Type: application/json" \
  -d '{}' http://localhost/v1/status
```

```python
import http.client, socket, json

class UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/secretbae/sock")

conn = UnixHTTPConnection("localhost")
conn.request("POST", "/v1/status", body="{}", headers={
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
})
print(json.loads(conn.getresponse().read()))
```

```php
<?php
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_UNIX_SOCKET_PATH => '/run/secretbae/sock',
    CURLOPT_URL => 'http://localhost/v1/status',
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => '{}',
    CURLOPT_HTTPHEADER => ["Authorization: Bearer $token", 'Content-Type: application/json'],
    CURLOPT_RETURNTRANSFER => true,
]);
echo curl_exec($ch);
```

### Routes

Capability required is in parentheses. `Admin` routes are for the CLI's own token/policy
management; an application should never need them.

| Route | Request | Response | Capability |
| :--- | :--- | :--- | :--- |
| `POST /v1/status` | `{}` | `{version, schema_version, sealed, seal_kind, mk_generation, secret_count}` | List |
| `POST /v1/secrets/read` | `{path, version?}` | `{path, version, value}` | Read |
| `POST /v1/secrets/write` | `{path, value, tags?, comment?}` | `{path, version}` | Write |
| `POST /v1/secrets/list` | `{prefix?, tags?}` | `{secrets: [{path, current_version, version_count, tags, updated_at}]}` | List |
| `POST /v1/secrets/versions` | `{path}` | `{path, versions: [{version, state, created_at, created_by, comment}]}` | List |
| `POST /v1/secrets/rollback` | `{path, to}` | `{ok}` | Delete |
| `POST /v1/secrets/delete` | `{path, version?, destroy?}` | `{ok}` | Delete |
| `POST /v1/tags/add` | `{path, tags}` | `{ok}` | Write |
| `POST /v1/tags/remove` | `{path, tags}` (selectors: a bare key removes every value under it) | `{ok}` | Write |
| `POST /v1/resolve` | `{paths}` | `{secrets: [{path, version, value}]}` | Read |
| `POST /v1/tokens/create` | `{name, policies, bind_uid?, ttl_seconds?}` | `{token, prefix, expires_at}` — the only time the token itself is sent | Admin |
| `POST /v1/tokens/list` | `{}` | `{tokens: [{prefix, name, policies, bound_uid, created_at, expires_at, revoked, last_used_at}]}` | Admin |
| `POST /v1/tokens/revoke` | `{prefix}` | `{ok}` | Admin |
| `POST /v1/policies/put` | `{document}` (a policy document as JSON text) | `{ok}` | Admin |
| `POST /v1/policies/list` | `{}` | `{policies: [name]}` | Admin |
| `POST /v1/policies/delete` | `{name}` | `{ok}` | Admin |
| `POST /v1/audit/verify` | `{}` | `{entries, broken_at, detail}` | Admin |
| `POST /v1/rekey` | `{}` | `{versions_rewrapped, audit_entries_rekeyed, generation}` | Admin |
| `POST /v1/backup` | `{passphrase}` | `{bundle, secrets, versions}` | Admin |
| `POST /v1/restore` | `{passphrase, bundle}` | `{secrets, versions, policies}` | Admin |

`/v1/resolve` is the one route worth calling out for an application: it's what `exec` calls
once, batched, for a whole profile. A path the caller may not read fails the **entire** batch
(`403`, not a partial result) — a profile listing an unreadable path is refused outright rather
than handing the application a short environment it then fails on later.

`sbae-proto`'s `api` module (`crates/sbae-proto/src/api.rs`) is the single source of truth for
every route path, request/response field, and the capability each route requires — this table
is a summary of it, not a separate spec.

---

## 2. The resolve socket

A second, minimal, read-only protocol on its own socket (`/run/secretbae/resolve.sock` by
default — see `resolve_socket` in `config.toml`), for reading secrets from a long-running
application's own code without an HTTP client or a JSON parser. It grants nothing the HTTP
`/v1/resolve` route doesn't already grant — same token, same `SO_PEERCRED` check, same `Read`
capability scope — it is just a plainer way to reach the same thing.

**Use `secretbae exec` if you can.** It needs no code in your application at all. Reach for this
only when a process needs to notice a rotated secret without restarting — `exec` fetches once,
at start, and there's no way to make it fetch again short of a restart (see
[OPERATIONS.md](OPERATIONS.html#rotating-a-secret)). This is still meant to be called when a
process starts, or occasionally afterward, not on every request it serves.

### Wire format

One request per connection. Every line ends with `\n`. All-or-nothing: if every requested path
is readable, every value comes back; if even one is not, the whole batch is refused — matching
`/v1/resolve`'s own behavior, for the same reason.

**Request:**

```
RESOLVE 1 <token> <path-count>\n
<path-1>[@<version-1>]\n
<path-2>[@<version-2>]\n
...                          -- exactly <path-count> lines
```

- `RESOLVE` is the only verb. `1` is the protocol version.
- `<token>` is the same bearer token used everywhere else.
- `<path-count>` is how many path lines follow — at most 256. There is no terminator line; the
  daemon reads exactly this many.
- Each path line is a secret path, optionally suffixed `@<version>` to pin a version instead of
  tracking current — the same optional pin `secretbae get --version` offers.

**Response, on success** — one block per path, in the order requested, raw bytes (no base64):

```
VALUE <version> <byte-length>\n<byte-length raw bytes>
VALUE <version> <byte-length>\n<byte-length raw bytes>
...
```

**Response, on any failure** — exactly one line, then the daemon closes the connection:

```
ERROR <message>\n
```

`<message>` is the same generic `not found or not permitted` for anything permission-shaped, or
`internal error` for a genuine server-side fault. A batch of zero paths still requires and
authenticates a valid token; it just gets zero `VALUE` blocks back on success.

A line over 4096 bytes, a batch over 256 paths, or a client that stalls for more than a few
seconds mid-request all get the connection closed rather than read or waited on indefinitely —
this hand-rolled parser doesn't get axum/hyper's protections for free, so it bounds itself
explicitly instead.

### Example clients

Neither example uses a library beyond the language's own standard socket support.

**Python:**

```python
import socket

def resolve(token: str, paths: list[str], sock_path="/run/secretbae/resolve.sock"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    request = f"RESOLVE 1 {token} {len(paths)}\n" + "".join(f"{p}\n" for p in paths)
    s.sendall(request.encode())

    f = s.makefile("rb")
    results = []
    for _ in paths:
        line = f.readline().decode().rstrip("\n")
        if line.startswith("ERROR"):
            raise RuntimeError(line[len("ERROR "):])
        _, version, length = line.split(" ")
        results.append((int(version), f.read(int(length))))
    s.close()
    return results

[(version, value)] = resolve(token, ["prod/billing/db_url"])
db_url = value.decode()
```

**PHP:**

```php
<?php
function sbae_resolve(string $token, array $paths, string $sock = "/run/secretbae/resolve.sock"): array
{
    $fp = stream_socket_client("unix://$sock", $errno, $errstr);
    if (!$fp) {
        throw new RuntimeException("connect failed: $errstr");
    }

    $request = sprintf("RESOLVE 1 %s %d\n", $token, count($paths));
    foreach ($paths as $path) {
        $request .= "$path\n";
    }
    fwrite($fp, $request);

    $results = [];
    foreach ($paths as $_) {
        $line = rtrim(fgets($fp), "\n");
        if (str_starts_with($line, "ERROR")) {
            throw new RuntimeException(substr($line, 6));
        }
        [, $version, $length] = explode(" ", $line);
        $value = fread($fp, (int) $length);
        $results[] = [(int) $version, $value];
    }
    fclose($fp);
    return $results;
}

[[$version, $dbUrl]] = sbae_resolve($token, ["prod/billing/db_url"]);
```

Any other language follows the same three steps: open a Unix socket, write the request as
described above, then read a line at a time — parsing `VALUE <version> <length>` and reading
exactly `<length>` more bytes, or treating a line starting `ERROR ` as the whole batch's
failure.
