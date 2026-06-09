# gh-tls-repro — HTTPS intercept proxy dirty-close vs GnuTLS git

Minimal, self-contained reproduction of a real bug: an **HTTPS intercept proxy
that closes the origin TLS connection without a `close_notify` alert** breaks
`git clone https://github.com/...` when `git` is linked against **GnuTLS**,
while OpenSSL-based clients (`curl`, Go's `net/http`) tolerate the same
truncated close.

```
GnuTLS recv error (-110): The TLS connection was non-properly terminated.
```

## The bug

GnuTLS treats a TCP connection that ends **without** a TLS `close_notify` alert
as a fatal, possibly-truncated stream and raises error `-110`. OpenSSL treats
the same situation as a tolerable EOF (it warns — `curl` exits `56` — but still
returns the bytes it received). Git's HTTPS transport (`git-remote-https`) uses
whatever TLS library `libcurl` is linked against; on Debian/Ubuntu that is
`libcurl-gnutls.so` → GnuTLS, so a proxy that drops the socket without
`close_notify` makes clones fail even though the full response was delivered.

This is exactly what happens inside sandboxes whose egress is routed through an
HTTPS-intercepting proxy that re-originates upstream TLS and then closes the
downstream socket uncleanly.

## What this repro does

A tiny Go container is an intercepting reverse proxy for `github.com` with two
listeners:

- **`:8443` — HTTPS, reproduces the bug.** Self-signed cert. It relays
  GitHub's real response, then closes the **underlying raw TCP socket directly**
  and **never** calls `tls.Conn.Close()` (which is what would send
  `close_notify`). Responses use `Connection: close` framing (no
  `Content-Length`), so the client reads until EOF and reliably observes the
  premature termination.
- **`:8080` — plain HTTP, demonstrates the fix.** No downstream TLS at all: git
  speaks cleartext to the proxy, and the proxy originates a clean OpenSSL TLS
  connection upstream. Clones succeed. This mirrors the production fix of
  rewriting `https://host/` → `http://host/` for git
  (`git config --global url."http://github.com/".insteadOf "https://github.com/"`).

`/` on `:8080` serves a short landing page describing the repro.

## Run it

Requires Go (the `Dockerfile` builds it; locally `go run` is fine). The proxy
fetches from the real `github.com`, so the host needs outbound network access.

```bash
# from the repo root
( cd container_src && go run . )
# logs:
#   plain HTTP proxy listening on :8080 -> https://github.com
#   dirty-close TLS proxy listening on :8443 -> https://github.com
```

In another shell:

### 1. The bug — git over `:8443` fails with GnuTLS -110

```bash
git -c http.sslVerify=false clone https://localhost:8443/cloudflare/templates.git
```

Expected (with a **GnuTLS-linked** git):

```
Cloning into 'templates'...
fatal: unable to access 'https://localhost:8443/cloudflare/templates.git/': GnuTLS recv error (-110): The TLS connection was non-properly terminated.
```

### 2. curl (OpenSSL) over the same `:8443` succeeds (tolerates the dirty close)

```bash
curl -k "https://localhost:8443/cloudflare/templates.git/info/refs?service=git-upload-pack"
```

Expected: HTTP 200 with the real `git-upload-pack` advertisement, e.g.

```
001e# service=git-upload-pack
00000159<sha> HEAD multi_ack thin-pack side-band ... symref=HEAD:refs/heads/main ...
...
```

`curl` may print `curl: (56) ... Recv failure` / exit `56` (unexpected EOF) — it
still returns the body. That is the whole point: OpenSSL tolerates what GnuTLS
rejects.

### 3. The fix — git over `:8080` (plain HTTP) clones successfully

```bash
git clone http://localhost:8080/cloudflare/templates.git
```

Expected: it gets past the TLS failure and clones the real repository
(`templates/.git` is created). `:8443` fails, `:8080` works → this is the
`https→http` rewrite fix.

## Important notes

- **The exact `-110` wording requires a GnuTLS-linked git.** Check yours:
  ```bash
  ldd "$(git --exec-path)/git-remote-https" | grep -i gnutls
  ```
  An OpenSSL-linked git will tolerate the dirty close (like curl) and will
  **not** reproduce the failure.
- **A deployed Worker will NOT show the bug on `:8443`.** Cloudflare's edge
  re-terminates TLS in front of the Worker and sends a clean `close_notify`,
  masking the missing alert. To observe the real failure you must hit the
  **container directly** on `:8443` (run it locally, or exec into the container).
  The Worker scaffolding here only forwards to the container's `:8080` plain-HTTP
  path.
- The proxy fetches from the live `github.com`; if the host's own egress also
  dirty-closes, the Go upstream client tolerates it (OpenSSL-style) and returns
  the buffered bytes.

## Files

- `container_src/main.go` — the proxy (both listeners + landing page). The crux
  is `serveDirtyTLS`, which calls `tc.NetConn().Close()` and never
  `tls.Conn.Close()`.
- `Dockerfile` — builds the Go binary, exposes `8080` + `8443`.
- `src/index.ts` + `wrangler.jsonc` — minimal Worker/Container scaffolding
  pointing at the container's `:8080`.

## The production fix

The shippable fix is the same one already used for other intercepted hosts:
rewrite git's transport to plain HTTP so the proxy (not git) owns the upstream
TLS:

```bash
git config --global url."http://github.com/".insteadOf "https://github.com/"
```

The proper long-term fix lives in the intercept proxy itself: send a TLS
`close_notify` before closing the socket.
