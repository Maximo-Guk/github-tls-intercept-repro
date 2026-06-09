# gh-tls-repro — HTTPS intercept proxy dirty-close vs GnuTLS git

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Maximo-Guk/github-tls-intercept-repro)

> Deploying spins up the demo container + landing page. It does **not** reproduce the `-110` failure over the public URL — Cloudflare's edge re-terminates TLS cleanly (see [Important notes](#important-notes)); the repro must hit the container's `:8443` directly.

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

`/` on `:8080` serves a landing page that runs the probes and renders the result.

## Observability — making the bug show up in logs

Because a deployed container's behavior is only visible through logs, the
container runs **two probes** — on a 30s timer, on container start, and on demand
via `GET /probe`. Each emits one structured JSON line to **stdout** (so it
appears in container/Worker logs, `wrangler tail`, and dashboard observability).

### A. Self-test — always reproduces, anywhere

Hits the container's **own** `:8443` dirty-close listener, so the failure
surfaces no matter where it's deployed. The **authoritative** signal is a
GnuTLS-linked `git ls-remote` that fails with `-110`:

```json
{"event":"selftest","target":"localhost:8443","gnutls_110":true,"git_exit":128,
 "git_error":"... GnuTLS recv error (-110): The TLS connection was non-properly terminated.",
 "go_detects_dirty":false,"go_terminal_err":"EOF","ts":"..."}
```

> **Why git, not Go, is the detector.** Go's `crypto/tls` (like OpenSSL)
> *tolerates* a dirty close when the final TLS record is complete: it returns
> plain `io.EOF`, indistinguishable from a clean `close_notify`. Go only flags
> `io.ErrUnexpectedEOF` on a *truncated* (mid-record) close. The COR bug — and
> this listener — send complete records with no `close_notify`, so `go_detects_dirty`
> is `false` while `gnutls_110` is `true`. That asymmetry is the bug: GnuTLS is
> strict, OpenSSL/Go are lenient. The self-test reports both, and treats
> `gnutls_110` as ground truth.

### B. Real-egress probe — reveals whether THIS env intercepts

Dials the real `github.com:443` and logs the served leaf cert issuer:

```json
{"event":"egress_probe","host":"github.com","intercepted":true,
 "cert_issuer":"Cloudflare TLS proxy-everything Intercept CA",
 "go_detects_dirty":false,"go_terminal_err":"EOF","ts":"..."}
```

`intercepted` is `true` when the issuer is the cloudchamber intercept CA
(`Cloudflare TLS proxy-everything Intercept CA`). **On a normal Cloudflare
account this logs `intercepted:false` with a real public CA (DigiCert/Sectigo)
and a clean shutdown**, because a vanilla container's own egress bypasses the
egress proxy entirely — direct/public egress is FIB-forwarded straight to the
internet and never traverses `cc-oxy-router-v2`'s TLS interceptor (which only
wraps Worker-routed egress endpoints explicitly configured with `tls=true`).
Inside a Seal-style intercepted environment it logs `intercepted:true` with the
Intercept CA. Either way the line is informative.

### Viewing the logs

- **Deployed Worker:** `npx wrangler tail` (or the dashboard → Worker →
  Observability/Logs). The Worker's `GET /probe` also `console.log`s the report,
  and the container's stdout JSON lines are captured in the Worker/container logs.
- **Worker endpoints:** `GET /probe` returns the combined JSON; `GET /` renders
  the landing page with the live probe results embedded.
- **Local container:** the JSON lines print to the container's stdout (see below).

## Run it

Requires Go (the `Dockerfile` builds it; locally `go run` is fine). The proxy
fetches from the real `github.com`, so the host needs outbound network access.

```bash
# from the repo root
( cd container_src && go run . )
# logs:
#   plain HTTP proxy listening on :8080 -> https://github.com
#   dirty-close TLS proxy listening on :8443 -> https://github.com
# then, every 30s (and at startup), structured probe lines:
#   {"event":"selftest", ... "gnutls_110":true ...}
#   {"event":"egress_probe", ... "intercepted":<bool> ...}
```

Or via Docker (matches the deployed image):

```bash
docker build -t gh-tls-repro .
docker run --rm -p 8080:8080 -p 8443:8443 gh-tls-repro
# watch the structured probe JSON on stdout; GET http://localhost:8080/probe
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
- **A deployed Worker will NOT show the bug over its public URL on `:8443`.**
  Cloudflare's edge re-terminates TLS in front of the Worker and sends a clean
  `close_notify`, masking the missing alert. That's why the **self-test** exists:
  the container probes its *own* `:8443` internally and logs the GnuTLS `-110`, so
  the bug is visible in deployed logs even though you can't trigger it from the
  public URL. The Worker forwards external traffic to the container's `:8080`.
- The proxy fetches from the live `github.com`; if the host's own egress also
  dirty-closes, the Go upstream client tolerates it (OpenSSL-style) and returns
  the buffered bytes.

## Files

- `container_src/main.go` — the proxy (both listeners), landing page, `/probe`
  endpoint, and the 30s probe timer. The crux is `serveDirtyTLS`, which calls
  `tc.NetConn().Close()` and never `tls.Conn.Close()`.
- `container_src/probe.go` — the two probes: `runSelfTest` (own `:8443` +
  GnuTLS git `-110`) and `runEgressProbe` (real github cert-issuer +
  close classification), plus the structured JSON log lines.
- `Dockerfile` — builds the Go binary, exposes `8080` + `8443`.
- `src/index.ts` + `wrangler.jsonc` — Worker/Container scaffolding: `GET /probe`
  runs both probes and `console.log`s the report; everything else forwards to the
  container's `:8080`.

## The production fix

The shippable fix is the same one already used for other intercepted hosts:
rewrite git's transport to plain HTTP so the proxy (not git) owns the upstream
TLS:

```bash
git config --global url."http://github.com/".insteadOf "https://github.com/"
```

The proper long-term fix lives in the intercept proxy itself: send a TLS
`close_notify` before closing the socket.
