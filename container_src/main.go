// Command server is a minimal repro of the "HTTPS intercept proxy closes the
// origin TLS connection without a close_notify" bug. GnuTLS-linked git treats a
// missing close_notify as fatal ("GnuTLS recv error (-110): The TLS connection
// was non-properly terminated."), while OpenSSL-based clients (curl, Go's
// net/http) tolerate it.
//
// Two listeners forward to https://github.com:
//
//	:8443  TLS, self-signed. After relaying GitHub's response it closes the
//	       UNDERLYING raw TCP socket directly and NEVER calls tls.Conn.Close()
//	       (which would send close_notify). Responses are connection-close
//	       framed (no Content-Length) so the client reads until EOF and so
//	       reliably observes the premature TLS termination. This reproduces the
//	       bug: git fails with the GnuTLS -110 error.
//
//	:8080  Plain HTTP, no downstream TLS at all. This is the "fix": git speaks
//	       cleartext HTTP to the proxy, the proxy originates a clean OpenSSL TLS
//	       connection upstream. Clones succeed. Mirrors the
//	       url."http://host/".insteadOf "https://host/" git rewrite used in
//	       production sandboxes.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

const upstream = "https://github.com"

// upstreamClient fetches from GitHub like a tolerant OpenSSL client would. It
// must NOT follow redirects (git drives its own redirects) and tolerates the
// sandbox's own dirty-close egress by reading whatever bytes arrive.
var upstreamClient = &http.Client{
	Timeout: 60 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchUpstream proxies the inbound request to github.com and returns the
// status, headers, and fully-buffered body. Buffering the body lets us frame
// the downstream response with Connection: close (read-until-EOF), which is
// what makes the missing close_notify fatal for git.
func fetchUpstream(r *http.Request) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), r.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Host = "github.com"

	resp, err := upstreamClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	// Tolerate a truncated upstream body (the sandbox egress proxy can itself
	// dirty-close): use whatever bytes we managed to read.
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body, nil
}

// writeFramed serializes an HTTP/1.1 response with Connection: close framing
// (no Content-Length / no chunked) directly onto the connection. The client
// must read until the connection ends, so a clean vs. dirty close is
// observable.
func writeFramed(conn net.Conn, status int, header http.Header, body []byte) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	b.WriteString(statusLine(status))
	b.WriteString("\r\n")
	if ct := header.Get("Content-Type"); ct != "" {
		b.WriteString("Content-Type: " + ct + "\r\n")
	}
	// Preserve git's www-authenticate / redirect signalling.
	if loc := header.Get("Location"); loc != "" {
		b.WriteString("Location: " + loc + "\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	conn.Write([]byte(b.String()))
	conn.Write(body)
}

func statusLine(code int) string {
	if t := http.StatusText(code); t != "" {
		return itoa(code) + " " + t
	}
	return itoa(code) + " Status"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// serveDirtyTLS accepts a raw TLS connection, relays one request to github.com,
// writes the response, and then closes the UNDERLYING TCP socket without ever
// invoking tls.Conn.Close(). No close_notify alert is sent — this is the bug.
func serveDirtyTLS(tc *tls.Conn) {
	// Force the handshake so the peer is the *tls.Conn we control.
	if err := tc.Handshake(); err != nil {
		tc.NetConn().Close()
		return
	}
	tc.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(tc))
	if err != nil {
		tc.NetConn().Close()
		return
	}
	status, header, body, err := fetchUpstream(req)
	if err != nil {
		writeFramed(tc, http.StatusBadGateway, http.Header{"Content-Type": {"text/plain"}},
			[]byte("upstream error: "+err.Error()))
	} else {
		writeFramed(tc, status, header, body)
	}
	// CRUX: drop the raw TCP socket. tls.Conn.Close() (which would send
	// close_notify) is deliberately never called.
	tc.NetConn().Close()
}

// plainProxy is the :8080 handler: a clean HTTP reverse proxy to github.com
// with no downstream TLS. This is the working "fix" path.
func plainProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && r.URL.RawQuery == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(landingPage))
		return
	}
	status, header, body, err := fetchUpstream(r)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	if ct := header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if loc := header.Get("Location"); loc != "" {
		w.Header().Set("Location", loc)
	}
	w.WriteHeader(status)
	w.Write(body)
}

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost", "github.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	cert := selfSignedCert()

	// :8443 — dirty-close TLS proxy (reproduces the bug).
	go func() {
		ln, err := net.Listen("tcp", ":8443")
		if err != nil {
			log.Fatalf("listen :8443: %v", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Println("dirty-close TLS proxy listening on :8443 -> https://github.com")
		for {
			raw, err := ln.Accept()
			if err != nil {
				continue
			}
			go serveDirtyTLS(tls.Server(raw, tlsCfg))
		}
	}()

	// :8080 — clean plain-HTTP proxy (demonstrates the fix) + landing page.
	log.Println("plain HTTP proxy listening on :8080 -> https://github.com")
	if err := http.ListenAndServe(":8080", http.HandlerFunc(plainProxy)); err != nil {
		log.Fatal(err)
	}
}

const landingPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>github TLS close_notify repro</title></head>
<body style="font-family:system-ui;max-width:48rem;margin:3rem auto;line-height:1.5">
<h1>GitHub TLS dirty-close repro</h1>
<p>This container is a tiny intercepting reverse proxy for <code>github.com</code>.</p>
<ul>
  <li><b>:8443</b> — HTTPS. Relays GitHub's response then closes the raw TCP
      socket <b>without</b> a TLS <code>close_notify</code>. GnuTLS-linked
      <code>git</code> fails with
      <code>GnuTLS recv error (-110): The TLS connection was non-properly terminated.</code></li>
  <li><b>:8080</b> — plain HTTP (no downstream TLS). Clones succeed. This is the
      <code>https-&gt;http</code> rewrite fix.</li>
</ul>
<pre># reproduces the bug (GnuTLS -110):
git -c http.sslVerify=false clone https://localhost:8443/cloudflare/templates.git

# demonstrates the fix (works):
git clone http://localhost:8080/cloudflare/templates.git</pre>
<p>See the README for full details.</p>
</body>
</html>
`
