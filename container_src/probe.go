package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"
)

// interceptCACommonName is the issuer CN minted per-VM by cloudchamber's
// firechamber-spawn and pushed into cc-oxy-router-v2. Observing it on a real
// github.com connection proves the egress is being MITM'd.
const interceptCACommonName = "Cloudflare TLS proxy-everything Intercept CA"

// closeResult classifies how a TLS stream ended after the full response was read.
//
// Go's crypto/tls maps the teardown to a terminal Read error:
//
//	io.EOF              -> the final TLS record was complete. Go returns this for
//	                       BOTH a clean close_notify AND a raw TCP FIN after a
//	                       complete record. Go is tolerant here and does NOT
//	                       distinguish the two (the decrypted close_notify, if
//	                       any, is folded into io.EOF). This is exactly why an
//	                       OpenSSL client tolerates what GnuTLS rejects.
//	io.ErrUnexpectedEOF -> the connection closed MID-record (truncated). Go flags
//	                       this as a dirty close.
//
// Therefore `go_detects_dirty` is true only for the truncated case. For a
// complete-record dirty close (the COR bug shape, and what our :8443 listener
// emits) Go cannot tell it apart from clean — the authoritative detector is the
// GnuTLS-linked git probe (gnutls_110), which is why the self-test shells out to
// git.
type closeResult struct {
	GoDetectsDirty bool   `json:"go_detects_dirty"`
	TerminalErr    string `json:"terminal_err"`
}

// classifyClose reads to the end of an already-established TLS stream and
// classifies the terminal error. The caller must have already written its
// request; classifyClose drains all remaining bytes then issues one final Read.
func classifyClose(conn *tls.Conn) closeResult {
	buf := make([]byte, 16*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Read(buf)
		if err == nil {
			continue // still draining the body
		}
		return closeResult{
			GoDetectsDirty: errors.Is(err, io.ErrUnexpectedEOF),
			TerminalErr:    err.Error(),
		}
	}
}

// SelfTestResult (event "selftest") is the always-reproduces probe: it hits the
// container's OWN :8443 dirty-close listener, so the missing-close_notify
// failure surfaces in logs regardless of the deploy environment. The
// authoritative dirty-close signal is gnutls_110 (a GnuTLS-linked git fails
// with -110); go_detects_dirty is the weaker Go-side signal (truncation only).
type SelfTestResult struct {
	Event          string `json:"event"`
	Target         string `json:"target"`
	Gnutls110      bool   `json:"gnutls_110"`
	GitExit        int    `json:"git_exit"`
	GitError       string `json:"git_error,omitempty"`
	GoDetectsDirty bool   `json:"go_detects_dirty"`
	GoTerminalErr  string `json:"go_terminal_err"`
	Err            string `json:"err,omitempty"`
	TS             string `json:"ts"`
}

// EgressProbeResult (event "egress_probe") dials the REAL github.com:443 and
// reports the served leaf cert issuer (proving interception when it is the
// Intercept CA) plus the Go-side close classification against real github.
type EgressProbeResult struct {
	Event          string `json:"event"`
	Host           string `json:"host"`
	Intercepted    bool   `json:"intercepted"`
	CertIssuer     string `json:"cert_issuer"`
	GoDetectsDirty bool   `json:"go_detects_dirty"`
	GoTerminalErr  string `json:"go_terminal_err"`
	Err            string `json:"err,omitempty"`
	TS             string `json:"ts"`
}

// ProbeReport bundles both probes for the /probe endpoint and landing page.
type ProbeReport struct {
	SelfTest    SelfTestResult    `json:"selftest"`
	EgressProbe EgressProbeResult `json:"egress_probe"`
}

func nowTS() string { return time.Now().UTC().Format(time.RFC3339) }

// gitInfoRefsRequest is the minimal git smart-HTTP info/refs request line +
// headers. Written over the TLS conn so the dirty-close listener relays a real
// github response that we then read to EOF.
func gitInfoRefsRequest(host, path string) string {
	return "GET " + path + "/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: git/2.34.1\r\n" +
		"Connection: close\r\n\r\n"
}

// runSelfTest probes the container's own :8443 dirty-close TLS listener.
func runSelfTest() SelfTestResult {
	const target = "localhost:8443"
	res := SelfTestResult{Event: "selftest", Target: target, TS: nowTS()}

	// TLS classification: the listener serves a self-signed cert, so skip
	// verification — we only care about the teardown behavior.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", target,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		res.Err = "dial: " + err.Error()
	} else {
		_, werr := conn.Write([]byte(gitInfoRefsRequest("localhost", "/cloudflare/templates.git")))
		if werr != nil {
			res.Err = "write: " + werr.Error()
		} else {
			cr := classifyClose(conn)
			res.GoDetectsDirty = cr.GoDetectsDirty
			res.GoTerminalErr = cr.TerminalErr
		}
		conn.Close()
	}

	// Authoritative signal: a GnuTLS-linked git fails with -110 on a missing
	// close_notify even when the final record is complete.
	exit, gitErr := gitLsRemote("https://localhost:8443/cloudflare/templates.git")
	res.GitExit = exit
	res.GitError = gitErr
	res.Gnutls110 = strings.Contains(gitErr, "GnuTLS recv error (-110)")
	return res
}

// gitLsRemote runs `git ls-remote` (with TLS verification disabled, since the
// listener is self-signed) and returns the exit code and trimmed stderr.
func gitLsRemote(url string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-c", "http.sslVerify=false", "ls-remote", url)
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		exit = 1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		}
	}
	return exit, strings.TrimSpace(string(out))
}

// runEgressProbe dials the REAL github.com:443 and reports interception state.
func runEgressProbe() EgressProbeResult {
	const host = "github.com"
	res := EgressProbeResult{Event: "egress_probe", Host: host, TS: nowTS()}

	// InsecureSkipVerify so we can read the served chain even when it is an
	// intercept CA the container would otherwise reject.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp", host+":443",
		&tls.Config{ServerName: host, InsecureSkipVerify: true},
	)
	if err != nil {
		res.Err = "dial: " + err.Error()
		return res
	}
	defer conn.Close()

	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		res.CertIssuer = certs[0].Issuer.CommonName
		res.Intercepted = res.CertIssuer == interceptCACommonName
	}

	if _, werr := conn.Write([]byte(gitInfoRefsRequest(host, "/cloudflare/templates.git"))); werr != nil {
		res.Err = "write: " + werr.Error()
		return res
	}
	cr := classifyClose(conn)
	res.GoDetectsDirty = cr.GoDetectsDirty
	res.GoTerminalErr = cr.TerminalErr
	return res
}

// runProbes runs both probes and emits each as a structured JSON log line to
// stdout (so it appears in container/Worker logs and `wrangler tail`).
func runProbes() ProbeReport {
	report := ProbeReport{SelfTest: runSelfTest(), EgressProbe: runEgressProbe()}
	logJSON(report.SelfTest)
	logJSON(report.EgressProbe)
	return report
}

func logJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	stdoutLine(string(b))
}
