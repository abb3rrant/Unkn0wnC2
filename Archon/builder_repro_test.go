package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificateSPKISHA256(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	der := server.TLS.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "archon.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := base64.StdEncoding.EncodeToString(sum[:])
	got, err := certificateSPKISHA256(certPath)
	if err != nil {
		t.Fatalf("certificateSPKISHA256() error = %v", err)
	}
	if got != want {
		t.Fatalf("pin = %q, want %q", got, want)
	}
}

func TestBuilderEmbedsMasterSPKIPin(t *testing.T) {
	source, err := os.ReadFile("builder.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "certificateSPKISHA256(api.config.TLSCert)") {
		t.Fatal("DNS listener builder does not pin the configured Archon certificate")
	}
	if !strings.Contains(text, "MasterSPKIPin") {
		t.Fatal("DNS listener builder does not project the Archon SPKI pin")
	}
}

func TestBuilderKeepsModuleGraphReadOnly(t *testing.T) {
	source, err := os.ReadFile("builder.go")
	if err != nil {
		t.Fatalf("read builder.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, `exec.Command("go", "mod", "tidy")`) {
		t.Fatal("production builder must not rewrite the pinned module graph")
	}
	if got := strings.Count(text, `exec.Command("go", "mod", "download")`); got != 2 {
		t.Fatalf("go mod download command count = %d, want 2", got)
	}
	if got := strings.Count(text, `"build", "-mod=readonly"`); got != 2 {
		t.Fatalf("read-only go build command count = %d, want 2", got)
	}
	if got := strings.Count(text, `"-tags=generated"`); got != 1 {
		t.Fatalf("generated-config build tag count = %d, want 1", got)
	}
}
