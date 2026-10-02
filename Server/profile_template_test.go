package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestShippedExampleProfileIsValid pins the shipped profile template against the
// profile schema.
//
// The template is what an operator copies and what the Docker build rewrites into
// a real profile, so a field renamed in the schema without updating the template
// would surface as a listener that refuses to start in someone else's deployment
// rather than in CI.
func TestShippedExampleProfileIsValid(t *testing.T) {
	const templatePath = "profiles/cdn-assets.json.example"

	raw, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("failed to read the shipped template: %v", err)
	}

	// The template must parse as a profile document, with defaults applied the
	// same way LoadHTTPProfile does it.
	var profile HTTPProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("shipped template is not valid JSON: %v", err)
	}

	// The template deliberately ships a placeholder pin and the cert paths the
	// installer generates, so validation needs a real certificate in place.
	dir := t.TempDir()
	certPath, keyPath, spki, err := GenerateListenerCert("cdn-assets", dir, "cdn.example.com")
	if err != nil {
		t.Fatalf("GenerateListenerCert() error = %v", err)
	}
	profile.TLS.CertFile = certPath
	profile.TLS.KeyFile = keyPath
	profile.TLS.SPKISHA256 = spki

	if err := profile.Validate(); err != nil {
		t.Fatalf("shipped template does not satisfy the profile schema: %v", err)
	}

	// Every operation the beacon can route to must have a URI, or messages would
	// have nowhere to go in a real deployment.
	for operation, paths := range map[string][]string{
		"register": profile.URIs.Register,
		"task":     profile.URIs.Task,
		"result":   profile.URIs.Result,
		"ack":      profile.URIs.Ack,
	} {
		if len(paths) == 0 {
			t.Errorf("template has no %s URI", operation)
		}
	}

	// And the declared URIs must actually route, which is what the beacon and the
	// listener both rely on.
	for _, probe := range []struct {
		method, path, want string
	}{
		{"POST", "/api/v1/ping", "register"},
		{"GET", "/api/v1/sync", "task"},
		{"POST", "/api/v1/report", "result"},
		{"GET", "/api/v1/ack", "ack"},
	} {
		if got := profile.OperationForPath(probe.method, probe.path); got != probe.want {
			t.Errorf("template URI %s %s routes to %q, want %q", probe.method, probe.path, got, probe.want)
		}
	}
}

// TestShippedExampleProfileIsDisabledByDockerBuild asserts the Docker build's jq
// transformation produces a profile that is valid and disabled.
//
// The image ships a listener profile but must keep its existing DNS-only
// behaviour until an operator opts in, so the enabled flag is part of the recipe.
func TestShippedExampleProfileIsDisabledByDockerBuild(t *testing.T) {
	raw, err := os.ReadFile("profiles/cdn-assets.json.example")
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]interface{}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	// Mirror the Dockerfile: '.tls.spki_sha256 = $pin | .enabled = false'
	document["enabled"] = false
	tlsSection, ok := document["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("template has no tls section for the build to rewrite")
	}
	tlsSection["spki_sha256"] = "generated-pin"

	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "cdn-assets.json")
	if err := os.WriteFile(path, rewritten, 0644); err != nil {
		t.Fatal(err)
	}

	profile, err := LoadHTTPProfile(path)
	if err != nil {
		t.Fatalf("profile rewritten the way the Docker build does is rejected: %v", err)
	}
	if profile.Enabled {
		t.Error("the Docker recipe must leave the profile disabled so the image stays DNS-only")
	}
	if profile.TLS.SPKISHA256 != "generated-pin" {
		t.Errorf("pin was not substituted: %q", profile.TLS.SPKISHA256)
	}
}
