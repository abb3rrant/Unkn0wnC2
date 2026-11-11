package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A successful response must finish the actual page loader without referring
// to a removed renderer. Run the source function, not a duplicate implementation.
func TestProfilePageLoaderCompletesAfterSuccessfulResponse(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js required to execute the profile page loader")
	}
	page, err := os.ReadFile(filepath.Join("web", "listeners.html"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	start := strings.Index(text, "async function loadProfiles()")
	end := strings.Index(text, "function renderProfileList()")
	if start < 0 || end <= start {
		t.Fatal("profile page loader boundaries not found")
	}
	script := `let profiles = [];
let rendered = false;
const document = { getElementById: () => ({ innerHTML: '' }) };
const authFetch = async () => ({ ok: true, json: async () => ({ data: { profiles: [{name:'fixture'}] } }) });
function renderProfileList() { rendered = true; }
` + text[start:end] + `
loadProfiles().then(() => {
    if (!rendered || profiles.length !== 1 || profiles[0].name !== 'fixture') {
        throw new Error('successful profile load did not render the returned profiles');
    }
}).catch(error => { console.error(error.message); process.exitCode = 1; });
`
	if output, err := exec.Command(node, "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("successful profile load rejected: %v\n%s", err, output)
	}
}

// The CSP allows local styles only. External Google Fonts links are therefore
// blocked requests, not usable fonts; preserve the existing rendered fallback
// fonts rather than weakening the policy to permit third-party requests.
func TestWebPagesDoNotRequestCSPBlockedGoogleFonts(t *testing.T) {
	pages, err := filepath.Glob(filepath.Join("web", "*.html"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("locate page fixtures: pages=%d err=%v", len(pages), err)
	}
	for _, page := range pages {
		t.Run(filepath.Base(page), func(t *testing.T) {
			body, err := os.ReadFile(page)
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"fonts.googleapis.com", "fonts.gstatic.com"} {
				if strings.Contains(string(body), host) {
					t.Errorf("page still requests %s despite self-only stylesheet CSP", host)
				}
			}
		})
	}
}
