package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The listener and HTTP profile pages were once shipped with a header markup and
// control classes that the shared stylesheet never defined (header, header-content,
// logo, logo-img, logo-text, nav, logout-btn, btn, form-select, form-group,
// form-label, form-row). Nothing failed server-side: the pages returned 200 and the
// class attributes were valid HTML, so the only symptom was a page that rendered as
// raw, unstyled markup - the unbounded logo image alone was 1024px tall and covered
// the whole viewport.
//
// These tests pin the two things that actually matter for those pages: they use the
// shared navbar chrome, and every class they reference resolves to a rule in
// static/style.css or in the page's own <style> block.

// HTTP profiles share the listeners page now; there is no profiles.html.
var webUIPages = []string{"listener.html", "listeners.html"}

var classAttrRe = regexp.MustCompile(`class="([^"]*)"`)
var styleBlockRe = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
var selectorRe = regexp.MustCompile(`\.([A-Za-z][A-Za-z0-9_-]*)`)
var classTokenRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

func readWebFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("web", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// definedClasses returns every class name mentioned by a selector in the given CSS.
func definedClasses(css string) map[string]bool {
	defined := make(map[string]bool)
	for _, match := range selectorRe.FindAllStringSubmatch(css, -1) {
		defined[match[1]] = true
	}
	return defined
}

// usedClasses returns the class tokens in a document's class attributes, excluding
// fragments of template literals that only look like class names.
func usedClasses(html string) []string {
	seen := make(map[string]bool)
	var classes []string
	for _, attr := range classAttrRe.FindAllStringSubmatch(html, -1) {
		for _, token := range strings.Fields(attr[1]) {
			// Only tokens that could be a CSS selector count; this drops the
			// fragments of runtime template literals such as ${state ? 'ok' : 'bad'}.
			if !classTokenRe.MatchString(token) {
				continue
			}
			if seen[token] {
				continue
			}
			seen[token] = true
			classes = append(classes, token)
		}
	}
	sort.Strings(classes)
	return classes
}

func TestWebUIPagesUseSharedNavbar(t *testing.T) {
	for _, page := range webUIPages {
		html := readWebFile(t, page)
		if !strings.Contains(html, `class="navbar"`) {
			t.Errorf("%s: does not use the shared .navbar chrome", page)
		}
		// The retired markup that rendered unstyled.
		for _, retired := range []string{`class="header"`, `class="logo-img"`, `class="logout-btn"`} {
			if strings.Contains(html, retired) {
				t.Errorf("%s: still uses %s, which has no rule in static/style.css", page, retired)
			}
		}
	}
}

func TestWebUIPageClassesAreDefined(t *testing.T) {
	shared := definedClasses(readWebFile(t, filepath.Join("static", "style.css")))

	for _, page := range webUIPages {
		html := readWebFile(t, page)
		defined := make(map[string]bool, len(shared))
		for name := range shared {
			defined[name] = true
		}
		for _, block := range styleBlockRe.FindAllStringSubmatch(html, -1) {
			for name := range definedClasses(block[1]) {
				defined[name] = true
			}
		}

		var undefined []string
		for _, class := range usedClasses(html) {
			if !defined[class] {
				undefined = append(undefined, class)
			}
		}
		if len(undefined) > 0 {
			t.Errorf("%s: classes with no CSS rule anywhere: %s", page, strings.Join(undefined, ", "))
		}
	}
}

// The transport panel is derived from the assigned profile list, so the page must
// load the assignments before it renders that panel. Rendering first showed the
// previous state after an assign or a remove.
func TestListenerPageLoadsAssignmentsBeforeTransportPanel(t *testing.T) {
	html := readWebFile(t, "listener.html")

	assignAt := strings.Index(html, "assigned = data.assigned_profiles")
	renderAt := strings.Index(html, "renderTransport(")
	if assignAt < 0 || renderAt < 0 {
		t.Fatalf("listener.html: expected both the assignment load and the transport render")
	}
	if assignAt > renderAt {
		t.Errorf("listener.html: renderTransport runs before assigned profiles are loaded, so the transport panel shows stale state")
	}
}
