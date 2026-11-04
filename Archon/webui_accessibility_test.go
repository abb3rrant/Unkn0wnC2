package main

import (
	"regexp"
	"strings"
	"testing"
)

// Authenticated pages share the same navigation contract, including detail pages.
func TestWebUIAccessibleNavigation(t *testing.T) {
	pages := map[string]string{
		"dashboard.html": "/dashboard", "beacon.html": "/dashboard",
		"builder.html": "/builder", "listeners.html": "/listeners",
		"listener.html": "/listeners", "stager.html": "/stager",
		"exfils.html": "/exfils", "logs.html": "/logs",
		"report.html": "/report", "users.html": "/users",
	}
	navRe := regexp.MustCompile(`(?s)<nav class="nav-menu" aria-label="Primary">(.*?)</nav>`)
	linkRe := regexp.MustCompile(`<a href="([^"]+)"[^>]*>`)
	wantLinks := "/dashboard,/builder,/listeners,/stager,/exfils,/logs,/report,/users"
	for page, active := range pages {
		t.Run(page, func(t *testing.T) {
			html := readWebFile(t, page)
			nav := navRe.FindStringSubmatch(html)
			if len(nav) != 2 {
				t.Fatal("missing labelled primary navigation landmark")
			}
			var links []string
			current := ""
			for _, link := range linkRe.FindAllStringSubmatch(nav[1], -1) {
				links = append(links, link[1])
				if strings.Contains(link[0], `aria-current="page"`) {
					if current != "" {
						t.Fatal("multiple current navigation sections")
					}
					current = link[1]
				}
			}
			if strings.Join(links, ",") != wantLinks {
				t.Errorf("inconsistent navigation order: %v", links)
			}
			if current != active {
				t.Errorf("current section = %q, want %q", current, active)
			}
			skip := strings.Index(html, `<a class="skip-link" href="#main-content">Skip to content</a>`)
			if skip < 0 || skip > strings.Index(html, `<nav class="navbar">`) {
				t.Error("skip link must precede header controls")
			}
			if strings.Count(html, `<main class="container" id="main-content" tabindex="-1">`) != 1 || strings.Count(html, "</main>") != 1 {
				t.Error("expected one focusable main content landmark")
			}
		})
	}
}
