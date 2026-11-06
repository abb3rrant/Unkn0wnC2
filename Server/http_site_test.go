package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// siteForTest returns a small cover site with a nested asset and a custom 404.
func siteForTest() *HTTPSite {
	return &HTTPSite{
		Revision: 1,
		Files: map[string]HTTPSiteFile{
			"/index.html":     {Content: []byte("<html>cover</html>"), ContentType: "text/html; charset=utf-8"},
			"/assets/app.css": {Content: []byte("body{color:red}"), ContentType: "text/css; charset=utf-8"},
			"/404.html":       {Content: []byte("<html>missing</html>"), ContentType: "text/html; charset=utf-8"},
		},
	}
}

func TestHTTPListener_ServesCoverSite(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	// The helper persists the profile document and reloads it, which drops the
	// non-serialized Site; attach it to the live store entry the listener reads.
	if live, ok := listener.store.Get(profile.Name); ok {
		live.Site = siteForTest()
	}
	baseURL := "http://" + listener.Addr()

	get := func(path string) (int, http.Header, string) {
		resp, err := http.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(raw)
	}

	t.Run("root serves index", func(t *testing.T) {
		status, header, body := get("/")
		if status != http.StatusOK || body != "<html>cover</html>" {
			t.Fatalf("GET / = %d %q, want 200 index", status, body)
		}
		if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
	})

	t.Run("nested asset", func(t *testing.T) {
		status, header, body := get("/assets/app.css")
		if status != http.StatusOK || body != "body{color:red}" {
			t.Fatalf("GET asset = %d %q", status, body)
		}
		if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
			t.Errorf("Content-Type = %q, want text/css", ct)
		}
	})

	t.Run("custom 404", func(t *testing.T) {
		status, _, body := get("/nope")
		if status != http.StatusNotFound || body != "<html>missing</html>" {
			t.Fatalf("GET /nope = %d %q, want custom 404", status, body)
		}
	})

	t.Run("HEAD has no body", func(t *testing.T) {
		resp, err := http.Head(baseURL + "/index.html")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || len(raw) != 0 {
			t.Fatalf("HEAD = %d body %q, want 200 empty", resp.StatusCode, raw)
		}
		if resp.ContentLength != int64(len("<html>cover</html>")) {
			t.Errorf("Content-Length = %d", resp.ContentLength)
		}
	})

	t.Run("non-GET is not served as a file", func(t *testing.T) {
		resp, err := http.Post(baseURL+"/index.html", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if string(raw) == "<html>cover</html>" {
			t.Fatal("POST was answered from the cover site")
		}
	})

	t.Run("C2 URI still wins", func(t *testing.T) {
		// The profile's task URI is claimed by the operation table, so an
		// unsigned request must be rejected as C2 traffic, not served as a page.
		status, _, body := get(profile.URIs.Task[0])
		if status == http.StatusOK || body == "<html>cover</html>" {
			t.Fatalf("C2 task URI was served from the cover site (%d %q)", status, body)
		}
	})

	t.Run("bootstrap path still wins", func(t *testing.T) {
		status, _, body := get(bootstrapPathDefault)
		if status != http.StatusBadRequest || !strings.Contains(body, "token required") {
			t.Fatalf("GET %s = %d %q, want 400 token required", bootstrapPathDefault, status, body)
		}
	})
}

func TestHTTPListener_NoSiteKeepsScannerBehaviour(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	baseURL := "http://" + listener.Addr()

	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("profile without a site answered 200: %q", raw)
	}
	if profile.Status.NotFound != 0 && resp.StatusCode != profile.Status.NotFound {
		t.Errorf("status = %d, want profile not-found %d", resp.StatusCode, profile.Status.NotFound)
	}
}

func TestParseByteRange(t *testing.T) {
	const size = 15
	cases := []struct {
		header        string
		start, end    int64
		ok            bool
		unsatisfiable bool
	}{
		{"", 0, 0, false, false},
		{"bytes=0-3", 0, 3, true, false},
		{"bytes=10-", 10, 14, true, false},
		{"bytes=-4", 11, 14, true, false},
		{"bytes=0-99", 0, 14, true, false},
		{"bytes=99-", 0, 0, true, true},
		{"bytes=-0", 0, 0, false, false},
		{"bytes=0-1,4-5", 0, 0, false, false},
		{"bytes=x-y", 0, 0, false, false},
		{"items=0-3", 0, 0, false, false},
		{"bytes=-", 0, 0, false, false},
	}
	for _, tc := range cases {
		start, end, ok, unsatisfiable := parseByteRange(tc.header, size)
		if start != tc.start || end != tc.end || ok != tc.ok || unsatisfiable != tc.unsatisfiable {
			t.Errorf("parseByteRange(%q) = (%d,%d,%v,%v), want (%d,%d,%v,%v)",
				tc.header, start, end, ok, unsatisfiable, tc.start, tc.end, tc.ok, tc.unsatisfiable)
		}
	}
}

func TestHTTPListener_CoverSiteRange(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	if live, ok := listener.store.Get(profile.Name); ok {
		live.Site = siteForTest()
	}
	baseURL := "http://" + listener.Addr()

	do := func(method, path, rangeHeader string) (*http.Response, string) {
		req, err := http.NewRequest(method, baseURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(raw)
	}

	t.Run("full response advertises ranges", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "")
		if resp.StatusCode != http.StatusOK || body != "body{color:red}" {
			t.Fatalf("full GET = %d %q", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Accept-Ranges"); got != "bytes" {
			t.Errorf("Accept-Ranges = %q", got)
		}
	})

	t.Run("first bytes", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "bytes=0-3")
		if resp.StatusCode != http.StatusPartialContent || body != "body" {
			t.Fatalf("range = %d %q", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Range"); got != "bytes 0-3/15" {
			t.Errorf("Content-Range = %q", got)
		}
		if got := resp.Header.Get("Content-Length"); got != "4" {
			t.Errorf("Content-Length = %q", got)
		}
	})

	t.Run("open ended", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "bytes=10-")
		if resp.StatusCode != http.StatusPartialContent || body != ":red}" {
			t.Fatalf("range = %d %q", resp.StatusCode, body)
		}
	})

	t.Run("suffix", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "bytes=-4")
		if resp.StatusCode != http.StatusPartialContent || body != "red}" {
			t.Fatalf("range = %d %q", resp.StatusCode, body)
		}
	})

	t.Run("unsatisfiable", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "bytes=99-")
		if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable || body != "" {
			t.Fatalf("range = %d %q", resp.StatusCode, body)
		}
		if got := resp.Header.Get("Content-Range"); got != "bytes */15" {
			t.Errorf("Content-Range = %q", got)
		}
	})

	t.Run("multi range falls back to full", func(t *testing.T) {
		resp, body := do(http.MethodGet, "/assets/app.css", "bytes=0-1,4-5")
		if resp.StatusCode != http.StatusOK || body != "body{color:red}" {
			t.Fatalf("multi-range = %d %q", resp.StatusCode, body)
		}
	})

	t.Run("head with range has no body", func(t *testing.T) {
		resp, body := do(http.MethodHead, "/assets/app.css", "bytes=0-3")
		if resp.StatusCode != http.StatusPartialContent || body != "" {
			t.Fatalf("HEAD range = %d %q", resp.StatusCode, body)
		}
		if resp.ContentLength != 4 {
			t.Errorf("Content-Length = %d", resp.ContentLength)
		}
	})
}
