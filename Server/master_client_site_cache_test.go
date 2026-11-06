package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFetchHTTPProfileSiteCachesByRevision(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		body := "v1"
		if n > 1 {
			body = "v2"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"name":     "cover",
			"revision": 100,
			"files": []map[string]string{{
				"path":         "/index.html",
				"content_type": "text/html; charset=utf-8",
				"content":      base64.StdEncoding.EncodeToString([]byte(body)),
			}},
		})
	}))
	defer srv.Close()

	mc := &MasterClient{
		masterURL:  srv.URL,
		serverID:   "dns-1",
		apiKey:     "key",
		httpClient: srv.Client(),
		siteCache:  map[string]*HTTPSite{},
	}

	first, err := mc.FetchHTTPProfileSite("cover", 100)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if got := string(first.Files["/index.html"].Content); got != "v1" {
		t.Fatalf("first content = %q", got)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("after first fetch hits = %d, want 1", got)
	}

	// Same revision: no second request, same cached object.
	second, err := mc.FetchHTTPProfileSite("cover", 100)
	if err != nil {
		t.Fatalf("cached fetch: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("unchanged revision refetched: hits = %d, want 1", got)
	}
	if second != first {
		t.Fatal("unchanged revision did not return the cached site")
	}

	// New revision: must fetch again and replace the cached copy.
	third, err := mc.FetchHTTPProfileSite("cover", 200)
	if err != nil {
		t.Fatalf("revised fetch: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("revision change hits = %d, want 2", got)
	}
	if got := string(third.Files["/index.html"].Content); got != "v2" {
		t.Fatalf("revised content = %q, want v2", got)
	}

	// A profile that is no longer assigned must not pin its site in memory.
	mc.pruneSiteCache(map[string]int64{})
	mc.siteMutex.Lock()
	_, cached := mc.siteCache["cover"]
	mc.siteMutex.Unlock()
	if cached {
		t.Fatal("prune kept a site for a profile that is no longer assigned")
	}
}

func TestPruneSiteCacheKeepsCurrentRevisions(t *testing.T) {
	mc := &MasterClient{siteCache: map[string]*HTTPSite{
		"keep":   {Revision: 5},
		"drop":   {Revision: 6},
		"delete": {Revision: 7},
	}}

	mc.pruneSiteCache(map[string]int64{"keep": 5, "delete": 0})

	mc.siteMutex.Lock()
	defer mc.siteMutex.Unlock()
	if _, ok := mc.siteCache["keep"]; !ok {
		t.Error("current site was pruned")
	}
	if _, ok := mc.siteCache["drop"]; ok {
		t.Error("unassigned site survived prune")
	}
	if _, ok := mc.siteCache["delete"]; ok {
		t.Error("site with revision 0 survived prune")
	}
}
