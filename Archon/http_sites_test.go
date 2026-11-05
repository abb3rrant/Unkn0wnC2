package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNormalizeSitePath(t *testing.T) {
	valid := map[string]string{
		"index.html":        "/index.html",
		"./index.html":      "/index.html",
		"/index.html":       "/index.html",
		"assets/app.css":    "/assets/app.css",
		`assets\app.css`:    "/assets/app.css",
		"img/logo 2.png":    "/img/logo 2.png",
		"fonts/inter.woff2": "/fonts/inter.woff2",
	}
	for input, want := range valid {
		got, err := normalizeSitePath(input)
		if err != nil {
			t.Errorf("normalizeSitePath(%q) error = %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeSitePath(%q) = %q, want %q", input, got, want)
		}
	}

	invalid := []string{
		"",
		"..",
		"../index.html",
		"a/../b.html",
		"a//b.html",
		"a/",
		"/a/../b.html",
		"a?b.html",
		"a#b.html",
		"a%20b.html",
		"a:b.html",
		"a<b.html",
		"a\x00b.html",
		strings.Repeat("a", 181),
	}
	for _, input := range invalid {
		if got, err := normalizeSitePath(input); err == nil {
			t.Errorf("normalizeSitePath(%q) = %q, want an error", input, got)
		}
	}
}

func TestValidateSiteFiles(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	t.Run("valid", func(t *testing.T) {
		records, err := validateSiteFiles([]HTTPSiteUploadFile{
			{Path: "index.html", Content: encode("<h1>hi</h1>")},
			{Path: "assets/app.css", Content: encode("body{}")},
		})
		if err != nil {
			t.Fatalf("validateSiteFiles() error = %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("got %d records, want 2", len(records))
		}
		byPath := map[string]HTTPSiteFileRecord{}
		for _, record := range records {
			byPath[record.Path] = record
		}
		if got := byPath["/assets/app.css"]; got.ContentType != "text/css; charset=utf-8" {
			t.Errorf("unexpected css record: %+v", got)
		}
		if got := byPath["/index.html"]; got.ContentType != "text/html; charset=utf-8" {
			t.Errorf("unexpected index record: %+v", got)
		}
	})

	t.Run("missing index", func(t *testing.T) {
		if _, err := validateSiteFiles([]HTTPSiteUploadFile{{Path: "about.html", Content: encode("x")}}); err == nil {
			t.Fatal("a site without index.html was accepted")
		}
	})

	t.Run("duplicate path", func(t *testing.T) {
		_, err := validateSiteFiles([]HTTPSiteUploadFile{
			{Path: "index.html", Content: encode("x")},
			{Path: "/index.html", Content: encode("y")},
		})
		if err == nil {
			t.Fatal("duplicate paths were accepted")
		}
	})

	t.Run("unsupported extension", func(t *testing.T) {
		_, err := validateSiteFiles([]HTTPSiteUploadFile{
			{Path: "index.html", Content: encode("x")},
			{Path: "shell.exe", Content: encode("MZ")},
		})
		if err == nil {
			t.Fatal("an executable was accepted")
		}
	})

	t.Run("per-file limit", func(t *testing.T) {
		big := base64.StdEncoding.EncodeToString(make([]byte, maxSiteFileBytes+1))
		_, err := validateSiteFiles([]HTTPSiteUploadFile{
			{Path: "index.html", Content: encode("x")},
			{Path: "big.bin.jpg", Content: big},
		})
		if err == nil {
			t.Fatal("an oversized file was accepted")
		}
	})

	t.Run("too many files", func(t *testing.T) {
		files := []HTTPSiteUploadFile{{Path: "index.html", Content: encode("x")}}
		for i := 0; i < maxSiteFiles; i++ {
			files = append(files, HTTPSiteUploadFile{Path: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".txt", Content: encode("x")})
		}
		if _, err := validateSiteFiles(files); err == nil {
			t.Fatal("more files than the limit were accepted")
		}
	})
}

func TestHTTPProfileSiteRoundTrip(t *testing.T) {
	db := newTestProfileDB(t)

	first := []HTTPSiteFileRecord{
		{Path: "/index.html", Content: []byte("<html>one</html>"), ContentType: "text/html; charset=utf-8", Size: 17, UpdatedAt: 100},
		{Path: "/app.css", Content: []byte("body{}"), ContentType: "text/css; charset=utf-8", Size: 6, UpdatedAt: 100},
	}
	if err := db.SaveHTTPProfileSite("cover", first); err != nil {
		t.Fatalf("SaveHTTPProfileSite() error = %v", err)
	}

	files, err := db.HTTPProfileSiteFiles("cover")
	if err != nil {
		t.Fatalf("HTTPProfileSiteFiles() error = %v", err)
	}
	if len(files) != 2 || files[0].Path != "/app.css" || files[1].Path != "/index.html" {
		t.Fatalf("unexpected files: %+v", files)
	}
	if got := db.HTTPProfileSiteRevision("cover"); got != 100 {
		t.Fatalf("revision = %d, want 100", got)
	}

	// Replacing must remove the files the new site does not contain.
	if err := db.SaveHTTPProfileSite("cover", []HTTPSiteFileRecord{
		{Path: "/index.html", Content: []byte("two"), ContentType: "text/html; charset=utf-8", Size: 3, UpdatedAt: 200},
	}); err != nil {
		t.Fatalf("second SaveHTTPProfileSite() error = %v", err)
	}
	files, _ = db.HTTPProfileSiteFiles("cover")
	if len(files) != 1 || files[0].Path != "/index.html" {
		t.Fatalf("replace left stale files: %+v", files)
	}
	if got := db.HTTPProfileSiteRevision("cover"); got != 200 {
		t.Fatalf("revision after replace = %d, want 200", got)
	}

	if err := db.DeleteHTTPProfileSite("cover"); err != nil {
		t.Fatalf("DeleteHTTPProfileSite() error = %v", err)
	}
	files, _ = db.HTTPProfileSiteFiles("cover")
	if len(files) != 0 {
		t.Fatalf("delete left files: %+v", files)
	}
	if got := db.HTTPProfileSiteRevision("cover"); got != 0 {
		t.Fatalf("revision after delete = %d, want 0", got)
	}
}
