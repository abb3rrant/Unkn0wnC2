//go:build !windows || !amd64

package main

import (
	"strings"
	"testing"
)

// A build that cannot load COFF objects must say so, rather than reporting a
// generic failure the operator would chase as a transport problem.
func TestHandleBOFCommand_ReportsPlatformOnUnsupportedBuild(t *testing.T) {
	beacon := &Beacon{transport: &transportManager{mode: transportHTTP}}

	result := beacon.handleBOFCommand(bofDocument(t, ""))
	if !strings.Contains(result, "windows/amd64") {
		t.Fatalf("result = %q, want it to name the required platform", result)
	}
}
