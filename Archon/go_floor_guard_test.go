package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var goFloorLiteral = regexp.MustCompile(`go[0-9]+\.[0-9]+\.[0-9]+`)

func floorGuardScript(t *testing.T, path, start, end string, release bool) (string, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	startAt := strings.Index(source, start)
	if startAt < 0 {
		t.Fatalf("could not find guard start %q in %s", start, path)
	}
	endAt := strings.Index(source[startAt:], end)
	if endAt < 0 {
		t.Fatalf("could not find guard end %q in %s", end, path)
	}
	block := source[startAt : startAt+endAt]
	floor := goFloorLiteral.FindString(block)
	if floor == "" {
		// The release script stores the floor immediately before its comparison.
		nearby := source[startAt:]
		floor = goFloorLiteral.FindString(nearby)
	}
	if floor == "" {
		t.Fatalf("could not derive Go floor literal from %s", path)
	}
	prefix := fmt.Sprintf("go() { printf '%%s\\n' \"$TEST_GO_VERSION\"; }; ")
	if release {
		prefix += "GO_BIN=go; fail() { printf 'FAIL:%s\\n' \"$*\" >&2; exit 42; }; "
	} else {
		prefix += "command() { if [[ $1 == -v && $2 == go ]]; then return 0; else builtin command \"$@\"; fi; }; "
	}
	return prefix + block, floor
}

func TestBuildScriptsRequireStableGoFloor(t *testing.T) {
	root := ".."
	cases := []struct {
		name, path, start, end string
		release                bool
	}{
		{"installer", root + "/build.sh", "if ! command -v go", "\n\n# GCC", false},
		{"release", root + "/scripts/build-release.sh", "GO_VERSION=$(${GO_BIN} env GOVERSION)", "\n\nfor module", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script, floor := floorGuardScript(t, tc.path, tc.start, tc.end, tc.release)
			parts := strings.Split(strings.TrimPrefix(floor, "go"), ".")
			major, minor, patch := parts[0], parts[1], parts[2]
			versions := []struct {
				name, value string
				wantOK      bool
			}{
				{"current-floor", floor, true},
				{"lower-stable", fmt.Sprintf("go%s.%s.%d", major, minor, mustInt(t, patch)-1), false},
				{"same-floor-rc", floor + "rc1", false},
				{"same-floor-beta", floor + "beta1", false},
				{"future-floor-rc", fmt.Sprintf("go%s.%s.%drc1", major, minor, mustInt(t, patch)+1), false},
				{"future-floor-beta", fmt.Sprintf("go%s.%s.%dbeta1", major, minor, mustInt(t, patch)+1), false},
				{"devel", "devel go1.99", false},
				{"malformed", "go1.x.y", false},
				{"future-stable", fmt.Sprintf("go%s.%s.%d", major, minor, mustInt(t, patch)+1), true},
			}
			if patch == "0" {
				t.Skip("floor patch zero has no lower patch in this minor series")
			}
			for _, tc := range versions {
				t.Run(tc.name, func(t *testing.T) {
					cmd := exec.Command("bash", "-c", script)
					cmd.Env = append(cmd.Environ(), "TEST_GO_VERSION="+tc.value)
					output, err := cmd.CombinedOutput()
					gotOK := err == nil
					if gotOK != tc.wantOK {
						t.Fatalf("guard acceptance for %q = %v, want %v (err=%v, output=%s)\nscript:\n%s", tc.value, gotOK, tc.wantOK, err, output, script)
					}
				})
			}
		})
	}
}

func mustInt(t *testing.T, value string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(value, "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}
