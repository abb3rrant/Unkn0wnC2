//go:build !windows || !amd64

package main

import "fmt"

// BOFs are amd64 COFF objects that execute in-process, so only a windows/amd64
// build can load them. Every other platform reports the reason instead of
// pretending the task failed for some other cause.
func executeBOF(request bofRequest) (string, error) {
	return "", fmt.Errorf("BOF execution needs a windows/amd64 beacon; this build cannot load %s", request.Name)
}
