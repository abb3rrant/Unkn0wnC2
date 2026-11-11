package main

import (
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestSelfEditPageOmitsNonAdminRole(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js required for executable form regression")
	}
	if out, err := exec.Command(node, "testdata/self_edit.cjs").CombinedOutput(); err != nil {
		t.Fatalf("self-edit form: %v\n%s", err, out)
	}
}

func TestSelfEditWithoutRolePreservesAuthorization(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("fixture-viewer", "original-name", "fixture-password", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer(db, Config{})
	update := func(body string) int {
		req := httptest.NewRequest("PUT", "/api/operators/fixture-viewer", strings.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"id": "fixture-viewer"})
		req.Header.Set("X-Operator-ID", "fixture-viewer")
		req.Header.Set("X-Operator-Role", "viewer")
		rec := httptest.NewRecorder()
		api.handleUpdateOperator(rec, req)
		return rec.Code
	}
	if got := update(`{"username":"updated-name","email":"fixture@example.invalid"}`); got != http.StatusOK {
		t.Fatalf("permitted edit status=%d", got)
	}
	if got := update(`{"role":"admin"}`); got != http.StatusForbidden {
		t.Fatalf("privilege escalation status=%d", got)
	}
	account, err := db.GetOperator("fixture-viewer")
	if err != nil {
		t.Fatal(err)
	}
	if account.Role != "viewer" || account.Username != "updated-name" || account.Email != "fixture@example.invalid" {
		t.Fatalf("unexpected account state: role=%s username=%s email=%s", account.Role, account.Username, account.Email)
	}
}
