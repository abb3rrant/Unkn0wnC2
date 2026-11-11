package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
)

type rowsAffectedErrorResult struct{ err error }

func (r rowsAffectedErrorResult) LastInsertId() (int64, error) { return 0, nil }
func (r rowsAffectedErrorResult) RowsAffected() (int64, error) { return 0, r.err }

func TestAdminMutationRowsAffectedErrorFailsClosed(t *testing.T) {
	want := errors.New("driver cannot report affected rows")
	if _, err := adminMutationRowsAffected(rowsAffectedErrorResult{err: want}); !errors.Is(err, want) {
		t.Fatalf("adminMutationRowsAffected error = %v, want wrapped %v", err, want)
	}
}

func TestOperatorMutationsReturnExplicitMissingRowErrors(t *testing.T) {
	db := newTestProfileDB(t)
	mutations := []struct {
		name string
		call func() error
	}{
		{"update", func() error { return db.UpdateOperator("missing", "renamed", "", "") }},
		{"disable", func() error { return db.SetOperatorActive("missing", false) }},
		{"delete", func() error { return db.DeleteOperator("missing") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if err := mutation.call(); err == nil || errors.Is(err, ErrLastActiveAdmin) {
				t.Fatalf("mutation error = %v, want explicit missing-row error", err)
			}
		})
	}
}

var _ sql.Result = rowsAffectedErrorResult{}

func TestUpdateOperatorRejectsDemotingLastActiveAdmin(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("admin-1", "admin", "test-password", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateOperator("admin-1", "", "viewer", ""); err == nil || !strings.Contains(err.Error(), "last active administrator") {
		t.Fatalf("UpdateOperator error = %v, want ErrLastActiveAdmin", err)
	}
	op, err := db.GetOperator("admin-1")
	if err != nil || op.Role != "admin" || !op.IsActive {
		t.Fatalf("operator after rejected demotion = %+v, err %v", op, err)
	}
}

func TestUpdateOperatorAllowsDemotionWhenAnotherActiveAdminExists(t *testing.T) {
	db := newTestProfileDB(t)
	for _, id := range []string{"admin-1", "admin-2"} {
		if err := db.CreateOperator(id, id, "test-password", "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpdateOperator("admin-1", "", "operator", ""); err != nil {
		t.Fatalf("demotion with another active admin: %v", err)
	}
}

func TestSetOperatorActiveRejectsDisablingLastActiveAdmin(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("admin-1", "admin", "test-password", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.SetOperatorActive("admin-1", false); err == nil || !strings.Contains(err.Error(), "last active administrator") {
		t.Fatalf("SetOperatorActive error = %v, want ErrLastActiveAdmin", err)
	}
}

func TestDeleteOperatorRejectsDeletingLastActiveAdmin(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("admin-1", "admin", "test-password", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteOperator("admin-1"); err == nil || !strings.Contains(err.Error(), "last active administrator") {
		t.Fatalf("DeleteOperator error = %v, want ErrLastActiveAdmin", err)
	}
}

func TestConcurrentActiveAdminRemovalsPreserveOne(t *testing.T) {
	db := newTestProfileDB(t)
	for _, id := range []string{"admin-1", "admin-2"} {
		if err := db.CreateOperator(id, id, "test-password", "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"admin-1", "admin-2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			results <- db.UpdateOperator(id, "", "viewer", "")
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case err != nil && strings.Contains(err.Error(), "last active administrator"):
			rejected++
		default:
			t.Fatalf("unexpected concurrent update error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejections=%d, want one each", succeeded, rejected)
	}
	var activeAdmins int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM operators WHERE role='admin' AND is_active=1`).Scan(&activeAdmins); err != nil {
		t.Fatal(err)
	}
	if activeAdmins != 1 {
		t.Fatalf("active admins=%d, want 1", activeAdmins)
	}
}

func TestConcurrentMixedAdminRemovalsAcrossDBHandles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  func(*MasterDatabase, string) error
		second func(*MasterDatabase, string) error
	}{
		{"disable-delete", func(db *MasterDatabase, id string) error { return db.SetOperatorActive(id, false) }, func(db *MasterDatabase, id string) error { return db.DeleteOperator(id) }},
		{"demote-disable", func(db *MasterDatabase, id string) error { return db.UpdateOperator(id, "", "viewer", "") }, func(db *MasterDatabase, id string) error { return db.SetOperatorActive(id, false) }},
		{"demote-delete", func(db *MasterDatabase, id string) error { return db.UpdateOperator(id, "", "viewer", "") }, func(db *MasterDatabase, id string) error { return db.DeleteOperator(id) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "operators.db")
			db1, err := NewMasterDatabase(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db1.Close()
			db2, err := NewMasterDatabase(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db2.Close()
			for _, id := range []string{"admin-1", "admin-2"} {
				if err := db1.CreateOperator(id, id, "test-password", "admin", ""); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			go func() { <-start; results <- tc.first(db1, "admin-1") }()
			go func() { <-start; results <- tc.second(db2, "admin-2") }()
			close(start)
			var succeeded, rejected int
			for range 2 {
				err := <-results
				if err == nil {
					succeeded++
				} else if errors.Is(err, ErrLastActiveAdmin) {
					rejected++
				} else {
					t.Fatalf("unexpected mutation error: %v", err)
				}
			}
			if succeeded != 1 || rejected != 1 {
				t.Fatalf("successes=%d rejections=%d, want one each", succeeded, rejected)
			}
			var activeAdmins int
			if err := db1.db.QueryRow(`SELECT COUNT(*) FROM operators WHERE role='admin' AND is_active=1`).Scan(&activeAdmins); err != nil {
				t.Fatal(err)
			}
			if activeAdmins != 1 {
				t.Fatalf("active admins=%d, want 1", activeAdmins)
			}
		})
	}
}

func TestAdminRemovalIgnoresInactiveAdminAndNonAdminRows(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("admin-1", "admin1", "test-password", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOperator("admin-2", "admin2", "test-password", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.SetOperatorActive("admin-2", false); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOperator("viewer", "viewer", "test-password", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateOperator("viewer", "viewer-renamed", "operator", ""); err != nil {
		t.Fatalf("ordinary role edit: %v", err)
	}
	if err := db.DeleteOperator("admin-1"); err == nil || !strings.Contains(err.Error(), "last active administrator") {
		t.Fatalf("delete with only inactive admin remaining = %v, want ErrLastActiveAdmin", err)
	}
}

func TestOperatorAdminInvariantHandlersReturnBadRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		handler func(*APIServer, http.ResponseWriter, *http.Request)
	}{
		{name: "role", body: `{"role":"viewer"}`, handler: (*APIServer).handleUpdateOperator},
		{name: "status", body: `{"active":false}`, handler: (*APIServer).handleToggleOperatorStatus},
		{name: "delete", handler: (*APIServer).handleDeleteOperator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestProfileDB(t)
			if err := db.CreateOperator("last-admin", "last-admin", "test-password", "admin", ""); err != nil {
				t.Fatal(err)
			}
			api := NewAPIServer(db, Config{})
			req := httptest.NewRequest(http.MethodPost, "/operators/last-admin", strings.NewReader(tc.body))
			req = mux.SetURLVars(req, map[string]string{"id": "last-admin"})
			req.Header.Set("X-Operator-ID", "another-admin")
			req.Header.Set("X-Operator-Role", "admin")
			recorder := httptest.NewRecorder()
			tc.handler(api, recorder, req)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "last active administrator") {
				t.Fatalf("response = %d %q, want 400 explaining last active administrator", recorder.Code, recorder.Body.String())
			}
		})
	}
}
