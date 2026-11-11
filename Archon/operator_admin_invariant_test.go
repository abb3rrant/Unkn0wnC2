package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
)

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
