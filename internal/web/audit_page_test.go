package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// idStr renders a JSON number (decoded as float64) as a stable string so two
// pages' IDs can be compared for overlap.
func idStr(v any) string {
	if f, ok := v.(float64); ok {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%v", v)
}

type auditPageEnv struct {
	Entries    []map[string]any `json:"entries"`
	NextCursor string           `json:"next_cursor"`
}

func (h *harness) getAuditPage(t *testing.T, tok, query string) auditPageEnv {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit"+query, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := h.do(req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit%s = %d, want 200", query, rec.Code)
	}
	var env auditPageEnv
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode audit page: %v", err)
	}
	return env
}

// TestAuditPagination verifies GET /api/v1/audit returns cursor-paginated
// pages: the first page carries a next_cursor, following it yields older,
// non-overlapping entries.
func TestAuditPagination(t *testing.T) {
	h := newHarness(t)
	tok := h.token("admin")

	// Seed 25 audit entries.
	for i := 0; i < 25; i++ {
		if err := h.svc.Store().Audit(context.Background(), "admin", "action", "", "", ""); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}

	page1 := h.getAuditPage(t, tok, "?limit=10")
	if len(page1.Entries) != 10 {
		t.Fatalf("first page entries = %d, want 10", len(page1.Entries))
	}
	if page1.NextCursor == "" {
		t.Fatal("first page should carry a next_cursor")
	}

	page2 := h.getAuditPage(t, tok, "?limit=10&cursor="+page1.NextCursor)
	if len(page2.Entries) != 10 {
		t.Fatalf("second page entries = %d, want 10", len(page2.Entries))
	}
	// No ID on page 2 may appear on page 1.
	firstIDs := map[string]bool{}
	for _, e := range page1.Entries {
		firstIDs[idStr(e["id"])] = true
	}
	for _, e := range page2.Entries {
		if firstIDs[idStr(e["id"])] {
			t.Fatalf("page 2 overlaps page 1 at id %v", e["id"])
		}
	}
}

// TestAuditFinalPageHasNoCursor verifies the last page reports an empty
// next_cursor so a client knows to stop.
func TestAuditFinalPageHasNoCursor(t *testing.T) {
	h := newHarness(t)
	tok := h.token("admin")

	for i := 0; i < 3; i++ {
		if err := h.svc.Store().Audit(context.Background(), "admin", "action", "", "", ""); err != nil {
			t.Fatalf("seed audit: %v", err)
		}
	}

	env := h.getAuditPage(t, tok, "?limit=100")
	if env.NextCursor != "" {
		t.Errorf("final page next_cursor = %q, want empty", env.NextCursor)
	}
}
