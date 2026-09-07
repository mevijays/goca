package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestListAuditPagePagination(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "audit-page.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Seed 25 audit entries with distinct, ordered actions.
	for i := 0; i < 25; i++ {
		if err := st.Audit(ctx, "admin", "action", string(rune('a'+i)), "", ""); err != nil {
			t.Fatalf("Audit %d: %v", i, err)
		}
	}

	// First page: 10 newest, IDs descending.
	page1, err := st.ListAuditPage(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListAuditPage first: %v", err)
	}
	if len(page1) != 10 {
		t.Fatalf("first page len = %d, want 10", len(page1))
	}
	for i := 1; i < len(page1); i++ {
		if page1[i-1].ID <= page1[i].ID {
			t.Fatalf("page not in descending ID order: %d then %d", page1[i-1].ID, page1[i].ID)
		}
	}

	// Second page: continue from the smallest ID on page 1.
	cursor := page1[len(page1)-1].ID
	page2, err := st.ListAuditPage(ctx, cursor, 10)
	if err != nil {
		t.Fatalf("ListAuditPage second: %v", err)
	}
	if len(page2) != 10 {
		t.Fatalf("second page len = %d, want 10", len(page2))
	}
	// No overlap with page 1.
	for _, e := range page2 {
		if e.ID >= cursor {
			t.Fatalf("second page leaked an ID >= cursor: %d", e.ID)
		}
	}

	// Third page: the remaining 5.
	cursor = page2[len(page2)-1].ID
	page3, err := st.ListAuditPage(ctx, cursor, 10)
	if err != nil {
		t.Fatalf("ListAuditPage third: %v", err)
	}
	if len(page3) != 5 {
		t.Fatalf("third page len = %d, want 5", len(page3))
	}

	// Total across pages is 25, all distinct.
	seen := map[int64]bool{}
	for _, p := range [][]*AuditEntry{page1, page2, page3} {
		for _, e := range p {
			if seen[e.ID] {
				t.Fatalf("duplicate ID across pages: %d", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 25 {
		t.Fatalf("total distinct entries = %d, want 25", len(seen))
	}
}

func TestListAuditPageLimitCap(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "audit-cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	for i := 0; i < 5; i++ {
		if err := st.Audit(ctx, "admin", "action", "", "", ""); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}
	// Asking for more than the 5 available returns all 5, not an error.
	got, err := st.ListAuditPage(ctx, 0, 1000)
	if err != nil {
		t.Fatalf("ListAuditPage: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5", len(got))
	}
}
