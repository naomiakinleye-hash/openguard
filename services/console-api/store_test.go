package consoleapi

import (
	"fmt"
	"testing"
)

func TestEventStore_AddAndList(t *testing.T) {
	store := NewEventStore()

	// Add 5 events.
	for i := 0; i < 5; i++ {
		store.Add(map[string]interface{}{
			"id":    fmt.Sprintf("evt-%d", i),
			"index": i,
		})
	}

	// List first page of 3.
	items, total := store.List(1, 3)
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items on page 1, got %d", len(items))
	}

	// List second page.
	items, total = store.List(2, 3)
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items on page 2, got %d", len(items))
	}

	// Page beyond end returns empty slice.
	items, total = store.List(10, 3)
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items on page 10, got %d", len(items))
	}
}

func TestEventStore_Get(t *testing.T) {
	store := NewEventStore()
	store.Add(map[string]interface{}{"id": "evt-abc", "value": "test"})

	evt, ok := store.Get("evt-abc")
	if !ok {
		t.Fatal("expected to find event evt-abc")
	}
	if evt["id"] != "evt-abc" {
		t.Errorf("expected id=evt-abc, got %v", evt["id"])
	}

	_, ok = store.Get("nonexistent")
	if ok {
		t.Fatal("expected not-found for nonexistent id")
	}
}

func TestEventStore_AutoAssignID(t *testing.T) {
	store := NewEventStore()
	evt := map[string]interface{}{"value": "no-id"}
	store.Add(evt)

	id, ok := evt["id"].(string)
	if !ok || id == "" {
		t.Fatal("expected auto-assigned id")
	}

	got, found := store.Get(id)
	if !found {
		t.Fatalf("expected to find event by auto-assigned id %s", id)
	}
	if got["value"] != "no-id" {
		t.Errorf("expected value=no-id, got %v", got["value"])
	}
}

func TestIncidentStore_UpdateStatus(t *testing.T) {
	store := NewIncidentStore()
	store.Add(&Incident{ID: "inc-1", Status: "pending"})

	if ok := store.UpdateStatus("inc-1", "approved"); !ok {
		t.Fatal("expected UpdateStatus to return true for existing incident")
	}

	inc, ok := store.Get("inc-1")
	if !ok {
		t.Fatal("expected to find incident inc-1")
	}
	if inc.Status != "approved" {
		t.Errorf("expected status=approved, got %s", inc.Status)
	}

	// Non-existent ID.
	if ok := store.UpdateStatus("missing", "approved"); ok {
		t.Fatal("expected UpdateStatus to return false for missing incident")
	}
}

func TestIncidentStore_ListPagination(t *testing.T) {
	store := NewIncidentStore()
	for i := 0; i < 7; i++ {
		store.Add(&Incident{ID: fmt.Sprintf("inc-%d", i), Status: "pending"})
	}

	items, total := store.List(1, 5)
	if total != 7 {
		t.Fatalf("expected total=7, got %d", total)
	}
	if len(items) != 5 {
		t.Fatalf("expected 5 items on page 1, got %d", len(items))
	}

	items, _ = store.List(2, 5)
	if len(items) != 2 {
		t.Fatalf("expected 2 items on page 2, got %d", len(items))
	}
}

func TestIncidentStore_Get_NotFound(t *testing.T) {
	store := NewIncidentStore()

	_, ok := store.Get("missing")
	if ok {
		t.Fatal("expected not-found for empty store")
	}
}
