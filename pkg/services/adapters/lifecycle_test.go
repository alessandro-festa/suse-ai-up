package services

import (
	"context"
	"testing"
	"time"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services"
)

// newTestAdapter returns a stored adapter created by `owner` with the given id.
func newTestAdapter(t *testing.T, store clients.AdapterResourceStore, owner, id string) models.AdapterResource {
	t.Helper()
	adapter := models.AdapterResource{
		AdapterData: models.AdapterData{
			Name:           id,
			ConnectionType: models.ConnectionTypeRemoteHttp,
			Status:         models.AdapterLifecycleStatusReady,
		},
		ID:            id,
		CreatedBy:     owner,
		CreatedAt:     time.Now(),
		LastUpdatedAt: time.Now(),
	}
	if err := store.Create(context.Background(), adapter); err != nil {
		t.Fatalf("seed adapter %q: %v", id, err)
	}
	return adapter
}

func TestGetAdapter_OwnerSucceeds(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")

	got, err := svc.GetAdapter(context.Background(), "alice", "a1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "a1" {
		t.Errorf("got id %q, want %q", got.ID, "a1")
	}
}

func TestGetAdapter_NonOwnerDeniedWhenNoGroupService(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")

	_, err := svc.GetAdapter(context.Background(), "bob", "a1", nil)
	if err == nil {
		t.Fatal("expected denial when non-owner reads without group service")
	}
}

func TestGetAdapter_AdminCanRead(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	ug := services.NewUserGroupService(userStore, groupStore)
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")

	// dev-admin short-circuits CanManageGroups.
	got, err := svc.GetAdapter(context.Background(), "dev-admin", "a1", ug)
	if err != nil {
		t.Fatalf("expected admin to read: %v", err)
	}
	if got.ID != "a1" {
		t.Errorf("got id %q, want %q", got.ID, "a1")
	}
}

func TestGetAdapter_MissingAdapterReturnsError(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)

	if _, err := svc.GetAdapter(context.Background(), "alice", "missing", nil); err == nil {
		t.Fatal("expected error for missing adapter")
	}
}

func TestListAdapters_OwnerSeesOwnOnly(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")
	newTestAdapter(t, store, "alice", "a2")
	newTestAdapter(t, store, "bob", "b1")

	list, err := svc.ListAdapters(context.Background(), "alice", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("alice should see 2 adapters, got %d", len(list))
	}
	for _, a := range list {
		if a.CreatedBy != "alice" {
			t.Errorf("alice should not see %q (owner %q)", a.ID, a.CreatedBy)
		}
	}
}

func TestListAdapters_AdminSeesAll(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	userStore := clients.NewInMemoryUserStore()
	groupStore := clients.NewInMemoryGroupStore()
	ug := services.NewUserGroupService(userStore, groupStore)
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")
	newTestAdapter(t, store, "bob", "b1")

	list, err := svc.ListAdapters(context.Background(), "dev-admin", ug)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("admin should see all 2, got %d", len(list))
	}
}

func TestUpdateAdapter_OwnerUpdates(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	adapter := newTestAdapter(t, store, "alice", "a1")

	adapter.Description = "updated by alice"
	if err := svc.UpdateAdapter(context.Background(), "alice", adapter); err != nil {
		t.Fatalf("owner update should succeed: %v", err)
	}
	got, _ := store.Get(context.Background(), "a1")
	if got.Description != "updated by alice" {
		t.Errorf("description not persisted, got %q", got.Description)
	}
}

func TestUpdateAdapter_NonOwnerDenied(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	adapter := newTestAdapter(t, store, "alice", "a1")

	adapter.Description = "hijack"
	if err := svc.UpdateAdapter(context.Background(), "bob", adapter); err == nil {
		t.Fatal("expected non-owner update to fail")
	}
}

func TestUpdateAdapter_MissingAdapterReturnsError(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)

	missing := models.AdapterResource{ID: "ghost", CreatedBy: "alice"}
	if err := svc.UpdateAdapter(context.Background(), "alice", missing); err == nil {
		t.Fatal("expected update to fail for missing adapter")
	}
}

func TestDeleteAdapter_RemovesAdapter(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	newTestAdapter(t, store, "alice", "a1")

	if err := svc.DeleteAdapter(context.Background(), "alice", "a1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(context.Background(), "a1"); err == nil {
		t.Fatal("expected adapter to be gone from store")
	}
}

func TestDeleteAdapter_MissingReturnsError(t *testing.T) {
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)

	if err := svc.DeleteAdapter(context.Background(), "alice", "ghost"); err == nil {
		t.Fatal("expected delete-missing to error from store")
	}
}

func TestDeleteAdapter_SidecarWithoutManagerStillDeletes(t *testing.T) {
	// An adapter flagged for sidecar cleanup but with no SidecarManager wired
	// should warn-and-continue, not refuse to delete the adapter row.
	store := clients.NewInMemoryAdapterStore()
	svc := NewAdapterService(store, clients.NewInMemoryMCPServerStore(), nil)
	adapter := models.AdapterResource{
		AdapterData: models.AdapterData{
			Name:           "sidecar-a",
			ConnectionType: models.ConnectionTypeStreamableHttp,
			SidecarConfig:  &models.SidecarConfig{CommandType: "docker", Command: "docker"},
		},
		ID:        "sidecar-a",
		CreatedBy: "alice",
		CreatedAt: time.Now(),
	}
	if err := store.Create(context.Background(), adapter); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.DeleteAdapter(context.Background(), "alice", "sidecar-a"); err != nil {
		t.Fatalf("delete should succeed even without sidecar manager: %v", err)
	}
	if _, err := store.Get(context.Background(), "sidecar-a"); err == nil {
		t.Fatal("adapter should have been deleted")
	}
}
