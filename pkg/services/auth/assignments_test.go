/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func TestInMemoryAssignmentStore_UpsertGetDelete(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	a := &RegisteredAssignment{
		ID: "ns/ra", Namespace: "ns", Name: "ra",
		Users: []string{"alice"}, Groups: []string{"admins"},
		Permissions: mcpv1alpha1.RouteAssignmentPermissionWrite,
		AutoSpawn:   true,
	}
	if err := s.UpsertAssignment(a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := s.GetAssignment("ns/ra")
	if !ok || got.Permissions != mcpv1alpha1.RouteAssignmentPermissionWrite || !got.AutoSpawn {
		t.Errorf("Get = %+v, want write+autospawn", got)
	}
	if err := s.DeleteAssignment("ns/ra"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.GetAssignment("ns/ra"); ok {
		t.Error("Get after delete: ok = true, want false")
	}
}

func TestInMemoryAssignmentStore_DeleteIdempotent(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	if err := s.DeleteAssignment("ns/missing"); err != nil {
		t.Errorf("delete missing: %v, want nil", err)
	}
}

func TestInMemoryAssignmentStore_UpsertInvalid(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	if err := s.UpsertAssignment(nil); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(nil) = %v, want ErrInvalidEntry", err)
	}
	if err := s.UpsertAssignment(&RegisteredAssignment{Name: "x"}); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(no-ID) = %v, want ErrInvalidEntry", err)
	}
}

func TestInMemoryAssignmentStore_ReplaceOnUpsert(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/ra", Users: []string{"a", "b"}, Groups: []string{"g1"}})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/ra", Users: []string{"c"}})
	got, _ := s.GetAssignment("ns/ra")
	if len(got.Users) != 1 || got.Users[0] != "c" {
		t.Errorf("Users = %v, want [c]", got.Users)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want empty (wholesale replace)", got.Groups)
	}
}

func TestInMemoryAssignmentStore_ListByNamespace(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "a/r1", Namespace: "a"})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "a/r2", Namespace: "a"})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "b/r1", Namespace: "b"})
	got := s.ListByNamespace("a")
	if len(got) != 2 || got[0].ID != "a/r1" || got[1].ID != "a/r2" {
		t.Errorf("ListByNamespace(a) = %v, want [a/r1, a/r2]", ids(got))
	}
	if len(s.ListByNamespace("c")) != 0 {
		t.Error("ListByNamespace(c) returned non-empty")
	}
}

func TestInMemoryAssignmentStore_ListAssignmentsSorted(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/c"})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/a"})
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/b"})
	got := s.ListAssignments()
	want := []string{"ns/a", "ns/b", "ns/c"}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("[%d].ID = %q, want %q", i, got[i].ID, w)
		}
	}
}

func TestInMemoryAssignmentStore_CopyOnRead(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	_ = s.UpsertAssignment(&RegisteredAssignment{ID: "ns/r", Users: []string{"a"}, Groups: []string{"g"}})
	got, _ := s.GetAssignment("ns/r")
	got.Users[0] = "tampered"
	got.Groups[0] = "tampered"
	fresh, _ := s.GetAssignment("ns/r")
	if fresh.Users[0] != "a" || fresh.Groups[0] != "g" {
		t.Errorf("cache poisoned: %+v", fresh)
	}
}

func TestInMemoryAssignmentStore_Concurrent(t *testing.T) {
	s := NewInMemoryAssignmentStore()
	const goroutines = 64
	const iter = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				id := fmt.Sprintf("ns/r-%d-%d", g, i%8)
				_ = s.UpsertAssignment(&RegisteredAssignment{ID: id, Namespace: "ns", Name: id})
				_, _ = s.GetAssignment(id)
				_ = s.ListAssignments()
				_ = s.ListByNamespace("ns")
				if i%4 == 0 {
					_ = s.DeleteAssignment(id)
				}
			}
		}(g)
	}
	wg.Wait()
}

func ids(as []*RegisteredAssignment) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}
