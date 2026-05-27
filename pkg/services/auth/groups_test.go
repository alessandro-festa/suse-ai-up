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
)

func TestInMemoryGroupStore_UpsertGetDelete(t *testing.T) {
	s := NewInMemoryGroupStore()
	g := &RegisteredGroup{ID: "ns/admins", Namespace: "ns", Name: "admins", Members: []string{"alice"}, Permissions: []string{"server:read"}}
	if err := s.UpsertGroup(g); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := s.GetGroup("ns/admins")
	if !ok || len(got.Members) != 1 || got.Members[0] != "alice" {
		t.Errorf("Get = %+v, want members=[alice]", got)
	}
	if err := s.DeleteGroup("ns/admins"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.GetGroup("ns/admins"); ok {
		t.Error("Get after delete: ok = true, want false")
	}
}

func TestInMemoryGroupStore_DeleteIdempotent(t *testing.T) {
	s := NewInMemoryGroupStore()
	if err := s.DeleteGroup("ns/missing"); err != nil {
		t.Errorf("delete missing: %v, want nil", err)
	}
}

func TestInMemoryGroupStore_UpsertInvalid(t *testing.T) {
	s := NewInMemoryGroupStore()
	if err := s.UpsertGroup(nil); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(nil) = %v, want ErrInvalidEntry", err)
	}
	if err := s.UpsertGroup(&RegisteredGroup{Name: "x"}); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(no-ID) = %v, want ErrInvalidEntry", err)
	}
}

func TestInMemoryGroupStore_ReplaceOnUpsert(t *testing.T) {
	s := NewInMemoryGroupStore()
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/g", Members: []string{"a", "b"}, Permissions: []string{"x"}})
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/g", Members: []string{"c"}})
	got, _ := s.GetGroup("ns/g")
	if len(got.Members) != 1 || got.Members[0] != "c" {
		t.Errorf("Members = %v, want [c]", got.Members)
	}
	if len(got.Permissions) != 0 {
		t.Errorf("Permissions = %v, want empty (wholesale replace)", got.Permissions)
	}
}

func TestInMemoryGroupStore_ListGroupsSorted(t *testing.T) {
	s := NewInMemoryGroupStore()
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/c"})
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/a"})
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/b"})
	got := s.ListGroups()
	want := []string{"ns/a", "ns/b", "ns/c"}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("[%d].ID = %q, want %q", i, got[i].ID, w)
		}
	}
}

func TestInMemoryGroupStore_CopyOnRead(t *testing.T) {
	s := NewInMemoryGroupStore()
	_ = s.UpsertGroup(&RegisteredGroup{ID: "ns/g", Members: []string{"alice"}, Permissions: []string{"x"}})
	got, _ := s.GetGroup("ns/g")
	got.Members[0] = "tampered"
	got.Permissions[0] = "tampered"
	fresh, _ := s.GetGroup("ns/g")
	if fresh.Members[0] != "alice" || fresh.Permissions[0] != "x" {
		t.Errorf("cache poisoned: %+v", fresh)
	}
}

func TestInMemoryGroupStore_Concurrent(t *testing.T) {
	s := NewInMemoryGroupStore()
	const goroutines = 64
	const iter = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				id := fmt.Sprintf("ns/g-%d-%d", g, i%8)
				_ = s.UpsertGroup(&RegisteredGroup{ID: id, Name: id})
				_, _ = s.GetGroup(id)
				_ = s.ListGroups()
				if i%4 == 0 {
					_ = s.DeleteGroup(id)
				}
			}
		}(g)
	}
	wg.Wait()
}
