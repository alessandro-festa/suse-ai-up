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

func TestInMemoryUserStore_UpsertGetDelete(t *testing.T) {
	s := NewInMemoryUserStore()
	u := &RegisteredUser{ID: "ns/alice", Namespace: "ns", Name: "alice", Email: "a@example.com"}
	if err := s.UpsertUser(u); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := s.GetUser("ns/alice")
	if !ok || got.Email != "a@example.com" {
		t.Errorf("Get = %+v, %v; want alice@example.com, true", got, ok)
	}
	if err := s.DeleteUser("ns/alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.GetUser("ns/alice"); ok {
		t.Error("Get after delete: ok = true, want false")
	}
}

func TestInMemoryUserStore_DeleteIdempotent(t *testing.T) {
	s := NewInMemoryUserStore()
	if err := s.DeleteUser("ns/missing"); err != nil {
		t.Errorf("delete missing: %v, want nil", err)
	}
}

func TestInMemoryUserStore_UpsertInvalid(t *testing.T) {
	s := NewInMemoryUserStore()
	if err := s.UpsertUser(nil); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(nil) = %v, want ErrInvalidEntry", err)
	}
	if err := s.UpsertUser(&RegisteredUser{Namespace: "ns", Name: "x"}); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("upsert(no-ID) = %v, want ErrInvalidEntry", err)
	}
}

func TestInMemoryUserStore_ReplaceOnUpsert(t *testing.T) {
	s := NewInMemoryUserStore()
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/alice", Email: "old@example.com", Groups: []string{"g1"}})
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/alice", Email: "new@example.com"})
	got, _ := s.GetUser("ns/alice")
	if got.Email != "new@example.com" {
		t.Errorf("Email = %q, want new@example.com", got.Email)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want empty (wholesale replace)", got.Groups)
	}
}

func TestInMemoryUserStore_GetUserByEmail(t *testing.T) {
	s := NewInMemoryUserStore()
	_ = s.UpsertUser(&RegisteredUser{ID: "a/alice", Namespace: "a", Email: "alice@x"})
	_ = s.UpsertUser(&RegisteredUser{ID: "b/alice", Namespace: "b", Email: "alice@x"})
	got, ok := s.GetUserByEmail("a", "alice@x")
	if !ok || got.Namespace != "a" {
		t.Errorf("GetUserByEmail(a) = %+v, want namespace=a", got)
	}
	if _, ok := s.GetUserByEmail("a", ""); ok {
		t.Error("GetUserByEmail(empty email) returned ok=true")
	}
	if _, ok := s.GetUserByEmail("c", "alice@x"); ok {
		t.Error("GetUserByEmail(wrong ns) returned ok=true")
	}
}

func TestInMemoryUserStore_ListUsersSorted(t *testing.T) {
	s := NewInMemoryUserStore()
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/charlie"})
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/alice"})
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/bob"})
	got := s.ListUsers()
	want := []string{"ns/alice", "ns/bob", "ns/charlie"}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("[%d].ID = %q, want %q", i, got[i].ID, w)
		}
	}
}

func TestInMemoryUserStore_CopyOnRead(t *testing.T) {
	s := NewInMemoryUserStore()
	_ = s.UpsertUser(&RegisteredUser{ID: "ns/alice", Groups: []string{"g1"}})
	got, _ := s.GetUser("ns/alice")
	got.Groups[0] = "tampered"
	got.Email = "tampered@example.com"
	fresh, _ := s.GetUser("ns/alice")
	if fresh.Groups[0] != "g1" || fresh.Email != "" {
		t.Errorf("cache poisoned: %+v", fresh)
	}
}

func TestInMemoryUserStore_Concurrent(t *testing.T) {
	s := NewInMemoryUserStore()
	const goroutines = 64
	const iter = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				id := fmt.Sprintf("ns/u-%d-%d", g, i%8)
				_ = s.UpsertUser(&RegisteredUser{ID: id, Namespace: "ns", Name: id})
				_, _ = s.GetUser(id)
				_ = s.ListUsers()
				if i%4 == 0 {
					_ = s.DeleteUser(id)
				}
			}
		}(g)
	}
	wg.Wait()
}
