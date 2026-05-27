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

// Package auth holds narrow in-process registries the data plane consults
// at request time for Users, Groups, and RouteAssignments. Mirrors the
// shape of pkg/services/agents and pkg/services/virtualmcp: a read-only
// Registry interface, a Store interface that extends it with mutation,
// and an InMemory default. The split prevents request-path code from
// accidentally mutating cached state.
package auth

import (
	"errors"
	"sort"
	"sync"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// ErrInvalidEntry is returned by Upsert* when the projection is missing
// its ID — every registered entry is keyed by "<namespace>/<name>", and
// an empty ID would clobber the zero-key slot.
var ErrInvalidEntry = errors.New("auth: registered entry missing ID")

// RegisteredUser is the minimal projection of a User CR the data plane
// needs to authenticate and authorize requests. Built by UserReconciler;
// consumed by the §2.4 HTTP shim.
type RegisteredUser struct {
	ID           string
	Namespace    string
	Name         string
	DisplayName  string
	Email        string
	AuthProvider mcpv1alpha1.UserAuthProvider
	ExternalID   string
	// Groups names Group CRs (same namespace) this user belongs to. Stored
	// verbatim from User.Spec.Groups; the AssignmentReconciler unions both
	// sides of the User↔Group edge at subject-resolution time.
	Groups []string
}

// UserRegistry is the read side. HTTP handlers / dispatchers depend on
// this narrow type so they can't accidentally mutate cached state.
type UserRegistry interface {
	GetUser(id string) (*RegisteredUser, bool)
	GetUserByEmail(namespace, email string) (*RegisteredUser, bool)
	ListUsers() []*RegisteredUser
}

// UserStore extends UserRegistry with the mutation methods the
// reconciler needs. The split mirrors agents.AgentStore.
type UserStore interface {
	UserRegistry
	UpsertUser(user *RegisteredUser) error
	DeleteUser(id string) error
}

// InMemoryUserStore is the default UserStore: a map guarded by an
// RWMutex. Lookups return deep-enough copies so caller mutation can't
// poison the cache.
type InMemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*RegisteredUser
}

// NewInMemoryUserStore returns an empty in-memory user store.
func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[string]*RegisteredUser)}
}

// UpsertUser inserts or replaces the entry under user.ID. Replaces the
// existing entry wholesale — partial updates aren't a concern because
// the reconciler builds the projection from the CR each pass.
func (s *InMemoryUserStore) UpsertUser(user *RegisteredUser) error {
	if user == nil || user.ID == "" {
		return ErrInvalidEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = copyUser(user)
	return nil
}

// DeleteUser is idempotent — removing a missing ID is not an error.
func (s *InMemoryUserStore) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

// GetUser returns a copy of the entry under id, or (nil, false) if
// absent.
func (s *InMemoryUserStore) GetUser(id string) (*RegisteredUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	return copyUser(u), true
}

// GetUserByEmail walks the store looking for a matching (namespace,
// email) pair. Linear scan is acceptable for typical proxy user counts;
// if it ever becomes a hot path we can shadow an index.
func (s *InMemoryUserStore) GetUserByEmail(namespace, email string) (*RegisteredUser, bool) {
	if email == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Namespace == namespace && u.Email == email {
			return copyUser(u), true
		}
	}
	return nil, false
}

// ListUsers returns ID-sorted copies for deterministic output.
func (s *InMemoryUserStore) ListUsers() []*RegisteredUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, copyUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func copyUser(u *RegisteredUser) *RegisteredUser {
	if u == nil {
		return nil
	}
	c := *u
	if u.Groups != nil {
		c.Groups = append([]string(nil), u.Groups...)
	}
	return &c
}
