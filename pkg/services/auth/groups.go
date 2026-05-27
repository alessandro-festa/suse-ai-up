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
	"sort"
	"sync"
)

// RegisteredGroup is the minimal projection of a Group CR the data
// plane needs to expand RouteAssignments at request time.
type RegisteredGroup struct {
	ID          string
	Namespace   string
	Name        string
	DisplayName string
	// Members names User CRs (same namespace) declared by this group. The
	// AssignmentReconciler unions this with the reverse User.Spec.Groups
	// edge when resolving subjects.
	Members []string
	// Permissions are free-form strings evaluated by request-time code
	// (matches Group.Spec.Permissions; reserved for the §2.4 evaluator).
	Permissions []string
}

// GroupRegistry is the read side, used by request-path code.
type GroupRegistry interface {
	GetGroup(id string) (*RegisteredGroup, bool)
	ListGroups() []*RegisteredGroup
}

// GroupStore extends GroupRegistry with the mutation methods the
// reconciler needs.
type GroupStore interface {
	GroupRegistry
	UpsertGroup(group *RegisteredGroup) error
	DeleteGroup(id string) error
}

// InMemoryGroupStore is the default GroupStore.
type InMemoryGroupStore struct {
	mu     sync.RWMutex
	groups map[string]*RegisteredGroup
}

// NewInMemoryGroupStore returns an empty in-memory group store.
func NewInMemoryGroupStore() *InMemoryGroupStore {
	return &InMemoryGroupStore{groups: make(map[string]*RegisteredGroup)}
}

func (s *InMemoryGroupStore) UpsertGroup(group *RegisteredGroup) error {
	if group == nil || group.ID == "" {
		return ErrInvalidEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = copyGroup(group)
	return nil
}

func (s *InMemoryGroupStore) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, id)
	return nil
}

func (s *InMemoryGroupStore) GetGroup(id string) (*RegisteredGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok {
		return nil, false
	}
	return copyGroup(g), true
}

func (s *InMemoryGroupStore) ListGroups() []*RegisteredGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredGroup, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, copyGroup(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func copyGroup(g *RegisteredGroup) *RegisteredGroup {
	if g == nil {
		return nil
	}
	c := *g
	if g.Members != nil {
		c.Members = append([]string(nil), g.Members...)
	}
	if g.Permissions != nil {
		c.Permissions = append([]string(nil), g.Permissions...)
	}
	return &c
}
