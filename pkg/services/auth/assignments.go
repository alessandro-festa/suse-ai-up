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

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// RegisteredAssignment is the projection of a RouteAssignment CR the
// data plane consults at request time. Holds the raw declared edges
// (Users, Groups) — subject expansion lives in the §2.4 dispatcher so
// it can react to live Group state without depending on a cached
// snapshot here.
type RegisteredAssignment struct {
	ID          string
	Namespace   string
	Name        string
	Users       []string
	Groups      []string
	Permissions mcpv1alpha1.RouteAssignmentPermission
	AutoSpawn   bool
	// MCPServerRef, when non-empty, names an MCPServer in the same
	// namespace that this assignment auto-applies to. Populated from
	// RouteAssignmentSpec.MCPServerRef.Name by the reconciler; consumed
	// by the proxy hot path's union evaluation (P2.5/#29) and by the
	// HTTP shim's server-scoped list endpoint.
	MCPServerRef string
}

// AssignmentRegistry is the read side.
type AssignmentRegistry interface {
	GetAssignment(id string) (*RegisteredAssignment, bool)
	ListAssignments() []*RegisteredAssignment
	ListByNamespace(namespace string) []*RegisteredAssignment
	// ListByMCPServerRef returns the assignments in namespace whose
	// MCPServerRef matches name. Empty slice when no matches. The
	// proxy hot path uses this to compute the effective ACL set as
	// the union of explicit Adapter.Spec.RouteAssignmentRefs and
	// server-scoped assignments.
	ListByMCPServerRef(namespace, name string) []*RegisteredAssignment
}

// AssignmentStore extends AssignmentRegistry with mutation.
type AssignmentStore interface {
	AssignmentRegistry
	UpsertAssignment(asg *RegisteredAssignment) error
	DeleteAssignment(id string) error
}

// InMemoryAssignmentStore is the default AssignmentStore.
type InMemoryAssignmentStore struct {
	mu          sync.RWMutex
	assignments map[string]*RegisteredAssignment
}

// NewInMemoryAssignmentStore returns an empty in-memory assignment store.
func NewInMemoryAssignmentStore() *InMemoryAssignmentStore {
	return &InMemoryAssignmentStore{assignments: make(map[string]*RegisteredAssignment)}
}

func (s *InMemoryAssignmentStore) UpsertAssignment(asg *RegisteredAssignment) error {
	if asg == nil || asg.ID == "" {
		return ErrInvalidEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assignments[asg.ID] = copyAssignment(asg)
	return nil
}

func (s *InMemoryAssignmentStore) DeleteAssignment(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.assignments, id)
	return nil
}

func (s *InMemoryAssignmentStore) GetAssignment(id string) (*RegisteredAssignment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assignments[id]
	if !ok {
		return nil, false
	}
	return copyAssignment(a), true
}

func (s *InMemoryAssignmentStore) ListAssignments() []*RegisteredAssignment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAssignment, 0, len(s.assignments))
	for _, a := range s.assignments {
		out = append(out, copyAssignment(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *InMemoryAssignmentStore) ListByNamespace(namespace string) []*RegisteredAssignment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAssignment, 0)
	for _, a := range s.assignments {
		if a.Namespace == namespace {
			out = append(out, copyAssignment(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *InMemoryAssignmentStore) ListByMCPServerRef(namespace, name string) []*RegisteredAssignment {
	// Guard the empty-name case so a caller with an unset MCPServerRef
	// (e.g. a SidecarConfig-only Adapter) does not accidentally collect
	// every assignment whose MCPServerRef happens to also be unset.
	if name == "" {
		return []*RegisteredAssignment{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAssignment, 0)
	for _, a := range s.assignments {
		if a.Namespace == namespace && a.MCPServerRef == name {
			out = append(out, copyAssignment(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func copyAssignment(a *RegisteredAssignment) *RegisteredAssignment {
	if a == nil {
		return nil
	}
	c := *a
	if a.Users != nil {
		c.Users = append([]string(nil), a.Users...)
	}
	if a.Groups != nil {
		c.Groups = append([]string(nil), a.Groups...)
	}
	return &c
}
