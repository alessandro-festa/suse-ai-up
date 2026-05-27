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

package agents

import (
	"errors"
	"sort"
	"sync"

	v1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

// ToolRef is one entry from Agent.Spec.Tools, flattened for the store.
// Exactly one of AdapterName / VirtualMCPRouteName is set.
type ToolRef struct {
	AdapterName         string
	VirtualMCPRouteName string
}

// RegisteredAgent is the data-plane projection of an Agent CR. Built by
// AgentReconciler whenever the agent reaches Ready or Degraded; consumed
// by the §2.4 HTTP shim when routing inbound requests.
//
// Deliberately omits ACL data — §2.3e (RouteAssignment reconciler) will
// decide whether the data plane consults the store or the assignments
// directly; baking ACL into the registered shape now would predetermine
// that.
type RegisteredAgent struct {
	ID          string
	Namespace   string
	Name        string
	Protocol    string
	EndpointURL string
	Mode        v1alpha1.AgentMode
	Tools       []ToolRef
}

// AgentRegistry is the read side. HTTP handlers / dispatchers depend on
// this narrow type so they can't accidentally mutate the store.
type AgentRegistry interface {
	GetAgent(id string) (*RegisteredAgent, bool)
	ListAgents() []*RegisteredAgent
	ListByProtocol(protocol string) []*RegisteredAgent
}

// AgentStore extends AgentRegistry with the mutation methods the
// reconciler needs to publish agents. The split mirrors
// pkg/services/virtualmcp.RouteRegistry / RouteStore.
type AgentStore interface {
	AgentRegistry
	UpsertAgent(agent *RegisteredAgent) error
	DeleteAgent(id string) error
}

// ErrInvalidAgent is returned by UpsertAgent when the registration is
// missing required identity fields. Reconciler bugs surface here rather
// than producing a silently-malformed store entry.
var ErrInvalidAgent = errors.New("agents: registered agent missing ID")

// InMemoryAgentStore is the default AgentStore. Owned by the manager
// binary; §2.4 will share this same instance with the HTTP shim so the
// controller and the request path see the same agents.
type InMemoryAgentStore struct {
	mu     sync.RWMutex
	agents map[string]*RegisteredAgent
}

// NewInMemoryAgentStore returns an empty store ready for Upsert/Delete.
func NewInMemoryAgentStore() *InMemoryAgentStore {
	return &InMemoryAgentStore{agents: map[string]*RegisteredAgent{}}
}

// UpsertAgent stores a deep-ish copy of agent under agent.ID. Subsequent
// reads return a fresh copy so callers can't mutate the stored value.
func (s *InMemoryAgentStore) UpsertAgent(agent *RegisteredAgent) error {
	if agent == nil || agent.ID == "" {
		return ErrInvalidAgent
	}
	stored := cloneAgent(agent)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID] = stored
	return nil
}

// DeleteAgent is idempotent: removing an unknown ID is not an error.
func (s *InMemoryAgentStore) DeleteAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, id)
	return nil
}

// GetAgent returns a fresh copy of the stored agent, or (nil, false).
func (s *InMemoryAgentStore) GetAgent(id string) (*RegisteredAgent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, false
	}
	return cloneAgent(a), true
}

// ListAgents returns every registered agent in ID-sorted order so callers
// (printers, tests) get deterministic output.
func (s *InMemoryAgentStore) ListAgents() []*RegisteredAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAgent, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, cloneAgent(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListByProtocol filters ListAgents to agents whose Protocol matches.
// Empty protocol returns nothing — callers asking for "any protocol"
// should use ListAgents.
func (s *InMemoryAgentStore) ListByProtocol(protocol string) []*RegisteredAgent {
	if protocol == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAgent, 0)
	for _, a := range s.agents {
		if a.Protocol == protocol {
			out = append(out, cloneAgent(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func cloneAgent(a *RegisteredAgent) *RegisteredAgent {
	cp := *a
	if len(a.Tools) > 0 {
		cp.Tools = append([]ToolRef(nil), a.Tools...)
	}
	return &cp
}
