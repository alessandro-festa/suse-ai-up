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
	"fmt"
	"sync"
	"testing"

	v1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func sampleAgent(id, protocol string) *RegisteredAgent {
	return &RegisteredAgent{
		ID:          id,
		Namespace:   "default",
		Name:        id,
		Protocol:    protocol,
		EndpointURL: "/api/v1/agents/" + id,
		Mode:        v1alpha1.AgentModeInProcess,
		Tools:       []ToolRef{{AdapterName: "ada"}},
	}
}

func TestInMemoryAgentStore_UpsertAndGet(t *testing.T) {
	s := NewInMemoryAgentStore()
	a := sampleAgent("default/a1", "smartagents")

	if err := s.UpsertAgent(a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := s.GetAgent("default/a1")
	if !ok {
		t.Fatal("get: not found")
	}
	if got.Protocol != "smartagents" || got.EndpointURL != "/api/v1/agents/default/a1" {
		t.Errorf("got = %+v", got)
	}

	// Stored value should be a copy — mutating the returned struct must
	// not affect the next GetAgent.
	got.Protocol = "mutated"
	got2, _ := s.GetAgent("default/a1")
	if got2.Protocol != "smartagents" {
		t.Errorf("store returned shared pointer: protocol leaked to %q", got2.Protocol)
	}
}

func TestInMemoryAgentStore_UpsertReplaces(t *testing.T) {
	s := NewInMemoryAgentStore()
	_ = s.UpsertAgent(sampleAgent("default/a1", "smartagents"))
	if err := s.UpsertAgent(sampleAgent("default/a1", "a2a")); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ := s.GetAgent("default/a1")
	if got.Protocol != "a2a" {
		t.Errorf("protocol = %q, want a2a (upsert should replace)", got.Protocol)
	}
}

func TestInMemoryAgentStore_DeleteIdempotent(t *testing.T) {
	s := NewInMemoryAgentStore()
	_ = s.UpsertAgent(sampleAgent("default/a1", "smartagents"))

	if err := s.DeleteAgent("default/a1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteAgent("default/a1"); err != nil {
		t.Errorf("second delete returned %v, want nil (idempotent)", err)
	}
	if err := s.DeleteAgent("nonexistent"); err != nil {
		t.Errorf("delete of unknown id returned %v, want nil", err)
	}
	if _, ok := s.GetAgent("default/a1"); ok {
		t.Error("get after delete: still present")
	}
}

func TestInMemoryAgentStore_RejectsMissingID(t *testing.T) {
	s := NewInMemoryAgentStore()
	err := s.UpsertAgent(&RegisteredAgent{Protocol: "smartagents"})
	if !errors.Is(err, ErrInvalidAgent) {
		t.Errorf("err = %v, want ErrInvalidAgent", err)
	}
	if err := s.UpsertAgent(nil); !errors.Is(err, ErrInvalidAgent) {
		t.Errorf("nil agent err = %v, want ErrInvalidAgent", err)
	}
}

func TestInMemoryAgentStore_ListSorted(t *testing.T) {
	s := NewInMemoryAgentStore()
	_ = s.UpsertAgent(sampleAgent("default/c", "smartagents"))
	_ = s.UpsertAgent(sampleAgent("default/a", "smartagents"))
	_ = s.UpsertAgent(sampleAgent("default/b", "smartagents"))

	got := s.ListAgents()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, want := range []string{"default/a", "default/b", "default/c"} {
		if got[i].ID != want {
			t.Errorf("got[%d].ID = %q, want %q", i, got[i].ID, want)
		}
	}
}

func TestInMemoryAgentStore_ListByProtocol(t *testing.T) {
	s := NewInMemoryAgentStore()
	_ = s.UpsertAgent(sampleAgent("default/a1", "smartagents"))
	_ = s.UpsertAgent(sampleAgent("default/a2", "a2a"))
	_ = s.UpsertAgent(sampleAgent("default/a3", "smartagents"))

	got := s.ListByProtocol("smartagents")
	if len(got) != 2 || got[0].ID != "default/a1" || got[1].ID != "default/a3" {
		t.Errorf("smartagents list = %+v, want a1+a3", got)
	}

	got = s.ListByProtocol("a2a")
	if len(got) != 1 || got[0].ID != "default/a2" {
		t.Errorf("a2a list = %+v, want a2", got)
	}

	if got := s.ListByProtocol(""); got != nil {
		t.Errorf("empty protocol = %+v, want nil", got)
	}

	if got := s.ListByProtocol("unknown"); len(got) != 0 {
		t.Errorf("unknown protocol = %+v, want empty", got)
	}
}

func TestInMemoryAgentStore_ConcurrentAccess(t *testing.T) {
	// Light smoke for the -race detector: many writers + readers on
	// disjoint keys should never panic or trigger the race detector.
	s := NewInMemoryAgentStore()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("ns/a%d", i)
			_ = s.UpsertAgent(sampleAgent(id, "smartagents"))
			_, _ = s.GetAgent(id)
			_ = s.ListAgents()
			_ = s.DeleteAgent(id)
		}(i)
	}
	wg.Wait()
}
