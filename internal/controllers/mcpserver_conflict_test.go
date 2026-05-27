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

package controllers

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
)

func mkServer(name string, priority int32, created time.Time) mcpv1alpha1.MCPServer {
	return mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: mcpv1alpha1.MCPServerStatus{Priority: priority},
	}
}

func TestPickWinner_Empty(t *testing.T) {
	if got := pickWinner(nil); got != -1 {
		t.Errorf("pickWinner(nil) = %d, want -1", got)
	}
	if got := pickWinner([]mcpv1alpha1.MCPServer{}); got != -1 {
		t.Errorf("pickWinner([]) = %d, want -1", got)
	}
}

func TestPickWinner_SingleEntry(t *testing.T) {
	siblings := []mcpv1alpha1.MCPServer{mkServer("only", 0, time.Now())}
	if got := pickWinner(siblings); got != 0 {
		t.Errorf("pickWinner(singleton) = %d, want 0", got)
	}
}

func TestPickWinner_HigherPriorityWins(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	siblings := []mcpv1alpha1.MCPServer{
		mkServer("a", 10, t0),
		mkServer("b", 50, t0.Add(time.Hour)),
		mkServer("c", 20, t0.Add(2*time.Hour)),
	}
	if got, want := pickWinner(siblings), 1; got != want {
		t.Errorf("pickWinner = %d, want %d (b has priority 50)", got, want)
	}
}

func TestPickWinner_TieOnPriority_OlderWins(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	siblings := []mcpv1alpha1.MCPServer{
		mkServer("a", 10, newer),
		mkServer("b", 10, older),
		mkServer("c", 10, older.Add(2*time.Hour)),
	}
	if got, want := pickWinner(siblings), 1; got != want {
		t.Errorf("pickWinner = %d, want %d (b is oldest at the winning priority)", got, want)
	}
}

func TestPickWinner_TieOnPriorityAndTime_LexicographicWins(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	siblings := []mcpv1alpha1.MCPServer{
		mkServer("charlie", 5, t0),
		mkServer("alpha", 5, t0),
		mkServer("bravo", 5, t0),
	}
	// alpha < bravo < charlie → alpha at index 1 wins.
	if got, want := pickWinner(siblings), 1; got != want {
		t.Errorf("pickWinner = %d, want %d (alpha is lex-first at the same priority+time)", got, want)
	}
}

func TestPickWinner_NegativePriorityWorks(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	siblings := []mcpv1alpha1.MCPServer{
		mkServer("a", -10, t0),
		mkServer("b", -5, t0),
	}
	if got, want := pickWinner(siblings), 1; got != want {
		t.Errorf("pickWinner = %d, want %d (-5 > -10)", got, want)
	}
}
