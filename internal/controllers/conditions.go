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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// setMetaCondition finds-or-appends a Condition by Type in conds and stamps
// LastTransitionTime only when Status flips. Shared by all reconcilers in
// this package — each *Status type carries its own []metav1.Condition slice
// but the merge semantics are identical.
func setMetaCondition(conds *[]metav1.Condition, observedGeneration int64, condType string, condStatus metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i := range *conds {
		if (*conds)[i].Type != condType {
			continue
		}
		c := &(*conds)[i]
		if c.Status != condStatus {
			c.LastTransitionTime = now
		}
		c.Status = condStatus
		c.Reason = reason
		c.Message = message
		c.ObservedGeneration = observedGeneration
		return
	}
	*conds = append(*conds, metav1.Condition{
		Type:               condType,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
		ObservedGeneration: observedGeneration,
	})
}
