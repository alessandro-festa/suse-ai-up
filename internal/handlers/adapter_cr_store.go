/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4d — read-side projection from Adapter CRs to models.AdapterResource.
//
// AdapterService still wraps a clients.AdapterResourceStore for the read
// paths (ListAdapters/GetAdapter). In CR mode the underlying store is this
// type: List/Get/ListAll consult the controller-runtime client (which
// reads from the cached informer — no API round-trip) and project the CR
// into the AdapterResource shape the HTTP DTOs expect. The write methods
// return ErrCRStoreReadOnly because the new write trio in adapters_crud.go
// bypasses adapterService entirely and goes to crClient directly.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
)

// ErrCRStoreReadOnly is returned by the CR-backed adapter store on any
// write attempt. The new HTTP write path goes through crClient.Create /
// Update / Delete directly; nothing in the system should be asking the
// store to mutate. Returning an error (rather than silently no-op'ing)
// surfaces any forgotten legacy write path during smoke testing.
var ErrCRStoreReadOnly = errors.New("adapter CR store is read-only; writes must go through controller-runtime client")

// AdapterCRStore implements clients.AdapterResourceStore by reading
// Adapter CRs through a controller-runtime client.
type AdapterCRStore struct {
	c         client.Client
	namespace string
}

// NewAdapterCRStore returns a read-only AdapterResourceStore backed by
// Adapter CRs in the given namespace.
func NewAdapterCRStore(c client.Client, namespace string) *AdapterCRStore {
	return &AdapterCRStore{c: c, namespace: namespace}
}

// Get returns the Adapter CR projected to models.AdapterResource.
func (s *AdapterCRStore) Get(ctx context.Context, id string) (*models.AdapterResource, error) {
	var cr mcpv1alpha1.Adapter
	if err := s.c.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: id}, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("adapter not found")
		}
		return nil, fmt.Errorf("get adapter CR: %w", err)
	}
	return adapterCRToResource(&cr), nil
}

// List returns every Adapter CR projected to models.AdapterResource.
// The userID filter is honored when CRs carry an owner annotation
// (suse-ai-up.suse.com/created-by); otherwise all entries are returned
// — matches today's behavior where AdapterService.ListAdapters falls
// back to ListAll for admin-equivalent users.
func (s *AdapterCRStore) List(ctx context.Context, userID string) ([]models.AdapterResource, error) {
	all, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return all, nil
	}
	out := make([]models.AdapterResource, 0, len(all))
	for _, a := range all {
		if a.CreatedBy == "" || a.CreatedBy == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// ListAll returns every Adapter CR in the configured namespace.
func (s *AdapterCRStore) ListAll(ctx context.Context) ([]models.AdapterResource, error) {
	var list mcpv1alpha1.AdapterList
	if err := s.c.List(ctx, &list, client.InNamespace(s.namespace)); err != nil {
		return nil, fmt.Errorf("list adapter CRs: %w", err)
	}
	out := make([]models.AdapterResource, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, *adapterCRToResource(&list.Items[i]))
	}
	return out, nil
}

func (s *AdapterCRStore) Create(ctx context.Context, adapter models.AdapterResource) error {
	return ErrCRStoreReadOnly
}
func (s *AdapterCRStore) Update(ctx context.Context, adapter models.AdapterResource) error {
	return ErrCRStoreReadOnly
}
func (s *AdapterCRStore) Delete(ctx context.Context, id string) error {
	return ErrCRStoreReadOnly
}
func (s *AdapterCRStore) UpsertAsync(adapter models.AdapterResource, ctx context.Context) error {
	return ErrCRStoreReadOnly
}

// Watch / Subscribe — the CR projection doesn't surface store events.
// Reconciler-driven cache changes are observable via the controller-runtime
// informer; nothing today consumes adapter store events anyway. Returning
// a closed channel keeps any accidental consumer from blocking.
func (s *AdapterCRStore) Watch(ctx context.Context) (<-chan clients.StoreEvent, error) {
	ch := make(chan clients.StoreEvent)
	close(ch)
	return ch, nil
}
func (s *AdapterCRStore) Subscribe(ctx context.Context, handler clients.StoreEventHandler) error {
	return nil
}

// adapterCRToResource projects an Adapter CR into the AdapterResource
// shape that BuildCreateClientConfig / BuildListClientConfig and the
// existing HTTP DTOs expect. Fields not carried by the CR (legacy
// MCPClientConfig, MCPFunctionality discovered at runtime) stay zero
// — the same as today's GET behavior for adapters that haven't been
// probed yet.
func adapterCRToResource(cr *mcpv1alpha1.Adapter) *models.AdapterResource {
	if cr == nil {
		return nil
	}
	connectionType := models.ConnectionType(cr.Spec.ConnectionType)
	url := cr.Status.EndpointURL
	if url == "" {
		url = fmt.Sprintf("/api/v1/adapters/%s/mcp", cr.Name)
	}

	status := models.AdapterLifecycleStatusNotReady
	for _, cond := range cr.Status.Conditions {
		if cond.Type == mcpv1alpha1.AdapterConditionReady {
			switch cond.Status {
			case metav1.ConditionTrue:
				status = models.AdapterLifecycleStatusReady
			case metav1.ConditionFalse:
				status = models.AdapterLifecycleStatusError
			}
			break
		}
	}

	createdBy := cr.Annotations[adapterAnnotationCreatedBy]
	created := cr.CreationTimestamp.Time
	if created.IsZero() {
		created = time.Now().UTC()
	}

	var mcpServerID string
	if cr.Spec.Source.MCPServerRef != nil {
		mcpServerID = cr.Spec.Source.MCPServerRef.Name
	}
	routeAssignmentRefs := make([]string, 0, len(cr.Spec.RouteAssignmentRefs))
	for _, ref := range cr.Spec.RouteAssignmentRefs {
		if ref.Name != "" {
			routeAssignmentRefs = append(routeAssignmentRefs, ref.Name)
		}
	}

	res := &models.AdapterResource{
		AdapterData: models.AdapterData{
			Name:                 cr.Name,
			Protocol:             models.ServerProtocolMCP,
			ConnectionType:       connectionType,
			Status:               status,
			EnvironmentVariables: cr.Spec.Variables,
			Description:          cr.Spec.Description,
			URL:                  url,
			RemoteUrl:            cr.Spec.Source.RemoteURL,
			MCPServerID:          mcpServerID,
			RouteAssignmentRefs:  routeAssignmentRefs,
		},
		ID:            cr.Name,
		CreatedBy:     createdBy,
		CreatedAt:     created,
		LastUpdatedAt: created,
	}
	if cr.Spec.Replicas != nil {
		res.ReplicaCount = int(*cr.Spec.Replicas)
	}
	return res
}

// Annotations the HTTP write path stamps onto the Adapter CR so the read
// projection can recover owner identity. The CR Spec itself has no
// "createdBy" field — it's an HTTP-layer concept.
const (
	adapterAnnotationCreatedBy     = "suse-ai-up.suse.com/created-by"
	adapterAnnotationSyncRequested = "suse-ai-up.suse.com/sync-requested"
)

// Compile-time interface check.
var _ clients.AdapterResourceStore = (*AdapterCRStore)(nil)
