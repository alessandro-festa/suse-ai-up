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

// P2.4/PR3 — layered user/group stores.
//
// Background. The reconcilers (User, Group, RouteAssignment) project
// validated CR state into auth.UserStore / auth.GroupStore /
// auth.AssignmentStore. The HTTP data plane uses clients.UserStore /
// clients.GroupStore for both CRUD and local-password authentication.
// The two interfaces are not adaptable end-to-end:
//
//   - clients.UserStore has Authenticate(ctx, id, password); auth's
//     RegisteredUser has no PasswordHash because CRs don't carry one.
//   - clients.UserStore is full CRUD over models.User; auth.UserStore is
//     read-mostly over a narrow projection (no LastLoginAt, no
//     ProviderGroups, no created/updated timestamps).
//
// The layered adapter here closes the gap that IS closable: read endpoints
// (GET /users, GET /users/:id, ListGroups, etc.) merge the projection
// view on top of the file-backed store, so a `kubectl apply` of a User
// CR is immediately visible to /api/v1/users. Writes and Authenticate
// stay on the file-backed store — HTTP CRUD remains a working write
// surface; local-auth login continues to work for the bootstrap-seeded
// admin user. Unifying writes (HTTP POST → User CR) and local auth
// (User CR → credential Secret reference) is a follow-up issue post
// Epic 1; that work also lets us delete the file-backed clients stores.
package bootstrap

import (
	"context"
	"strings"

	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// layeredUserStore satisfies clients.UserStore by reading from the
// reconciler-populated projection first and falling back to the
// file-backed store. Mutations and Authenticate go to the file store.
type layeredUserStore struct {
	file       clients.UserStore
	projection auth.UserRegistry
}

func newLayeredUserStore(file clients.UserStore, projection auth.UserRegistry) *layeredUserStore {
	return &layeredUserStore{file: file, projection: projection}
}

func (s *layeredUserStore) Get(ctx context.Context, id string) (*models.User, error) {
	if u, ok := s.projection.GetUser(id); ok {
		return registeredUserToModel(u), nil
	}
	return s.file.Get(ctx, id)
}

func (s *layeredUserStore) List(ctx context.Context) ([]models.User, error) {
	seen := make(map[string]bool)
	out := make([]models.User, 0)
	for _, u := range s.projection.ListUsers() {
		m := registeredUserToModel(u)
		out = append(out, *m)
		seen[m.ID] = true
	}
	fileUsers, err := s.file.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range fileUsers {
		if !seen[u.ID] {
			out = append(out, u)
		}
	}
	return out, nil
}

func (s *layeredUserStore) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return s.file.GetByEmail(ctx, email)
	}
	// Projection's GetUserByEmail needs a namespace; scan all entries to
	// honor the namespace-agnostic HTTP contract.
	for _, u := range s.projection.ListUsers() {
		if strings.EqualFold(u.Email, email) {
			return registeredUserToModel(u), nil
		}
	}
	return s.file.GetByEmail(ctx, email)
}

func (s *layeredUserStore) Create(ctx context.Context, user models.User) error {
	return s.file.Create(ctx, user)
}

func (s *layeredUserStore) Update(ctx context.Context, user models.User) error {
	return s.file.Update(ctx, user)
}

func (s *layeredUserStore) Delete(ctx context.Context, user models.User) error {
	return s.file.Delete(ctx, user)
}

func (s *layeredUserStore) GetByExternalID(ctx context.Context, provider, externalID string) (*models.User, error) {
	return s.file.GetByExternalID(ctx, provider, externalID)
}

func (s *layeredUserStore) Authenticate(ctx context.Context, id, password string) (*models.User, error) {
	return s.file.Authenticate(ctx, id, password)
}

func (s *layeredUserStore) Watch(ctx context.Context) (<-chan clients.StoreEvent, error) {
	return s.file.Watch(ctx)
}

func (s *layeredUserStore) Subscribe(ctx context.Context, handler clients.StoreEventHandler) error {
	return s.file.Subscribe(ctx, handler)
}

// layeredGroupStore is the GroupStore mirror of layeredUserStore.
type layeredGroupStore struct {
	file       clients.GroupStore
	projection auth.GroupRegistry
}

func newLayeredGroupStore(file clients.GroupStore, projection auth.GroupRegistry) *layeredGroupStore {
	return &layeredGroupStore{file: file, projection: projection}
}

func (s *layeredGroupStore) Get(ctx context.Context, id string) (*models.Group, error) {
	if g, ok := s.projection.GetGroup(id); ok {
		return registeredGroupToModel(g), nil
	}
	return s.file.Get(ctx, id)
}

func (s *layeredGroupStore) List(ctx context.Context) ([]models.Group, error) {
	seen := make(map[string]bool)
	out := make([]models.Group, 0)
	for _, g := range s.projection.ListGroups() {
		m := registeredGroupToModel(g)
		out = append(out, *m)
		seen[m.ID] = true
	}
	fileGroups, err := s.file.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range fileGroups {
		if !seen[g.ID] {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *layeredGroupStore) Create(ctx context.Context, group models.Group) error {
	return s.file.Create(ctx, group)
}

func (s *layeredGroupStore) Update(ctx context.Context, group models.Group) error {
	return s.file.Update(ctx, group)
}

func (s *layeredGroupStore) Delete(ctx context.Context, id string) error {
	return s.file.Delete(ctx, id)
}

func (s *layeredGroupStore) AddMember(ctx context.Context, groupID, userID string) error {
	return s.file.AddMember(ctx, groupID, userID)
}

func (s *layeredGroupStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	return s.file.RemoveMember(ctx, groupID, userID)
}

func (s *layeredGroupStore) Watch(ctx context.Context) (<-chan clients.StoreEvent, error) {
	return s.file.Watch(ctx)
}

func (s *layeredGroupStore) Subscribe(ctx context.Context, handler clients.StoreEventHandler) error {
	return s.file.Subscribe(ctx, handler)
}

// registeredUserToModel projects an auth.RegisteredUser into the
// models.User shape the HTTP DTOs use. Fields absent from the CR
// projection (PasswordHash, LastLoginAt, timestamps, provider groups)
// stay zero — the file-store path remains the source of those for
// locally-authenticated users.
func registeredUserToModel(u *auth.RegisteredUser) *models.User {
	if u == nil {
		return nil
	}
	name := u.DisplayName
	if name == "" {
		name = u.Name
	}
	return &models.User{
		ID:           u.ID,
		Name:         name,
		Email:        u.Email,
		Groups:       append([]string(nil), u.Groups...),
		AuthProvider: string(u.AuthProvider),
		ExternalID:   u.ExternalID,
	}
}

// registeredGroupToModel projects an auth.RegisteredGroup into
// models.Group.
func registeredGroupToModel(g *auth.RegisteredGroup) *models.Group {
	if g == nil {
		return nil
	}
	name := g.DisplayName
	if name == "" {
		name = g.Name
	}
	return &models.Group{
		ID:          g.ID,
		Name:        name,
		Members:     append([]string(nil), g.Members...),
		Permissions: append([]string(nil), g.Permissions...),
	}
}

// Compile-time interface checks.
var (
	_ clients.UserStore  = (*layeredUserStore)(nil)
	_ clients.GroupStore = (*layeredGroupStore)(nil)
)
