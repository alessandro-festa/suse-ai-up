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

// P2.4/PR3 — layered user/group stores. Extended in P2.4f with
// CR-aware local Authenticate.
//
// Background. The reconcilers (User, Group, RouteAssignment) project
// validated CR state into auth.UserStore / auth.GroupStore /
// auth.AssignmentStore. The HTTP data plane uses clients.UserStore /
// clients.GroupStore for both CRUD and local-password authentication.
// Reads merge the projection view on top of the file-backed store, so a
// `kubectl apply` of a User CR is immediately visible to /api/v1/users.
//
// P2.4f added a CR client + namespace so Authenticate can also serve
// CR-created local users: when crClient is set, Authenticate first tries
// to read the User CR by name in the operator namespace, resolves its
// PasswordSecretRef, and bcrypt-compares against the stored hash. When
// the CR isn't present (e.g. the bootstrap-seeded admin still living in
// the file store), it falls through to s.file.Authenticate so login
// continues to work for legacy users. Mutations (Create/Update/Delete)
// continue to go to the file store; HTTP-driven user creation is owned
// by the CR-mode branch in internal/handlers/user_group_crud.go.
package bootstrap

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"golang.org/x/crypto/bcrypt"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services/auth"
)

// layeredUserStore satisfies clients.UserStore by reading from the
// reconciler-populated projection first and falling back to the
// file-backed store. Mutations go to the file store. Authenticate prefers
// the CR-backed credential when crClient is set; otherwise it falls
// through to the file store (preserves the bootstrap admin login).
type layeredUserStore struct {
	file       clients.UserStore
	projection auth.UserRegistry
	crClient   client.Client
	namespace  string
}

func newLayeredUserStore(file clients.UserStore, projection auth.UserRegistry) *layeredUserStore {
	return &layeredUserStore{file: file, projection: projection}
}

// withCRClient enables CR-aware Authenticate. Returns the store for
// chaining; safe to call once during bootstrap wiring.
func (s *layeredUserStore) withCRClient(c client.Client, namespace string) *layeredUserStore {
	s.crClient = c
	s.namespace = namespace
	return s
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

// Authenticate verifies password against a CR-backed credential when
// available, else falls through to the file store. The CR path reads the
// User CR directly from the operator namespace (bypassing the projection,
// whose keys are "<namespace>/<name>" while HTTP supplies bare IDs),
// resolves Spec.PasswordSecretRef, and bcrypt-compares.
//
// Errors are intentionally vague ("invalid credentials") to avoid leaking
// account-existence to a probing caller — only the AuthProvider-mismatch
// case names the provider, because federated users genuinely need a
// different login flow.
func (s *layeredUserStore) Authenticate(ctx context.Context, id, password string) (*models.User, error) {
	if s.crClient == nil {
		return s.file.Authenticate(ctx, id, password)
	}

	var cr mcpv1alpha1.User
	err := s.crClient.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: id}, &cr)
	switch {
	case apierrors.IsNotFound(err):
		// No CR for this id — fall through so the bootstrap-seeded admin
		// (file store only) can still log in.
		return s.file.Authenticate(ctx, id, password)
	case err != nil:
		return nil, fmt.Errorf("fetch User CR: %w", err)
	}

	provider := cr.Spec.AuthProvider
	if provider == "" {
		provider = mcpv1alpha1.UserAuthProviderLocal
	}
	if provider != mcpv1alpha1.UserAuthProviderLocal {
		return nil, fmt.Errorf("user uses %s authentication; local password not accepted", provider)
	}
	if cr.Spec.PasswordSecretRef == nil || cr.Spec.PasswordSecretRef.Name == "" {
		return nil, fmt.Errorf("invalid credentials")
	}

	var secret corev1.Secret
	if err := s.crClient.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: cr.Spec.PasswordSecretRef.Name}, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("fetch password secret: %w", err)
	}
	key := cr.Spec.PasswordSecretRef.Key
	if key == "" {
		key = "password"
	}
	hash, ok := secret.Data[key]
	if !ok || len(hash) == 0 {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	registered := crUserToRegistered(&cr)
	user := registeredUserToModel(registered)
	return user, nil
}

// crUserToRegistered mirrors controllers.toRegisteredUser but is local
// to the layered store so we don't pull in the controllers package
// (which would create an import cycle through bootstrap).
func crUserToRegistered(u *mcpv1alpha1.User) *auth.RegisteredUser {
	groups := make([]string, 0, len(u.Spec.Groups))
	for _, ref := range u.Spec.Groups {
		if ref.Name != "" {
			groups = append(groups, ref.Name)
		}
	}
	provider := u.Spec.AuthProvider
	if provider == "" {
		provider = mcpv1alpha1.UserAuthProviderLocal
	}
	// HTTP layer uses bare IDs throughout, so we keep ID=u.Name here
	// (the projection keyed by namespaced ID isn't relevant to the auth
	// caller — userAuthService.AuthenticateUser uses what Authenticate
	// returns to call Update for LastLoginAt, both of which match on
	// models.User.ID alone).
	return &auth.RegisteredUser{
		ID:           u.Name,
		Namespace:    u.Namespace,
		Name:         u.Name,
		DisplayName:  u.Spec.DisplayName,
		Email:        u.Spec.Email,
		AuthProvider: provider,
		ExternalID:   u.Spec.ExternalID,
		Groups:       groups,
	}
}

func (s *layeredUserStore) Watch(ctx context.Context) (<-chan clients.StoreEvent, error) {
	return s.file.Watch(ctx)
}

func (s *layeredUserStore) Subscribe(ctx context.Context, handler clients.StoreEventHandler) error {
	return s.file.Subscribe(ctx, handler)
}

// layeredGroupStore is the GroupStore mirror of layeredUserStore.
// It also holds a userRegistry so List/Get can augment each group's
// Members with the users who reference it in their Spec.Groups —
// without that "reverse edge" the file-store-only groups (e.g.
// chart-installed mcp-admins) appear empty even when User CRs declare
// membership in them.
type layeredGroupStore struct {
	file         clients.GroupStore
	projection   auth.GroupRegistry
	userRegistry auth.UserRegistry
}

func newLayeredGroupStore(file clients.GroupStore, projection auth.GroupRegistry, userRegistry auth.UserRegistry) *layeredGroupStore {
	return &layeredGroupStore{file: file, projection: projection, userRegistry: userRegistry}
}

// derivedMembersFor returns the set of user IDs (bare names) that
// reference `groupID` in their RegisteredUser.Groups. Scans the entire
// user registry — fine for the small directories this system targets.
// Pass either the bare group name or "namespace/name" form; both are
// matched against user.Groups entries.
func (s *layeredGroupStore) derivedMembersFor(groupID string) []string {
	if s.userRegistry == nil {
		return nil
	}
	bareGroup := stripNamespaceID(groupID)
	var out []string
	for _, u := range s.userRegistry.ListUsers() {
		for _, g := range u.Groups {
			if g == groupID || g == bareGroup || stripNamespaceID(g) == bareGroup {
				out = append(out, stripNamespaceID(u.ID))
				break
			}
		}
	}
	return out
}

// unionMembers folds derivedMembers into g.Members in place, dedup +
// sorted. Stable output makes the picker UI stable across reloads.
func (s *layeredGroupStore) unionMembers(g *models.Group) {
	derived := s.derivedMembersFor(g.ID)
	if len(derived) == 0 && len(g.Members) == 0 {
		return
	}
	seen := make(map[string]bool, len(g.Members)+len(derived))
	for _, m := range g.Members {
		if m != "" {
			seen[stripNamespaceID(m)] = true
		}
	}
	for _, m := range derived {
		if m != "" {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	g.Members = out
}

func (s *layeredGroupStore) Get(ctx context.Context, id string) (*models.Group, error) {
	if g, ok := s.projection.GetGroup(id); ok {
		m := registeredGroupToModel(g)
		s.unionMembers(m)
		return m, nil
	}
	g, err := s.file.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.unionMembers(g)
	return g, nil
}

func (s *layeredGroupStore) List(ctx context.Context) ([]models.Group, error) {
	seen := make(map[string]bool)
	out := make([]models.Group, 0)
	for _, g := range s.projection.ListGroups() {
		m := registeredGroupToModel(g)
		s.unionMembers(m)
		out = append(out, *m)
		seen[m.ID] = true
	}
	fileGroups, err := s.file.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range fileGroups {
		if !seen[g.ID] {
			s.unionMembers(&g)
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

// stripNamespaceID removes the "<namespace>/" prefix that the User /
// Group reconcilers stamp onto auth.RegisteredUser.ID for global
// uniqueness across namespaces. The HTTP DTOs are single-namespace
// (the operator's own namespace), so callers expect the bare name —
// otherwise the UI's `DELETE /users/alice` 404s because the actual
// stored ID is `suse-ai-up-mcp/alice`.
func stripNamespaceID(id string) string {
	if i := strings.IndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
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
		ID:           stripNamespaceID(u.ID),
		Name:         name,
		Email:        u.Email,
		Groups:       append([]string(nil), u.Groups...),
		AuthProvider: string(u.AuthProvider),
		ExternalID:   u.ExternalID,
	}
}

// registeredGroupToModel projects an auth.RegisteredGroup into
// models.Group. Members are stored by the reconciler as the full
// "<namespace>/<name>" id; strip to bare name so the UI can correlate
// with its own user IDs and the group-membership picker round-trips
// cleanly.
func registeredGroupToModel(g *auth.RegisteredGroup) *models.Group {
	if g == nil {
		return nil
	}
	name := g.DisplayName
	if name == "" {
		name = g.Name
	}
	members := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, stripNamespaceID(m))
	}
	return &models.Group{
		ID:          stripNamespaceID(g.ID),
		Name:        name,
		Members:     members,
		Permissions: append([]string(nil), g.Permissions...),
	}
}

// Compile-time interface checks.
var (
	_ clients.UserStore  = (*layeredUserStore)(nil)
	_ clients.GroupStore = (*layeredGroupStore)(nil)
)
