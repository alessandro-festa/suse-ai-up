/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// P2.4f tests for the CR-aware Authenticate path in layeredUserStore.
// The fake controller-runtime client stands in for the API server; we
// plant User CRs + their PasswordSecretRef Secrets, then exercise the
// branches: happy path, wrong password, missing Secret, non-local
// provider, and the fall-through-to-file path that keeps the bootstrap
// admin able to log in even when the CR client is wired.
package bootstrap

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"golang.org/x/crypto/bcrypt"

	mcpv1alpha1 "github.com/SUSE/suse-ai-up/api/v1alpha1"
	"github.com/SUSE/suse-ai-up/pkg/clients"
	"github.com/SUSE/suse-ai-up/pkg/models"
	"github.com/SUSE/suse-ai-up/pkg/services/auth"
)

const layeredTestNamespace = "test-ns"

func newTestCRClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := mcpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register mcpv1alpha1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		Build()
}

// stubFileStore is the in-memory fallback that stands in for the
// JSON-file-backed clients.UserStore in tests. Only Authenticate and
// helpers used by the layered tests are populated; everything else
// errors out so accidental delegation is loud.
type stubFileStore struct {
	users map[string]models.User
}

func newStubFileStore(seed ...models.User) *stubFileStore {
	s := &stubFileStore{users: map[string]models.User{}}
	for _, u := range seed {
		s.users[u.ID] = u
	}
	return s
}

func (s *stubFileStore) Authenticate(_ context.Context, id, password string) (*models.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}
	return &u, nil
}
func (s *stubFileStore) Get(_ context.Context, id string) (*models.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return &u, nil
}
func (s *stubFileStore) List(_ context.Context) ([]models.User, error) {
	out := make([]models.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out, nil
}
func (s *stubFileStore) GetByEmail(_ context.Context, _ string) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (s *stubFileStore) GetByExternalID(_ context.Context, _, _ string) (*models.User, error) {
	return nil, errors.New("not implemented")
}
func (s *stubFileStore) Create(_ context.Context, _ models.User) error  { return nil }
func (s *stubFileStore) Update(_ context.Context, _ models.User) error  { return nil }
func (s *stubFileStore) Delete(_ context.Context, _ models.User) error  { return nil }
func (s *stubFileStore) Watch(_ context.Context) (<-chan clients.StoreEvent, error) {
	return nil, errors.New("not implemented")
}
func (s *stubFileStore) Subscribe(_ context.Context, _ clients.StoreEventHandler) error {
	return errors.New("not implemented")
}

var _ clients.UserStore = (*stubFileStore)(nil)

// userWithPassword constructs a User CR + its paired Secret with a
// bcrypt'd password. Returns both so the test can pass them to the fake
// client.
func userWithPassword(t *testing.T, name, plaintext string, provider mcpv1alpha1.UserAuthProvider) (*mcpv1alpha1.User, *corev1.Secret) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	secretName := "user-" + name + "-password"
	u := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: layeredTestNamespace},
		Spec: mcpv1alpha1.UserSpec{
			DisplayName:  name,
			AuthProvider: provider,
			PasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
				Key:                  "password",
			},
		},
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: layeredTestNamespace},
		Data:       map[string][]byte{"password": hash},
	}
	return u, s
}

// TestLayeredUserStore_Authenticate_CRPath_Success: CR-projected user
// with a valid Secret authenticates and the returned models.User
// reflects the CR's projection.
func TestLayeredUserStore_Authenticate_CRPath_Success(t *testing.T) {
	u, sec := userWithPassword(t, "alice", "right-password", mcpv1alpha1.UserAuthProviderLocal)
	crClient := newTestCRClient(t, u, sec)
	store := newLayeredUserStore(newStubFileStore(), auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	got, err := store.Authenticate(context.Background(), "alice", "right-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got == nil || got.ID != "alice" {
		t.Errorf("user = %+v, want ID=alice", got)
	}
	if got.AuthProvider != string(mcpv1alpha1.UserAuthProviderLocal) {
		t.Errorf("AuthProvider = %q", got.AuthProvider)
	}
}

// TestLayeredUserStore_Authenticate_CRPath_WrongPassword: bcrypt
// mismatch returns an error with the deliberately-vague message.
func TestLayeredUserStore_Authenticate_CRPath_WrongPassword(t *testing.T) {
	u, sec := userWithPassword(t, "alice", "right-password", mcpv1alpha1.UserAuthProviderLocal)
	crClient := newTestCRClient(t, u, sec)
	store := newLayeredUserStore(newStubFileStore(), auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	_, err := store.Authenticate(context.Background(), "alice", "wrong")
	if err == nil {
		t.Fatalf("expected error on wrong password")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("err = %q, want invalid credentials", err.Error())
	}
}

// TestLayeredUserStore_Authenticate_CRPath_MissingSecret: User CR has a
// PasswordSecretRef but the Secret doesn't exist (e.g. someone deleted
// it). Vague error so account existence isn't leaked.
func TestLayeredUserStore_Authenticate_CRPath_MissingSecret(t *testing.T) {
	u := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: layeredTestNamespace},
		Spec: mcpv1alpha1.UserSpec{
			AuthProvider: mcpv1alpha1.UserAuthProviderLocal,
			PasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "user-alice-password"},
				Key:                  "password",
			},
		},
	}
	crClient := newTestCRClient(t, u)
	store := newLayeredUserStore(newStubFileStore(), auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	_, err := store.Authenticate(context.Background(), "alice", "anything")
	if err == nil || err.Error() != "invalid credentials" {
		t.Errorf("err = %v, want invalid credentials", err)
	}
}

// TestLayeredUserStore_Authenticate_CRPath_NoPasswordSecretRef: a User
// without a credential ref (e.g. a federated user mis-routed here, or a
// local user pending password set) refuses with the vague message.
func TestLayeredUserStore_Authenticate_CRPath_NoPasswordSecretRef(t *testing.T) {
	u := &mcpv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: layeredTestNamespace},
		Spec:       mcpv1alpha1.UserSpec{AuthProvider: mcpv1alpha1.UserAuthProviderLocal},
	}
	crClient := newTestCRClient(t, u)
	store := newLayeredUserStore(newStubFileStore(), auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	_, err := store.Authenticate(context.Background(), "alice", "anything")
	if err == nil || err.Error() != "invalid credentials" {
		t.Errorf("err = %v, want invalid credentials", err)
	}
}

// TestLayeredUserStore_Authenticate_CRPath_NonLocalProvider: federated
// users get a named-provider error so callers can route them to the
// right login flow (rather than blindly retrying local).
func TestLayeredUserStore_Authenticate_CRPath_NonLocalProvider(t *testing.T) {
	u, sec := userWithPassword(t, "alice", "p", mcpv1alpha1.UserAuthProviderGitHub)
	crClient := newTestCRClient(t, u, sec)
	store := newLayeredUserStore(newStubFileStore(), auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	_, err := store.Authenticate(context.Background(), "alice", "p")
	if err == nil {
		t.Fatalf("expected non-nil error")
	}
	// Provider name appears so the caller can act on it; existence not
	// leaked beyond what RBAC on the CR already exposes.
	want := "user uses github authentication; local password not accepted"
	if err.Error() != want {
		t.Errorf("err = %q, want %q", err.Error(), want)
	}
}

// TestLayeredUserStore_Authenticate_FallsThroughToFile: when the User
// CR doesn't exist, Authenticate falls through to the file store —
// keeps the bootstrap-seeded admin functional after P2.4f's wiring
// change.
func TestLayeredUserStore_Authenticate_FallsThroughToFile(t *testing.T) {
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin-pw"), bcrypt.DefaultCost)
	file := newStubFileStore(models.User{
		ID:           "admin",
		AuthProvider: string(models.UserAuthProviderLocal),
		PasswordHash: string(adminHash),
	})
	crClient := newTestCRClient(t) // no User CRs
	store := newLayeredUserStore(file, auth.NewInMemoryUserStore()).
		withCRClient(crClient, layeredTestNamespace)

	got, err := store.Authenticate(context.Background(), "admin", "admin-pw")
	if err != nil {
		t.Fatalf("Authenticate (fall-through): %v", err)
	}
	if got == nil || got.ID != "admin" {
		t.Errorf("user = %+v, want ID=admin", got)
	}
}

// TestLayeredUserStore_Authenticate_NoCRClient: without crClient set
// (legacy mode), Authenticate goes straight to the file store — proves
// the wiring is opt-in and doesn't regress callers that haven't called
// withCRClient.
func TestLayeredUserStore_Authenticate_NoCRClient(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.DefaultCost)
	file := newStubFileStore(models.User{
		ID:           "legacy",
		AuthProvider: string(models.UserAuthProviderLocal),
		PasswordHash: string(hash),
	})
	store := newLayeredUserStore(file, auth.NewInMemoryUserStore())

	got, err := store.Authenticate(context.Background(), "legacy", "pw")
	if err != nil {
		t.Fatalf("Authenticate (no crClient): %v", err)
	}
	if got == nil || got.ID != "legacy" {
		t.Errorf("user = %+v", got)
	}
}
