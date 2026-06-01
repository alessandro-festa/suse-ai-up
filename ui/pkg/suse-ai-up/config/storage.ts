// localStorage keys owned by this extension. Centralized so a future
// migration / rename has one place to touch.

export const LOCAL_STORAGE_KEYS = {
  AUTH_TOKEN:          'suse-ai-up-auth-token',
  // JSON-serialized AuthUser. Stashed alongside AUTH_TOKEN so the UI can
  // render "Signed in as <name>" without re-fetching after a reload.
  AUTH_USER:           'suse-ai-up-auth-user',
  // JSON: { cluster, namespace, name, port }. Default below.
  SERVICE_LOCATION:    'suse-ai-up-service-location',
  // Optional direct backend URL (e.g. http://localhost:8911) for local
  // dev outside Rancher. Empty/absent → use the in-cluster proxy URL
  // built from SERVICE_LOCATION.
  DIRECT_BACKEND_URL:  'suse-ai-up-direct-backend-url',
  // 'local' (default) or 'rancher' — chosen by the admin on first
  // Settings load. Determines whether Users / Groups tabs and the
  // adapter ACL picker pull from our backend or from Rancher's own
  // Steve/Norman APIs (read-only in v1). See config/identity.ts.
  IDENTITY_PROVIDER:   'suse-ai-up-identity-provider',
  // JSON array of role-mapping rules, applied in Rancher mode to
  // mark Rancher principals/global-roles as members of local groups
  // (e.g. globalRole:admin → mcp-admins). See config/identity.ts.
  RANCHER_ROLE_MAP:    'suse-ai-up-rancher-role-map',
  SETTINGS:            'suse-ai-up-settings',
} as const;
