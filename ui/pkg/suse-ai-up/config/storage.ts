// localStorage keys owned by this extension. Centralized so a future
// migration / rename has one place to touch.

export const LOCAL_STORAGE_KEYS = {
  AUTH_TOKEN:  'suse-ai-up-auth-token',
  BACKEND_URL: 'suse-ai-up-backend-url',
  SETTINGS:    'suse-ai-up-settings',
} as const;
