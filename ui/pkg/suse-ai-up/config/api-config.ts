// Resolve the suse-ai-up backend base URL. Two modes:
//   1. Direct (default): user-configured backend URL, persisted in store.
//   2. Rancher cluster proxy: when the dashboard is hosted at a URL
//      containing /k8s/clusters/, route requests through the proxy so
//      auth and routing reuse Rancher's session.

import { LOCAL_STORAGE_KEYS } from './storage';

export const DEFAULT_BACKEND_URL = 'http://localhost:8911';

export const API_BASE = '/api/v1';

// Endpoint paths (relative to API_BASE unless leading slash present).
export const ENDPOINTS = {
  HEALTH:        '/health',
  AUTH_MODE:     '/auth/mode',
  AUTH_LOGIN:    '/auth/login',
  AUTH_LOGOUT:   '/auth/logout',
  ADAPTERS:      `${ API_BASE }/adapters`,
  REGISTRY:      `${ API_BASE }/registry`,
  USERS:         `${ API_BASE }/users`,
  GROUPS:        `${ API_BASE }/groups`,
  PLUGINS:       `${ API_BASE }/plugins`,
  DISCOVERY:     `${ API_BASE }/discovery`,
} as const;

let cachedBackend: string | null = null;

export function getBackendUrl(): string {
  if (cachedBackend) {
    return cachedBackend;
  }
  try {
    const stored = window.localStorage.getItem(LOCAL_STORAGE_KEYS.BACKEND_URL);
    if (stored) {
      cachedBackend = stored;
      return stored;
    }
  } catch {
    // window may be unavailable during SSR.
  }
  return DEFAULT_BACKEND_URL;
}

export function setBackendUrl(url: string) {
  cachedBackend = url;
  try {
    window.localStorage.setItem(LOCAL_STORAGE_KEYS.BACKEND_URL, url);
  } catch {
    /* ignore */
  }
}

// Detect Rancher cluster proxy hosting. When the dashboard URL contains
// /k8s/clusters/<id>, we tunnel API calls through Rancher's proxy so
// auth and SSL cert handling go through the dashboard.
export function resolveBaseUrl(): string {
  try {
    const { origin, pathname } = window.location;
    const match = pathname.match(/\/k8s\/clusters\/([^/]+)/);
    if (match) {
      // The backend is fronted by a Service in the workload cluster.
      // Operators configure the proxy path; for now we surface the
      // raw cluster origin and let the user override via settings.
      return `${ origin }/k8s/clusters/${ match[1] }/proxy:suse-ai-up`;
    }
  } catch {
    /* ignore */
  }
  return getBackendUrl();
}
