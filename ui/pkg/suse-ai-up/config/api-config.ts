// Resolve the suse-ai-up backend base URL. Two modes:
//
//   1. **In-cluster proxy (default)**: route every request through Rancher's
//      cluster proxy so the call stays same-origin HTTPS and reuses the
//      user's Rancher session. URL shape:
//
//        /k8s/clusters/<cluster>/api/v1/namespaces/<ns>/services/http:<svc>:<port>/proxy
//
//      The backend is a regular ClusterIP Service in the cluster where the
//      operator runs (default: cluster `local`, namespace `suse-ai-up`,
//      service `suse-ai-up`, port 8911). Defaults are overridable via the
//      Settings page and persisted in localStorage.
//
//   2. **Direct URL (opt-in)**: when a non-empty direct URL is configured
//      (Settings page), the proxy is bypassed and requests go straight
//      to that origin. Use this for local development outside Rancher
//      (e.g. running `yarn dev` against a Go backend on `http://localhost:8911`).
//      Note: direct mode triggers browser Mixed Content blocking when the
//      dashboard itself is loaded over HTTPS — keep it for dev only.

import { LOCAL_STORAGE_KEYS } from './storage';

export interface ServiceLocation {
  cluster:   string;
  namespace: string;
  name:      string;
  port:      number;
}

// Matches the Helm chart at charts/suse-ai-up/ when installed via
// `make helm-install`: namespace `suse-ai-up`, Service named
// `suse-ai-up-service` (template `{release}-service` in
// charts/suse-ai-up/templates/_helpers.tpl), proxy port 8911 from
// values.yaml `services.proxy.port`.
export const DEFAULT_SERVICE_LOCATION: ServiceLocation = {
  cluster:   'local',
  namespace: 'suse-ai-up',
  name:      'suse-ai-up-service',
  port:      8911,
};

export const API_BASE = '/api/v1';

// Endpoint paths (relative to the resolved base URL).
// `/health` and `/auth/mode` are served at the root by Gin (see
// internal/router/router.go); everything else lives under `/api/v1/`.
export const ENDPOINTS = {
  HEALTH:           '/health',
  AUTH_MODE:        '/auth/mode',
  AUTH_LOGIN:       `${ API_BASE }/auth/login`,
  AUTH_LOGOUT:      `${ API_BASE }/auth/logout`,
  AUTH_PASSWORD:    `${ API_BASE }/auth/password`,
  ADAPTERS:         `${ API_BASE }/adapters`,
  REGISTRY:         `${ API_BASE }/registry`,
  USERS:            `${ API_BASE }/users`,
  GROUPS:           `${ API_BASE }/groups`,
  PLUGINS:          `${ API_BASE }/plugins`,
  DISCOVERY:        `${ API_BASE }/discovery`,
  AGENTS:           `${ API_BASE }/agents`,
  VROUTES:          `${ API_BASE }/vroutes`,
} as const;

let cachedServiceLoc: ServiceLocation | null = null;
let cachedDirectUrl:  string | null = null;

function readLS(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeLS(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
}

export function getServiceLocation(): ServiceLocation {
  if (cachedServiceLoc) {
    return cachedServiceLoc;
  }
  const raw = readLS(LOCAL_STORAGE_KEYS.SERVICE_LOCATION);
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Partial<ServiceLocation>;
      cachedServiceLoc = { ...DEFAULT_SERVICE_LOCATION, ...parsed };
      return cachedServiceLoc;
    } catch {
      /* fall through to default */
    }
  }
  cachedServiceLoc = { ...DEFAULT_SERVICE_LOCATION };
  return cachedServiceLoc;
}

export function setServiceLocation(loc: ServiceLocation) {
  cachedServiceLoc = { ...loc };
  writeLS(LOCAL_STORAGE_KEYS.SERVICE_LOCATION, JSON.stringify(cachedServiceLoc));
}

export function getDirectBackendUrl(): string {
  if (cachedDirectUrl !== null) {
    return cachedDirectUrl;
  }
  cachedDirectUrl = readLS(LOCAL_STORAGE_KEYS.DIRECT_BACKEND_URL) || '';
  return cachedDirectUrl;
}

export function setDirectBackendUrl(url: string) {
  cachedDirectUrl = url || '';
  writeLS(LOCAL_STORAGE_KEYS.DIRECT_BACKEND_URL, cachedDirectUrl);
}

// Compose the Rancher cluster-proxy URL for the configured Service.
// Returns a relative URL — axios resolves it against window.location.origin
// so the call stays same-origin HTTPS and rides the Rancher session.
export function buildProxyBaseUrl(loc: ServiceLocation = getServiceLocation()): string {
  return `/k8s/clusters/${ loc.cluster }/api/v1/namespaces/${ loc.namespace }/services/http:${ loc.name }:${ loc.port }/proxy`;
}

// Effective base URL used by the axios client. Direct URL wins when set.
export function resolveBaseUrl(): string {
  const direct = getDirectBackendUrl();
  if (direct) {
    return direct;
  }
  return buildProxyBaseUrl();
}

// Human-readable label of the current mode for the Settings/Home UI.
export function describeBaseUrl(): { mode: 'proxy' | 'direct'; url: string } {
  const direct = getDirectBackendUrl();
  if (direct) {
    return { mode: 'direct', url: direct };
  }
  return { mode: 'proxy', url: buildProxyBaseUrl() };
}
