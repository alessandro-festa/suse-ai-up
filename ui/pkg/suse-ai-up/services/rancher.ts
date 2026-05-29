// Rancher RBAC read client. Hits the dashboard's own host (same-origin),
// so the browser sends Rancher's session cookie automatically. Used by
// Settings (read-only Users/Groups tabs in Rancher mode) and the adapter
// ACL picker. No write paths in v1.
//
// Endpoints:
//   GET /v1/management.cattle.io.users           (Steve API, canonical user list)
//   GET /v3/principals?type=group                (Norman API, group principals from external IDPs)
//   GET /v1/management.cattle.io.globalrolebindings   (admin detection)
//   GET /v3/me                                   (current dashboard user)
//
// All read-only. 403 means the dashboard user lacks `get` on the
// underlying CRD — surface that as an inline banner upstream.

import axios, { AxiosInstance } from 'axios';

export interface RancherUser {
  id:          string;        // metadata.name (Rancher's internal user id, e.g. u-abc123)
  name:        string;        // display name; falls back to username, then id
  username:    string;
  enabled:     boolean;
  principalIds: string[];     // e.g. ["local://u-abc123", "github_user://octocat"]
}

export interface RancherGroupPrincipal {
  id:        string;          // principalId, e.g. "keycloak_group://mcp-admins"
  name:      string;          // displayName, e.g. "MCP Admins"
  provider:  string;          // providerType, e.g. "keycloak"
  loginName?: string;
}

export interface GlobalRoleBinding {
  userName: string;           // metadata.name of the bound user
  roleName: string;           // e.g. "admin", "restricted-admin", "user", "user-base"
}

export interface CurrentPrincipal {
  id:       string;           // principalId
  name:     string;           // displayName
  loginName: string;
  me:       boolean;
}

const TIMEOUT_MS = 15_000;

function rancherClient(): AxiosInstance {
  return axios.create({
    // Relative — browser uses window.location.origin so the Rancher
    // session cookie travels with each request automatically.
    baseURL: '/',
    timeout: TIMEOUT_MS,
    // We don't set Authorization; the session cookie is httpOnly and
    // handled by the browser. CSRF for Rancher /v3 mutations would
    // need its own header, but we're read-only here.
    withCredentials: true,
    headers: { Accept: 'application/json' },
  });
}

const client = rancherClient();

// -------------------------------------------------- Users (Steve)

interface SteveListResponse<T> {
  data: T[];
}
interface SteveUser {
  id:   string;
  type: string;
  metadata: { name: string; uid?: string };
  spec?: { username?: string; displayName?: string; enabled?: boolean };
  principalIds?: string[];
}

export async function listUsers(): Promise<RancherUser[]> {
  const res = await client.get<SteveListResponse<SteveUser>>('/v1/management.cattle.io.users');
  const items = res.data?.data || [];
  return items.map((u) => ({
    id:           u.metadata?.name || u.id,
    name:         u.spec?.displayName || u.spec?.username || u.metadata?.name || u.id,
    username:     u.spec?.username || '',
    enabled:      u.spec?.enabled !== false,
    principalIds: u.principalIds || [],
  }));
}

// -------------------------------------------------- Group principals (Norman)

interface NormanCollection<T> {
  data: T[];
}
interface NormanPrincipal {
  id:           string;
  type:         string;
  principalType?: string;
  displayName?: string;
  loginName?:   string;
  provider?:    string;
}

export async function listGroupPrincipals(): Promise<RancherGroupPrincipal[]> {
  const res = await client.get<NormanCollection<NormanPrincipal>>('/v3/principals', {
    params: { type: 'group' },
  });
  const items = res.data?.data || [];
  return items.map((p) => ({
    id:        p.id,
    name:      p.displayName || p.loginName || p.id,
    provider:  p.provider || '',
    loginName: p.loginName,
  }));
}

// -------------------------------------------------- Global role bindings

interface SteveGlobalRoleBinding {
  id:   string;
  type: string;
  metadata: { name: string };
  userName?:        string;     // user reference
  groupPrincipalName?: string;  // group reference (for IDP groups)
  globalRoleName:   string;     // "admin", etc.
}

export async function listGlobalRoleBindings(): Promise<GlobalRoleBinding[]> {
  const res = await client.get<SteveListResponse<SteveGlobalRoleBinding>>(
    '/v1/management.cattle.io.globalrolebindings',
  );
  const items = res.data?.data || [];
  return items
    .filter((b) => !!b.userName && !!b.globalRoleName)
    .map((b) => ({ userName: b.userName as string, roleName: b.globalRoleName }));
}

// -------------------------------------------------- Current principal (/v3/me)

export async function currentPrincipal(): Promise<CurrentPrincipal | null> {
  try {
    const res = await client.get<NormanCollection<NormanPrincipal & { me?: boolean }>>('/v3/principals', {
      params: { me: 'true' },
    });
    const p = (res.data?.data || []).find((x) => x.me) || (res.data?.data || [])[0];
    if (!p) return null;
    return {
      id:        p.id,
      name:      p.displayName || p.loginName || p.id,
      loginName: p.loginName || '',
      me:        true,
    };
  } catch {
    return null;
  }
}

// Helper: index global-role bindings by user name so a caller can
// quickly look up the set of roles per Rancher user (used to compute
// the "Admin" pill and feed identity.localGroupsFor).
export function indexGlobalRoles(bindings: GlobalRoleBinding[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const b of bindings) {
    if (!out[b.userName]) out[b.userName] = [];
    if (!out[b.userName].includes(b.roleName)) out[b.userName].push(b.roleName);
  }
  return out;
}
