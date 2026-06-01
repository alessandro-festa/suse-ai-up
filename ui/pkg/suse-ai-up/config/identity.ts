// Identity-provider preference + Rancher role mapping rules.
//
// V1 supports two modes:
//
//   - 'local'  → Settings → Users/Groups, the adapter ACL picker, and
//                everything else use the suse-ai-up backend's own
//                User/Group CRDs. Sign-in is the local admin login.
//   - 'rancher' → Users / Groups are read directly from Rancher's
//                 Steve and Norman APIs (same-origin, session-cookie
//                 auth, no extra credentials). Adapter ACLs reference
//                 the Rancher principal IDs verbatim. Read-only in v1;
//                 the local admin JWT is still required for mutations.
//
// The choice is persisted in localStorage and chosen on first Settings
// load via a modal. It can be changed later from the Identity tab.

import { LOCAL_STORAGE_KEYS } from './storage';

export type IdentityProvider = 'local' | 'rancher';

export interface RoleMapRule {
  // Either a principal ID (e.g. `keycloak_user://abc`, `local://u-xyz`,
  // `group:keycloak_admins`) or a global-role name (`admin`,
  // `restricted-admin`, etc.) depending on `sourceKind`.
  source:     string;
  sourceKind: 'globalRole' | 'principal';
  // Local group name to grant membership in (e.g. `mcp-admins`).
  target:     string;
}

// Seeded the first time Rancher mode is enabled — matches the rule the
// user asked for ("Rancher admin → MCP Admin group by default").
export const IDENTITY_DEFAULT_RULES: RoleMapRule[] = [
  { source: 'admin', sourceKind: 'globalRole', target: 'mcp-admins' },
];

// `null` means "not yet decided" — triggers the first-login modal.
// Callers should treat null as 'local' for behavior purposes.
export function getIdentityProvider(): IdentityProvider | null {
  try {
    const raw = window.localStorage.getItem(LOCAL_STORAGE_KEYS.IDENTITY_PROVIDER);
    if (raw === 'local' || raw === 'rancher') return raw;
    return null;
  } catch {
    return null;
  }
}

export function setIdentityProvider(v: IdentityProvider) {
  try {
    window.localStorage.setItem(LOCAL_STORAGE_KEYS.IDENTITY_PROVIDER, v);
  } catch { /* ignore */ }
}

export function getRancherRoleMap(): RoleMapRule[] {
  try {
    const raw = window.localStorage.getItem(LOCAL_STORAGE_KEYS.RANCHER_ROLE_MAP);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.filter((r) => r && typeof r.source === 'string' && typeof r.target === 'string'
          && (r.sourceKind === 'globalRole' || r.sourceKind === 'principal'));
      }
    }
  } catch { /* fall through to default */ }
  return [...IDENTITY_DEFAULT_RULES];
}

export function setRancherRoleMap(rules: RoleMapRule[]) {
  try {
    window.localStorage.setItem(LOCAL_STORAGE_KEYS.RANCHER_ROLE_MAP, JSON.stringify(rules));
  } catch { /* ignore */ }
}

// Convenience: given a list of admin global-role users (joined client-
// side from /globalrolebindings), and a Rancher principal/user id,
// return the set of local groups that should be associated with that
// principal per the active role-map rules.
export function localGroupsFor(
  principalId: string,
  globalRoles: string[],
  rules: RoleMapRule[] = getRancherRoleMap(),
): string[] {
  const out = new Set<string>();
  for (const rule of rules) {
    if (rule.sourceKind === 'globalRole' && globalRoles.includes(rule.source)) {
      out.add(rule.target);
    } else if (rule.sourceKind === 'principal' && principalId === rule.source) {
      out.add(rule.target);
    }
  }
  return Array.from(out);
}
