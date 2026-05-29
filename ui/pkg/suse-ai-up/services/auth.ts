import { apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';
import { LOCAL_STORAGE_KEYS } from '../config/storage';

export type AuthMode = 'local' | 'github' | 'rancher' | 'dev';

export interface AuthModeResponse {
  mode:     AuthMode;
  dev_mode: boolean;
  local?:   { default_admin_password?: string; force_password_change?: boolean; password_min_length?: number };
}

export interface AuthUser {
  id:           string;
  name:         string;
  email?:       string;
  groups?:      string[];
  authProvider?: string;
}

// Backend wire shapes — see internal/handlers/auth.go.
interface LoginRequestWire {
  user_id:  string;
  password: string;
}
interface LoginResponseWire {
  token: { token: string; tokenType?: string; expiresAt?: string; userID?: string; provider?: string };
  user:  AuthUser;
}

export const authApi = {
  mode:           () => apiGet<AuthModeResponse>(ENDPOINTS.AUTH_MODE),
  login:          async (userId: string, password: string): Promise<{ token: string; user: AuthUser }> => {
    const wire: LoginRequestWire = { user_id: userId, password };
    const resp = await apiPost<LoginResponseWire>(ENDPOINTS.AUTH_LOGIN, wire);
    return { token: resp.token?.token || '', user: resp.user };
  },
  logout:         () => apiPost<void>(ENDPOINTS.AUTH_LOGOUT),
  changePassword: (oldPwd: string, newPwd: string) =>
    apiPut<void>(ENDPOINTS.AUTH_PASSWORD, { oldPassword: oldPwd, newPassword: newPwd }),
};

// Local helpers that wrap the JWT-in-localStorage convention used by
// base-api.ts's request interceptor. Keeping read/write in one place
// avoids drift between Settings, the 401 banner, and any future sign-in
// surface.
export function setStoredToken(token: string | null) {
  try {
    if (token) window.localStorage.setItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN, token);
    else       window.localStorage.removeItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
  } catch { /* ignore */ }
}

export function getStoredToken(): string | null {
  try {
    return window.localStorage.getItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
  } catch {
    return null;
  }
}

export function setStoredUser(user: AuthUser | null) {
  try {
    if (user) window.localStorage.setItem(LOCAL_STORAGE_KEYS.AUTH_USER, JSON.stringify(user));
    else      window.localStorage.removeItem(LOCAL_STORAGE_KEYS.AUTH_USER);
  } catch { /* ignore */ }
}

export function getStoredUser(): AuthUser | null {
  try {
    const raw = window.localStorage.getItem(LOCAL_STORAGE_KEYS.AUTH_USER);
    return raw ? JSON.parse(raw) as AuthUser : null;
  } catch {
    return null;
  }
}
