import { apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export type AuthMode = 'local' | 'github' | 'rancher' | 'dev';

export interface AuthModeResponse {
  mode:    AuthMode;
  enabled: boolean;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user:  { id: string; name: string; email: string; groups?: string[] };
}

export const authApi = {
  mode:           () => apiGet<AuthModeResponse>(ENDPOINTS.AUTH_MODE),
  login:          (req: LoginRequest) => apiPost<LoginResponse>(ENDPOINTS.AUTH_LOGIN, req),
  logout:         () => apiPost<void>(ENDPOINTS.AUTH_LOGOUT),
  changePassword: (oldPwd: string, newPwd: string) =>
    apiPut<void>('/auth/password', { oldPassword: oldPwd, newPassword: newPwd }),
};
