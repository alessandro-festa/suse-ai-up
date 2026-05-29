import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface User {
  id:           string;
  name:         string;
  email?:       string;
  authProvider?: string;
  groups?:      string[];
}

export const usersApi = {
  list:   () => apiGet<User[]>(ENDPOINTS.USERS),
  get:    (id: string) => apiGet<User>(`${ ENDPOINTS.USERS }/${ id }`),
  create: (body: Partial<User>) => apiPost<User>(ENDPOINTS.USERS, body),
  update: (id: string, body: Partial<User>) => apiPut<User>(`${ ENDPOINTS.USERS }/${ id }`, body),
  remove: (id: string) => apiDelete<void>(`${ ENDPOINTS.USERS }/${ id }`),
};
