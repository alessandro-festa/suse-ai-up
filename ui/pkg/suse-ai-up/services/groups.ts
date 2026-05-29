import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface Group {
  id:       string;
  name:     string;
  members?: string[];
}

export const groupsApi = {
  list:         () => apiGet<Group[]>(ENDPOINTS.GROUPS),
  get:          (id: string) => apiGet<Group>(`${ ENDPOINTS.GROUPS }/${ id }`),
  create:       (body: Partial<Group>) => apiPost<Group>(ENDPOINTS.GROUPS, body),
  update:       (id: string, body: Partial<Group>) => apiPut<Group>(`${ ENDPOINTS.GROUPS }/${ id }`, body),
  remove:       (id: string) => apiDelete<void>(`${ ENDPOINTS.GROUPS }/${ id }`),
  addMember:    (groupId: string, userId: string) =>
    apiPost<void>(`${ ENDPOINTS.GROUPS }/${ groupId }/members`, { userId }),
  removeMember: (groupId: string, userId: string) =>
    apiDelete<void>(`${ ENDPOINTS.GROUPS }/${ groupId }/members/${ userId }`),
};
