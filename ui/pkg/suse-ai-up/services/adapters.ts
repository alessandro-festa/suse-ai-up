import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface Adapter {
  name:        string;
  displayName?: string;
  description?: string;
  version?:    string;
  status?:     string;
  [key: string]: unknown;
}

export const adaptersApi = {
  list:        () => apiGet<Adapter[]>(ENDPOINTS.ADAPTERS),
  get:         (name: string) => apiGet<Adapter>(`${ ENDPOINTS.ADAPTERS }/${ name }`),
  create:      (body: Partial<Adapter>) => apiPost<Adapter>(ENDPOINTS.ADAPTERS, body),
  update:      (name: string, body: Partial<Adapter>) =>
    apiPut<Adapter>(`${ ENDPOINTS.ADAPTERS }/${ name }`, body),
  remove:      (name: string) => apiDelete<void>(`${ ENDPOINTS.ADAPTERS }/${ name }`),
  health:      (name: string) => apiPost<{ healthy: boolean }>(`${ ENDPOINTS.ADAPTERS }/${ name }/health`),
  sync:        (name: string) => apiPost<void>(`${ ENDPOINTS.ADAPTERS }/${ name }/sync`),
  tools:       (name: string) => apiGet<unknown[]>(`${ ENDPOINTS.ADAPTERS }/${ name }/tools`),
  resources:   (name: string) => apiGet<unknown[]>(`${ ENDPOINTS.ADAPTERS }/${ name }/resources`),
  prompts:     (name: string) => apiGet<unknown[]>(`${ ENDPOINTS.ADAPTERS }/${ name }/prompts`),
};
