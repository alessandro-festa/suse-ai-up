import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

// Shapes match internal/handlers/registry_sources_crud.go DTOs.

export interface RegistrySource {
  name:             string;
  format?:          string;
  url?:             string;
  configMapRef?:    string;
  priority:         number;
  refreshInterval?: string;
  phase?:           string;
  lastSyncTime?:    string;
  serverCount:      number;
  syncError?:       string;
  createdAt?:       string;
}

export interface CreateRegistrySourceRequest {
  name:             string;
  format?:          string;
  url?:             string;
  configMapRef?:    string;
  priority?:        number;
  refreshInterval?: string;
}

export interface WellKnownRegistrySource {
  name:        string;
  displayName: string;
  description: string;
  url:         string;
  format:      string;
  icon?:       string;
}

export const registrySourcesApi = {
  list:      () => apiGet<RegistrySource[]>(ENDPOINTS.REGISTRY_SOURCES),
  get:       (name: string) => apiGet<RegistrySource>(`${ ENDPOINTS.REGISTRY_SOURCES }/${ name }`),
  create:    (body: CreateRegistrySourceRequest) => apiPost<RegistrySource>(ENDPOINTS.REGISTRY_SOURCES, body),
  update:    (name: string, body: CreateRegistrySourceRequest) =>
    apiPut<RegistrySource>(`${ ENDPOINTS.REGISTRY_SOURCES }/${ name }`, body),
  remove:    (name: string) => apiDelete<void>(`${ ENDPOINTS.REGISTRY_SOURCES }/${ name }`),
  wellKnown: () => apiGet<WellKnownRegistrySource[]>(`${ ENDPOINTS.REGISTRY_SOURCES }/well-known`),
};
