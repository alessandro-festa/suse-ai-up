import { apiDelete, apiGet, apiPost } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface PluginService {
  id:          string;
  name:        string;
  type:        string;
  status?:     string;
  endpoints?: Record<string, string>;
}

export const pluginsApi = {
  list:           () => apiGet<PluginService[]>(`${ ENDPOINTS.PLUGINS }/services`),
  get:            (id: string) => apiGet<PluginService>(`${ ENDPOINTS.PLUGINS }/services/${ id }`),
  listByType:     (type: string) => apiGet<PluginService[]>(`${ ENDPOINTS.PLUGINS }/services/type/${ type }`),
  health:         (id: string) => apiGet<{ healthy: boolean }>(`${ ENDPOINTS.PLUGINS }/services/${ id }/health`),
  register:       (body: Partial<PluginService>) => apiPost<PluginService>(`${ ENDPOINTS.PLUGINS }/register`, body),
  unregister:     (id: string) => apiDelete<void>(`${ ENDPOINTS.PLUGINS }/register/${ id }`),
};
