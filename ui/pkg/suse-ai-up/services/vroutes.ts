import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

// Shapes match internal/handlers/vroutes_crud.go DTOs.

export interface VirtualMCPSelector {
  all?:    boolean;
  names?:  string[];
  prefix?: string;
  regex?:  string;
}

export interface VirtualMCPSourceRewrite {
  prefix?: string;
  suffix?: string;
}

export interface VirtualMCPSource {
  adapterName?:   string;
  mcpServerName?: string;
  tools?:         VirtualMCPSelector;
  resources?:     VirtualMCPSelector;
  prompts?:       VirtualMCPSelector;
  rewrite?:       VirtualMCPSourceRewrite;
}

export interface ResolvedEntry {
  name:             string;
  kind:             string; // "tool" | "resource" | "prompt"
  originalName?:    string;
  sourceAdapter?:   string;
  sourceMCPServer?: string;
}

export interface VirtualMCPRoute {
  name:             string;
  exposedAs?:       string;
  description?:     string;
  sources:          VirtualMCPSource[];
  acl:              string[];
  status:           string;
  phase?:           string;
  endpointURL?:     string;
  entryCount:       number;
  resolvedEntries?: ResolvedEntry[]; // only populated on GET /:name
  lastResolvedAt?:  string;
  createdAt:        string;
  createdBy?:       string;
}

export interface CreateVirtualMCPRouteRequest {
  name:         string;
  exposedAs?:   string;
  description?: string;
  sources:      VirtualMCPSource[];
  acl?:         string[];
}

export type UpdateVirtualMCPRouteRequest = Omit<CreateVirtualMCPRouteRequest, 'name'>;

export const vroutesApi = {
  list:   () => apiGet<VirtualMCPRoute[]>(ENDPOINTS.VROUTES),
  get:    (name: string) => apiGet<VirtualMCPRoute>(`${ ENDPOINTS.VROUTES }/${ name }`),
  create: (body: CreateVirtualMCPRouteRequest) => apiPost<VirtualMCPRoute>(ENDPOINTS.VROUTES, body),
  update: (name: string, body: UpdateVirtualMCPRouteRequest) =>
    apiPut<VirtualMCPRoute>(`${ ENDPOINTS.VROUTES }/${ name }`, body),
  remove: (name: string) => apiDelete<void>(`${ ENDPOINTS.VROUTES }/${ name }`),
};
