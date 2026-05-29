import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface MCPServer {
  id:          string;
  name?:       string;
  description?: string;
  version?:    string;
  image?:      string;
  url?:        string;
  routeAssignments?: RouteAssignment[];
  [key: string]: unknown;
}

export interface RouteAssignment {
  id:          string;
  serverID:    string;
  userIDs?:    string[];
  groupIDs?:   string[];
  autoSpawn?:  boolean;
  permissions: 'read' | 'write' | 'admin';
}

export interface GitUploadRequest {
  url:     string;
  token?:  string;
  branch?: string;
  path?:   string;
}

export interface CreateRouteAssignmentRequest {
  userIds?:    string[];
  groupIds?:   string[];
  autoSpawn?:  boolean;
  permissions: 'read' | 'write' | 'admin';
}

// The bulk endpoint takes a raw array of UploadRegistryEntryRequest.
// See internal/handlers/registry_upload.go:UploadBulkRegistryEntries.
export const registryApi = {
  list:           () => apiGet<MCPServer[]>(ENDPOINTS.REGISTRY),
  browse:         () => apiGet<MCPServer[]>(`${ ENDPOINTS.REGISTRY }/browse`),
  get:            (id: string) => apiGet<MCPServer>(`${ ENDPOINTS.REGISTRY }/${ id }`),
  upload:         (body: Partial<MCPServer>) => apiPost<MCPServer>(`${ ENDPOINTS.REGISTRY }/upload`, body),
  uploadBulk:     (entries: Partial<MCPServer>[]) =>
    apiPost<{ count: number; message?: string }>(`${ ENDPOINTS.REGISTRY }/upload/bulk`, entries),
  uploadGit:      (body: GitUploadRequest) =>
    apiPost<{ count: number; message?: string }>(`${ ENDPOINTS.REGISTRY }/upload/git`, body),
  uploadLocalMcp: (body: unknown) => apiPost<MCPServer>(`${ ENDPOINTS.REGISTRY }/upload/local-mcp`, body),
  reload:         () => apiPost<void>(`${ ENDPOINTS.REGISTRY }/reload`),
  update:         (id: string, body: Partial<MCPServer>) =>
    apiPut<MCPServer>(`${ ENDPOINTS.REGISTRY }/${ id }`, body),
  remove:         (id: string) => apiDelete<void>(`${ ENDPOINTS.REGISTRY }/${ id }`),
  listRoutes:     (id: string) => apiGet<RouteAssignment[]>(`${ ENDPOINTS.REGISTRY }/${ id }/routes`),
  createRouteAssignment: (serverId: string, body: CreateRouteAssignmentRequest) =>
    apiPost<RouteAssignment>(`${ ENDPOINTS.REGISTRY }/${ serverId }/routes`, body),
};
