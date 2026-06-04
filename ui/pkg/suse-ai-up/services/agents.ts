import { apiDelete, apiGet, apiPost, apiPut } from './base-api';
import { ENDPOINTS } from '../config/api-config';

// Shapes match internal/handlers/agents_crud.go DTOs.

export interface AgentTool {
  adapterName?:         string;
  virtualMCPRouteName?: string;
}

export interface AgentRuntime {
  image?:    string;
  args?:     string[];
  env?:      Record<string, string>;
  port?:     number;
  replicas?: number;
}

export interface Agent {
  name:         string;
  protocol:     string;
  description?: string;
  tools:        AgentTool[];
  runtime?:     AgentRuntime;
  acl:          string[];
  status:       string; // "ready" | "provisioning" | "error" | "pending"
  phase?:       string;
  mode?:        string;
  endpointURL?: string;
  createdAt:    string;
  createdBy?:   string;
}

export interface CreateAgentRequest {
  name:         string;
  protocol:     string;
  description?: string;
  tools?:       AgentTool[];
  runtime?:     AgentRuntime;
  acl?:         string[];
}

export type UpdateAgentRequest = Omit<CreateAgentRequest, 'name' | 'protocol'>;

export const agentsApi = {
  list:   () => apiGet<Agent[]>(ENDPOINTS.AGENTS),
  get:    (name: string) => apiGet<Agent>(`${ ENDPOINTS.AGENTS }/${ name }`),
  create: (body: CreateAgentRequest) => apiPost<Agent>(ENDPOINTS.AGENTS, body),
  update: (name: string, body: UpdateAgentRequest) =>
    apiPut<Agent>(`${ ENDPOINTS.AGENTS }/${ name }`, body),
  remove: (name: string) => apiDelete<void>(`${ ENDPOINTS.AGENTS }/${ name }`),
};
