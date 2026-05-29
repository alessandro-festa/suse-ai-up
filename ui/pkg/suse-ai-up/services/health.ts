import { apiGet } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface HealthResponse {
  status:    string;
  timestamp: string;
  version?:  string;
}

export const healthApi = {
  check: () => apiGet<HealthResponse>(ENDPOINTS.HEALTH),
};
