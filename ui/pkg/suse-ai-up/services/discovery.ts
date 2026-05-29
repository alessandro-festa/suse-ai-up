import { apiDelete, apiGet, apiPost } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface ScanJob {
  jobId:  string;
  status: string;
  startedAt?: string;
  endedAt?:   string;
}

export interface DiscoveredServer {
  id:    string;
  name?: string;
  url?:  string;
}

export const discoveryApi = {
  scan:       (body?: unknown) => apiPost<ScanJob>(`${ ENDPOINTS.DISCOVERY }/scan`, body),
  listJobs:   () => apiGet<ScanJob[]>(`${ ENDPOINTS.DISCOVERY }/scan`),
  getJob:     (jobId: string) => apiGet<ScanJob>(`${ ENDPOINTS.DISCOVERY }/scan/${ jobId }`),
  cancelJob:  (jobId: string) => apiDelete<void>(`${ ENDPOINTS.DISCOVERY }/scan/${ jobId }`),
  listServers: () => apiGet<DiscoveredServer[]>(`${ ENDPOINTS.DISCOVERY }/servers`),
  results:    () => apiGet<unknown>(`${ ENDPOINTS.DISCOVERY }/results`),
};
