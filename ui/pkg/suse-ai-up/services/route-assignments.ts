import { apiGet } from './base-api';
import { ENDPOINTS } from '../config/api-config';

export interface RouteAssignment {
  id:          string;
  serverId?:   string;
  userIds?:    string[];
  groupIds?:   string[];
  permissions?: string;
  autoSpawn?:  boolean;
}

export const routeAssignmentsApi = {
  list: () => apiGet<RouteAssignment[]>(ENDPOINTS.ROUTE_ASSIGNMENTS),
};
