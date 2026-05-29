// Single axios instance used by every typed service module. Handles
// dynamic baseURL resolution (Rancher proxy vs direct backend), Bearer
// token injection, and a thin 401/5xx error envelope.

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { resolveBaseUrl } from '../config/api-config';
import { LOCAL_STORAGE_KEYS } from '../config/storage';

export interface ApiError extends Error {
  status?: number;
  data?:   unknown;
}

const TIMEOUT_MS = 15_000;

function buildClient(): AxiosInstance {
  const client = axios.create({
    baseURL: resolveBaseUrl(),
    timeout: TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
  });

  client.interceptors.request.use((cfg) => {
    cfg.baseURL = resolveBaseUrl();
    try {
      const token = window.localStorage.getItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
      if (token) {
        cfg.headers = cfg.headers || {};
        // Send via X-Api-Token, NOT Authorization. When the dashboard
        // proxies through `/k8s/clusters/<id>/.../proxy/`, Rancher
        // validates the standard Authorization header against its own
        // user store and rejects any non-Rancher Bearer JWT with 401
        // before the request even reaches our backend. Our middleware
        // (pkg/auth/user_middleware.go) accepts either header.
        (cfg.headers as Record<string, string>)['X-Api-Token'] = token;
      }
    } catch {
      /* ignore */
    }
    return cfg;
  });

  client.interceptors.response.use(
    (res) => res,
    (err) => {
      const status = err?.response?.status;
      if (status === 401) {
        try {
          window.localStorage.removeItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
        } catch {
          /* ignore */
        }
        window.dispatchEvent(new CustomEvent('suse-ai-up:auth-required'));
      }
      const wrapped: ApiError = new Error(err?.message || 'Request failed');
      wrapped.status = status;
      wrapped.data   = err?.response?.data;
      return Promise.reject(wrapped);
    },
  );

  return client;
}

const client = buildClient();

export async function apiGet<T>(path: string, cfg?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await client.get(path, cfg);
  return res.data;
}

export async function apiPost<T>(path: string, body?: unknown, cfg?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await client.post(path, body, cfg);
  return res.data;
}

export async function apiPut<T>(path: string, body?: unknown, cfg?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await client.put(path, body, cfg);
  return res.data;
}

export async function apiDelete<T>(path: string, cfg?: AxiosRequestConfig): Promise<T> {
  const res: AxiosResponse<T> = await client.delete(path, cfg);
  return res.data;
}
