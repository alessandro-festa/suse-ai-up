// Namespaced Vuex module for the extension. Tracks auth state, the
// service-location configuration that drives the Rancher cluster proxy
// URL (plus an optional direct-URL override for local dev), and a
// transient error-banner slice.

import { LOCAL_STORAGE_KEYS } from '../config/storage';
import {
  ServiceLocation,
  DEFAULT_SERVICE_LOCATION,
  getServiceLocation,
  setServiceLocation,
  getDirectBackendUrl,
  setDirectBackendUrl,
  describeBaseUrl,
} from '../config/api-config';

export interface AuthState {
  token: string | null;
  user:  { id: string; name: string; email?: string; groups?: string[] } | null;
  mode:  string | null;
}

export interface ErrorBanner {
  id:      number;
  message: string;
  tone:    'error' | 'warning' | 'info';
}

export interface SuseAiUpState {
  auth:             AuthState;
  serviceLocation:  ServiceLocation;
  directBackendUrl: string;
  banners:          ErrorBanner[];
  nextBannerId:     number;
}

function loadToken(): string | null {
  try {
    return window.localStorage.getItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
  } catch {
    return null;
  }
}

export default {
  namespaced: true,

  state(): SuseAiUpState {
    return {
      auth: {
        token: loadToken(),
        user:  null,
        mode:  null,
      },
      serviceLocation:  getServiceLocation(),
      directBackendUrl: getDirectBackendUrl(),
      banners:          [],
      nextBannerId:     1,
    };
  },

  getters: {
    isAuthenticated: (s: SuseAiUpState) => !!s.auth.token,
    serviceLocation: (s: SuseAiUpState) => s.serviceLocation,
    directBackendUrl: (s: SuseAiUpState) => s.directBackendUrl,
    effectiveBaseUrl: () => describeBaseUrl(),
    banners:         (s: SuseAiUpState) => s.banners,
  },

  mutations: {
    setToken(s: SuseAiUpState, token: string | null) {
      s.auth.token = token;
      try {
        if (token) {
          window.localStorage.setItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN, token);
        } else {
          window.localStorage.removeItem(LOCAL_STORAGE_KEYS.AUTH_TOKEN);
        }
      } catch {
        /* ignore */
      }
    },
    setUser(s: SuseAiUpState, user: AuthState['user']) {
      s.auth.user = user;
    },
    setAuthMode(s: SuseAiUpState, mode: string | null) {
      s.auth.mode = mode;
    },
    setServiceLocation(s: SuseAiUpState, loc: ServiceLocation) {
      s.serviceLocation = { ...DEFAULT_SERVICE_LOCATION, ...loc };
      setServiceLocation(s.serviceLocation);
    },
    setDirectBackendUrl(s: SuseAiUpState, url: string) {
      s.directBackendUrl = url || '';
      setDirectBackendUrl(s.directBackendUrl);
    },
    pushBanner(s: SuseAiUpState, banner: Omit<ErrorBanner, 'id'>) {
      s.banners.push({ id: s.nextBannerId++, ...banner });
    },
    dismissBanner(s: SuseAiUpState, id: number) {
      s.banners = s.banners.filter((b) => b.id !== id);
    },
  },

  actions: {
    reportError({ commit }: { commit: Function }, payload: { message: string; tone?: ErrorBanner['tone'] }) {
      commit('pushBanner', { message: payload.message, tone: payload.tone || 'error' });
    },
    signOut({ commit }: { commit: Function }) {
      commit('setToken', null);
      commit('setUser', null);
    },
  },
};
