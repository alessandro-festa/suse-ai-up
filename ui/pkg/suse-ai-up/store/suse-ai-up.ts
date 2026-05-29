// Namespaced Vuex module for the extension. Tracks auth state, the
// configured backend URL, and a transient error-banner slice.

import { LOCAL_STORAGE_KEYS } from '../config/storage';
import { setBackendUrl, getBackendUrl } from '../config/api-config';

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
  auth:        AuthState;
  backendUrl:  string;
  banners:     ErrorBanner[];
  nextBannerId: number;
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
      backendUrl:   getBackendUrl(),
      banners:      [],
      nextBannerId: 1,
    };
  },

  getters: {
    isAuthenticated: (s: SuseAiUpState) => !!s.auth.token,
    backendUrl:      (s: SuseAiUpState) => s.backendUrl,
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
    setBackendUrl(s: SuseAiUpState, url: string) {
      s.backendUrl = url;
      setBackendUrl(url);
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
