<template>
  <AiUpPage
    title="Registry Sources"
    subtitle="Manage external MCP registries that feed MCPServer entries into the cluster"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search sources..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openCreate">+ New source</button>
        <button class="ai-up-btn ai-up-btn--ghost" @click="openWellKnown">Add Official</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">
      Failed to load registry sources: {{ error }}
    </div>

    <div v-if="loading && !sources.length" class="ai-up-empty">Loading registry sources...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No registry sources match "{{ search }}".</p>
      <p v-else>No registry sources yet. Add an official registry or create a custom source.</p>
    </div>

    <AiUpGallery v-else>
      <AiUpCard
        v-for="s in filtered"
        :key="s.name"
        :title="s.name"
        :subtitle="s.url || (s.configMapRef ? `ConfigMap: ${s.configMapRef}` : '')"
      >
        <template #pill>
          <AiUpPill :tone="phaseTone(s.phase)" :label="s.phase || 'Pending'" />
        </template>
        <template #meta>
          <span v-if="s.format">Format: <code>{{ s.format || 'yaml' }}</code></span>
          <span>Servers: {{ s.serverCount }}</span>
          <span>Priority: {{ s.priority }}</span>
          <span v-if="s.refreshInterval">Refresh: {{ s.refreshInterval }}</span>
          <span v-if="s.lastSyncTime">Last sync: {{ relativeTime(s.lastSyncTime) }}</span>
        </template>
        <div v-if="s.syncError" class="ai-up-banner ai-up-banner--error sync-error">
          {{ s.syncError }}
        </div>
        <template #actions>
          <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === s.name" @click="confirmDelete(s)">
            {{ deleting === s.name ? 'Deleting...' : 'Delete' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <!-- Create modal -->
    <AiUpModal :open="creating" title="Create registry source" @close="closeCreate">
      <label class="ai-up-field">
        <span>Name <em>*</em></span>
        <input v-model="form.name" class="ai-up-input" placeholder="my-registry" />
      </label>
      <label class="ai-up-field">
        <span>Format</span>
        <select v-model="form.format" class="ai-up-input">
          <option value="">yaml (default)</option>
          <option value="mcp-registry-v0.1">mcp-registry-v0.1 (official JSON)</option>
        </select>
      </label>

      <div class="ai-up-fieldset">
        <div class="ai-up-fieldset__legend">Source</div>
        <div class="source-toggle">
          <label><input type="radio" v-model="form.sourceType" value="url" /> URL</label>
          <label><input type="radio" v-model="form.sourceType" value="configMap" /> ConfigMap</label>
        </div>
        <label v-if="form.sourceType === 'url'" class="ai-up-field">
          <span>URL <em>*</em></span>
          <input v-model="form.url" class="ai-up-input" placeholder="https://registry.example.com/servers" />
        </label>
        <label v-else class="ai-up-field">
          <span>ConfigMap name <em>*</em></span>
          <input v-model="form.configMapRef" class="ai-up-input" placeholder="my-registry-config" />
        </label>
      </div>

      <label class="ai-up-field">
        <span>Priority</span>
        <input v-model.number="form.priority" type="number" class="ai-up-input" placeholder="100" />
        <small class="ai-up-muted">Higher priority wins when two registries provide the same server name.</small>
      </label>
      <label class="ai-up-field">
        <span>Refresh interval</span>
        <input v-model="form.refreshInterval" class="ai-up-input" placeholder="5m" />
        <small class="ai-up-muted">Go duration (e.g. 5m, 1h, 30s). How often to re-sync from the source.</small>
      </label>

      <div v-if="createError" class="ai-up-banner ai-up-banner--error">{{ createError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeCreate">Cancel</button>
        <button type="button" class="ai-up-btn" :disabled="!canCreate || submitting" @click="submitCreate">
          {{ submitting ? 'Creating...' : 'Create source' }}
        </button>
      </template>
    </AiUpModal>

    <!-- Well-known picker modal -->
    <AiUpModal :open="pickingWellKnown" title="Add official registries" @close="closeWellKnown">
      <div v-if="wellKnownLoading" class="ai-up-empty">Loading registries...</div>
      <div v-else-if="wellKnownError" class="ai-up-banner ai-up-banner--error">{{ wellKnownError }}</div>
      <div v-else-if="!wellKnownSources.length" class="ai-up-empty">No well-known registries available.</div>
      <div v-else class="well-known-list">
        <label
          v-for="wk in wellKnownSources"
          :key="wk.name"
          class="well-known-item"
          :class="{ 'well-known-item--selected': selectedWellKnown.includes(wk.name) }"
        >
          <input
            type="checkbox"
            :value="wk.name"
            v-model="selectedWellKnown"
          />
          <div class="well-known-info">
            <strong>{{ wk.displayName }}</strong>
            <span class="ai-up-muted">{{ wk.description }}</span>
            <code class="ai-up-muted">{{ wk.url }}</code>
          </div>
        </label>
      </div>

      <div v-if="wellKnownCreateError" class="ai-up-banner ai-up-banner--error">{{ wellKnownCreateError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeWellKnown">Cancel</button>
        <button
          type="button"
          class="ai-up-btn"
          :disabled="!selectedWellKnown.length || addingWellKnown"
          @click="addSelectedWellKnown"
        >
          {{ addingWellKnown ? 'Adding...' : `Add ${ selectedWellKnown.length || '' } registr${ selectedWellKnown.length === 1 ? 'y' : 'ies' }` }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, reactive, computed, onMounted } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpModal from '../components/AiUpModal.vue';
import {
  registrySourcesApi,
  RegistrySource,
  WellKnownRegistrySource,
  CreateRegistrySourceRequest,
} from '../services/registry-sources';

export default defineComponent({
  name:       'RegistrySources',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal },
  setup() {
    const sources      = ref<RegistrySource[]>([]);
    const search       = ref('');
    const loading      = ref(false);
    const error        = ref<string | null>(null);
    const deleting     = ref<string | null>(null);

    // Create modal
    const creating     = ref(false);
    const submitting   = ref(false);
    const createError  = ref<string | null>(null);
    const form = reactive({
      name:            '',
      format:          '',
      sourceType:      'url' as 'url' | 'configMap',
      url:             '',
      configMapRef:    '',
      priority:        100,
      refreshInterval: '5m',
    });

    // Well-known picker
    const pickingWellKnown     = ref(false);
    const wellKnownLoading     = ref(false);
    const wellKnownError       = ref<string | null>(null);
    const wellKnownCreateError = ref<string | null>(null);
    const wellKnownSources     = ref<WellKnownRegistrySource[]>([]);
    const selectedWellKnown    = ref<string[]>([]);
    const addingWellKnown      = ref(false);

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return sources.value;
      return sources.value.filter((s) =>
        (s.name || '').toLowerCase().includes(q)
        || (s.url || '').toLowerCase().includes(q)
        || (s.format || '').toLowerCase().includes(q),
      );
    });

    const canCreate = computed(() => {
      if (!form.name.trim()) return false;
      if (form.sourceType === 'url' && !form.url.trim()) return false;
      if (form.sourceType === 'configMap' && !form.configMapRef.trim()) return false;
      return true;
    });

    function phaseTone(phase?: string): 'success' | 'error' | 'warning' | 'neutral' {
      if (!phase) return 'neutral';
      const v = phase.toLowerCase();
      if (v === 'ready') return 'success';
      if (v === 'failed') return 'error';
      if (v === 'syncing' || v === 'pending') return 'warning';
      return 'neutral';
    }

    function relativeTime(iso?: string): string {
      if (!iso) return '';
      const d = new Date(iso);
      const now = Date.now();
      const diffMs = now - d.getTime();
      if (diffMs < 0) return 'just now';
      const mins = Math.floor(diffMs / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${ mins }m ago`;
      const hours = Math.floor(mins / 60);
      if (hours < 24) return `${ hours }h ago`;
      const days = Math.floor(hours / 24);
      return `${ days }d ago`;
    }

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        sources.value = ((await registrySourcesApi.list()) || []) as RegistrySource[];
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    // --- Create modal ---

    function openCreate() {
      form.name            = '';
      form.format          = '';
      form.sourceType      = 'url';
      form.url             = '';
      form.configMapRef    = '';
      form.priority        = 100;
      form.refreshInterval = '5m';
      createError.value    = null;
      creating.value       = true;
    }

    function closeCreate() {
      creating.value = false;
    }

    async function submitCreate() {
      submitting.value  = true;
      createError.value = null;
      try {
        const req: CreateRegistrySourceRequest = {
          name:            form.name.trim(),
          format:          form.format || undefined,
          url:             form.sourceType === 'url' ? form.url.trim() : undefined,
          configMapRef:    form.sourceType === 'configMap' ? form.configMapRef.trim() : undefined,
          priority:        form.priority || 100,
          refreshInterval: form.refreshInterval.trim() || undefined,
        };
        await registrySourcesApi.create(req);
        closeCreate();
        await refresh();
      } catch (e: any) {
        createError.value = e?.data?.error || e?.message || 'Create failed';
      } finally {
        submitting.value = false;
      }
    }

    // --- Well-known picker ---

    async function openWellKnown() {
      pickingWellKnown.value     = true;
      wellKnownLoading.value     = true;
      wellKnownError.value       = null;
      wellKnownCreateError.value = null;
      selectedWellKnown.value    = [];
      try {
        wellKnownSources.value = ((await registrySourcesApi.wellKnown()) || []) as WellKnownRegistrySource[];
      } catch (e: any) {
        wellKnownError.value = e?.message || 'Failed to load well-known registries';
      } finally {
        wellKnownLoading.value = false;
      }
    }

    function closeWellKnown() {
      pickingWellKnown.value = false;
    }

    async function addSelectedWellKnown() {
      addingWellKnown.value      = true;
      wellKnownCreateError.value = null;
      try {
        const errors: string[] = [];
        for (const name of selectedWellKnown.value) {
          const wk = wellKnownSources.value.find((w) => w.name === name);
          if (!wk) continue;
          try {
            await registrySourcesApi.create({
              name:   wk.name,
              format: wk.format,
              url:    wk.url,
            });
          } catch (e: any) {
            const msg = e?.data?.error || e?.message || 'unknown error';
            if (!msg.includes('already exists')) {
              errors.push(`${ wk.displayName }: ${ msg }`);
            }
          }
        }
        if (errors.length) {
          wellKnownCreateError.value = errors.join('; ');
        } else {
          closeWellKnown();
        }
        await refresh();
      } finally {
        addingWellKnown.value = false;
      }
    }

    // --- Delete ---

    async function confirmDelete(s: RegistrySource) {
      if (!window.confirm(`Delete registry source "${ s.name }"? This will also remove all its child MCPServer entries.`)) return;
      deleting.value = s.name;
      try {
        await registrySourcesApi.remove(s.name);
        await refresh();
      } catch (e: any) {
        error.value = e?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    onMounted(refresh);

    return {
      sources, search, loading, error, deleting,
      creating, submitting, createError,
      form, filtered, canCreate,
      pickingWellKnown, wellKnownLoading, wellKnownError, wellKnownCreateError,
      wellKnownSources, selectedWellKnown, addingWellKnown,
      phaseTone, relativeTime,
      refresh, openCreate, closeCreate, submitCreate,
      openWellKnown, closeWellKnown, addSelectedWellKnown,
      confirmDelete,
    };
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-btn {
  padding:       6px 12px;
  border-radius: 6px;
  border:        1px solid var(--primary, #1d4ed8);
  background:    var(--primary, #1d4ed8);
  color:         #fff;
  font-size:     13px;
  cursor:        pointer;
}
.ai-up-btn:disabled { opacity: 0.55; cursor: not-allowed; }
.ai-up-btn--ghost   { background: transparent; color: var(--primary, #1d4ed8); }
.ai-up-btn--danger  { border-color: var(--error, #dc2626); background: transparent; color: var(--error, #dc2626); }

.ai-up-field {
  display:        flex;
  flex-direction: column;
  gap:            4px;
  font-size:      12px;
  color:          var(--muted, #888);
}
.ai-up-field em {
  color:      var(--error, #dc2626);
  font-style: normal;
  margin:     0 4px;
}
.ai-up-input {
  padding:       6px 10px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  background:    var(--body-bg, #fff);
  color:         var(--body-text, #333);
  font-size:     13px;
}

.ai-up-fieldset {
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  padding:        10px 12px 12px;
  display:        flex;
  flex-direction: column;
  gap:            8px;
}
.ai-up-fieldset__legend {
  font-size:    12px;
  font-weight:  600;
  color:        var(--body-text, #333);
  margin-bottom: 2px;
}

.source-toggle {
  display: flex;
  gap:     16px;
  font-size: 13px;
  color:   var(--body-text, #333);
  label { display: flex; align-items: center; gap: 4px; cursor: pointer; }
}

.ai-up-banner {
  padding:       8px 10px;
  border-radius: 6px;
  font-size:     12px;
}
.ai-up-banner--error {
  background: var(--error-banner-bg, rgba(220, 38, 38, 0.1));
  color:      var(--error, #dc2626);
  border:     1px solid var(--error, #dc2626);
}
.sync-error {
  margin-top: 6px;
  font-size:  11px;
}
.ai-up-empty {
  padding:    20px;
  text-align: center;
  color:      var(--muted, #888);
  font-size:  13px;
}
.ai-up-muted {
  color:     var(--muted, #888);
  font-size: 12px;
  margin:    0;
}
.ai-up-truncate {
  display:       inline-block;
  max-width:     100%;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
  font-family:   var(--font-mono, monospace);
}

.well-known-list {
  display:        flex;
  flex-direction: column;
  gap:            8px;
}
.well-known-item {
  display:       flex;
  align-items:   flex-start;
  gap:           10px;
  padding:       10px 12px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  cursor:        pointer;
  transition:    border-color 0.15s;
  &:hover { border-color: var(--primary, #1d4ed8); }
  &--selected { border-color: var(--primary, #1d4ed8); background: rgba(29, 78, 216, 0.04); }
  input[type="checkbox"] { margin-top: 3px; }
}
.well-known-info {
  display:        flex;
  flex-direction: column;
  gap:            2px;
  strong { font-size: 13px; color: var(--body-text, #333); }
  code { font-size: 11px; word-break: break-all; }
}
</style>
