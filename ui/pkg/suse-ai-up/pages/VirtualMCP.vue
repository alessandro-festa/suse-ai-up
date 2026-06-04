<template>
  <AiUpPage
    title="Virtual MCP"
    subtitle="Composed routes that aggregate tools across adapters"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search routes..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openCreate">+ New route</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">
      Failed to load virtual routes: {{ error }}
    </div>

    <div v-if="loading && !routes.length" class="ai-up-empty">Loading routes...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No routes match "{{ search }}".</p>
      <p v-else>No virtual routes yet. Create one to expose a composed MCP catalog.</p>
    </div>

    <AiUpGallery v-else>
      <AiUpCard
        v-for="r in filtered"
        :key="r.name"
        :title="r.name"
        :subtitle="r.description || ''"
      >
        <template #pill>
          <AiUpPill :tone="statusTone(r.status)" :label="r.status || 'unknown'" />
        </template>
        <template #meta>
          <span v-if="r.exposedAs">Exposed as: <code>{{ r.exposedAs }}</code></span>
          <span>Sources: {{ r.sources?.length || 0 }}</span>
          <span>Entries: {{ r.entryCount }}</span>
          <span v-if="r.endpointURL" class="ai-up-truncate">URL: {{ r.endpointURL }}</span>
        </template>
        <p v-if="r.createdBy" class="ai-up-muted">Created by: {{ r.createdBy }}</p>
        <template #actions>
          <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === r.name" @click="confirmDelete(r)">
            {{ deleting === r.name ? 'Deleting...' : 'Delete' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <AiUpModal :open="creating" title="Create virtual route" @close="closeCreate">
      <label class="ai-up-field">
        <span>Name <em>*</em></span>
        <input v-model="form.name" class="ai-up-input" placeholder="ops-route" />
      </label>
      <label class="ai-up-field">
        <span>Exposed as</span>
        <input v-model="form.exposedAs" class="ai-up-input" placeholder="(defaults to name)" />
        <small class="ai-up-muted">Path segment under <code>/api/v1/vroutes/</code>.</small>
      </label>
      <label class="ai-up-field">
        <span>Description</span>
        <input v-model="form.description" class="ai-up-input" placeholder="(optional)" />
      </label>

      <div class="ai-up-fieldset">
        <div class="ai-up-fieldset__legend">Sources <em>*</em></div>
        <p class="ai-up-muted">
          At least one source. Each source picks tools from an Adapter or MCPServer.
        </p>
        <div v-for="(s, idx) in form.sources" :key="idx" class="source-row">
          <div class="source-row__head">
            <select v-model="s.kind" class="ai-up-input">
              <option value="adapter">Adapter</option>
              <option value="mcpServer">MCPServer</option>
            </select>
            <select v-if="s.kind === 'adapter'" v-model="s.name" class="ai-up-input">
              <option value="">Select adapter…</option>
              <option v-for="a in adapterOptions" :key="a" :value="a">{{ a }}</option>
            </select>
            <select v-else v-model="s.name" class="ai-up-input">
              <option value="">Select MCP server…</option>
              <option v-for="m in mcpServerOptions" :key="m" :value="m">{{ m }}</option>
            </select>
            <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="removeSource(idx)">Remove</button>
          </div>
          <div class="source-row__selector">
            <span class="source-row__label">Tools selector</span>
            <select v-model="s.selectorMode" class="ai-up-input">
              <option value="all">All</option>
              <option value="names">Names (comma-separated)</option>
              <option value="prefix">Prefix</option>
              <option value="regex">Regex</option>
            </select>
            <input
              v-if="s.selectorMode !== 'all'"
              v-model="s.selectorValue"
              class="ai-up-input"
              :placeholder="selectorPlaceholder(s.selectorMode)"
            />
          </div>
        </div>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="addSource">+ Add source</button>
      </div>

      <label class="ai-up-field">
        <span>Access control (RouteAssignment names)</span>
        <small class="ai-up-muted">One assignment name per line. Leave empty for no per-route ACL.</small>
        <textarea v-model="aclText" class="ai-up-textarea" rows="2" placeholder="ops-route-admins" />
      </label>

      <div v-if="createError" class="ai-up-banner ai-up-banner--error">{{ createError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeCreate">Cancel</button>
        <button type="button" class="ai-up-btn" :disabled="!canCreate || submitting" @click="submitCreate">
          {{ submitting ? 'Creating...' : 'Create route' }}
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
  vroutesApi,
  VirtualMCPRoute,
  VirtualMCPSource,
  VirtualMCPSelector,
  CreateVirtualMCPRouteRequest,
} from '../services/vroutes';
import { adaptersApi } from '../services/adapters';
import { registryApi } from '../services/registry';

type SelectorMode = 'all' | 'names' | 'prefix' | 'regex';

interface SourceForm {
  kind:          'adapter' | 'mcpServer';
  name:          string;
  selectorMode:  SelectorMode;
  selectorValue: string;
}

function parseLines(text: string): string[] {
  return (text || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function buildSelector(mode: SelectorMode, value: string): VirtualMCPSelector | undefined {
  switch (mode) {
    case 'all':
      return { all: true };
    case 'names': {
      const names = value.split(',').map((s) => s.trim()).filter(Boolean);
      return names.length ? { names } : undefined;
    }
    case 'prefix':
      return value ? { prefix: value } : undefined;
    case 'regex':
      return value ? { regex: value } : undefined;
  }
}

export default defineComponent({
  name:       'VirtualMCP',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal },
  setup() {
    const routes      = ref<VirtualMCPRoute[]>([]);
    const search      = ref('');
    const loading     = ref(false);
    const error       = ref<string | null>(null);
    const deleting    = ref<string | null>(null);
    const creating    = ref(false);
    const submitting  = ref(false);
    const createError = ref<string | null>(null);

    const adapterOptions   = ref<string[]>([]);
    const mcpServerOptions = ref<string[]>([]);

    const form = reactive<{
      name: string;
      exposedAs: string;
      description: string;
      sources: SourceForm[];
    }>({
      name:        '',
      exposedAs:   '',
      description: '',
      sources:     [],
    });
    const aclText = ref('');

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return routes.value;
      return routes.value.filter((r) =>
        (r.name || '').toLowerCase().includes(q)
        || (r.description || '').toLowerCase().includes(q)
        || (r.exposedAs || '').toLowerCase().includes(q),
      );
    });

    const canCreate = computed(() =>
      !!form.name.trim()
      && form.sources.length > 0
      && form.sources.every((s) => !!s.name.trim()),
    );

    function statusTone(s?: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (!s) return 'neutral';
      const v = s.toLowerCase();
      if (v === 'ready') return 'success';
      if (v === 'error') return 'error';
      if (v === 'provisioning' || v === 'pending') return 'warning';
      return 'info';
    }

    function selectorPlaceholder(mode: SelectorMode): string {
      if (mode === 'names') return 'tool-a, tool-b';
      if (mode === 'prefix') return 'ops-';
      if (mode === 'regex') return '^read-.*';
      return '';
    }

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        routes.value = ((await vroutesApi.list()) || []) as VirtualMCPRoute[];
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    async function loadOptions() {
      try {
        const list = (await adaptersApi.list()) || [];
        adapterOptions.value = list.map((a: any) => a.name).filter(Boolean);
      } catch { adapterOptions.value = []; }
      try {
        const list = (await registryApi.list()) || [];
        mcpServerOptions.value = list.map((s: any) => s.id || s.name).filter(Boolean);
      } catch { mcpServerOptions.value = []; }
    }

    function openCreate() {
      form.name        = '';
      form.exposedAs   = '';
      form.description = '';
      form.sources     = [{ kind: 'adapter', name: '', selectorMode: 'all', selectorValue: '' }];
      aclText.value    = '';
      createError.value = null;
      creating.value   = true;
      loadOptions();
    }

    function closeCreate() {
      creating.value = false;
    }

    function addSource() {
      form.sources.push({ kind: 'adapter', name: '', selectorMode: 'all', selectorValue: '' });
    }

    function removeSource(idx: number) {
      form.sources.splice(idx, 1);
    }

    async function submitCreate() {
      submitting.value  = true;
      createError.value = null;
      try {
        const sources: VirtualMCPSource[] = form.sources.map((s) => {
          const src: VirtualMCPSource = {};
          if (s.kind === 'adapter') src.adapterName = s.name.trim();
          else                      src.mcpServerName = s.name.trim();
          const sel = buildSelector(s.selectorMode, s.selectorValue);
          if (sel) src.tools = sel;
          return src;
        });

        const req: CreateVirtualMCPRouteRequest = {
          name:        form.name.trim(),
          exposedAs:   form.exposedAs.trim() || undefined,
          description: form.description.trim() || undefined,
          sources,
          acl:         parseLines(aclText.value),
        };

        await vroutesApi.create(req);
        closeCreate();
        await refresh();
      } catch (e: any) {
        createError.value = e?.data?.error || e?.message || 'Create failed';
      } finally {
        submitting.value = false;
      }
    }

    async function confirmDelete(r: VirtualMCPRoute) {
      if (!window.confirm(`Delete virtual route "${ r.name }"?`)) return;
      deleting.value = r.name;
      try {
        await vroutesApi.remove(r.name);
        await refresh();
      } catch (e: any) {
        error.value = e?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    onMounted(refresh);

    return {
      routes, search, loading, error, deleting,
      creating, submitting, createError,
      form, aclText, adapterOptions, mcpServerOptions,
      filtered, canCreate,
      statusTone, selectorPlaceholder,
      refresh, openCreate, closeCreate, addSource, removeSource, submitCreate, confirmDelete,
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
.ai-up-input,
.ai-up-textarea {
  padding:       6px 10px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  background:    var(--body-bg, #fff);
  color:         var(--body-text, #333);
  font-size:     13px;
}
.ai-up-textarea { font-family: var(--font-mono, monospace); }

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
.source-row {
  display:        flex;
  flex-direction: column;
  gap:            6px;
  padding:        8px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
}
.source-row__head {
  display:               grid;
  grid-template-columns: 130px 1fr auto;
  gap:                   8px;
  align-items:           center;
}
.source-row__selector {
  display:     grid;
  grid-template-columns: auto 150px 1fr;
  gap:         8px;
  align-items: center;
}
.source-row__label {
  font-size: 11px;
  color:     var(--muted, #888);
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
</style>
