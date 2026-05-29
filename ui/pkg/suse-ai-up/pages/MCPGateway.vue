<template>
  <AiUpPage
    title="MCP Gateway"
    subtitle="Adapters that proxy MCP servers to clients"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search adapters..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openCreate">+ New adapter</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">
      Failed to load adapters: {{ error }}
    </div>

    <div v-if="loading && !adapters.length" class="ai-up-empty">Loading adapters...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No adapters match "{{ search }}".</p>
      <p v-else>No adapters yet. Create one to proxy an MCP server.</p>
    </div>

    <AiUpGallery v-else>
      <AiUpCard
        v-for="a in filtered"
        :key="a.id || a.name"
        :title="a.name"
        :subtitle="a.description || ''"
      >
        <template #pill>
          <AiUpPill :tone="statusTone(a.status)" :label="a.status || 'unknown'" />
        </template>
        <template #meta>
          <span v-if="a.url" class="ai-up-truncate">URL: {{ a.url }}</span>
          <span v-if="a.mcpServerId">From: {{ a.mcpServerId }}</span>
        </template>
        <p v-if="a.id" class="ai-up-muted">ID: <code>{{ a.id }}</code></p>
        <template #actions>
          <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === a.name" @click="confirmDelete(a)">
            {{ deleting === a.name ? 'Deleting...' : 'Delete' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <AiUpModal :open="creating" title="Create adapter" @close="closeCreate">
      <label class="ai-up-field">
        <span>Name <em>*</em></span>
        <input v-model="form.name" class="ai-up-input" placeholder="my-adapter" />
      </label>
      <label class="ai-up-field">
        <span>MCP Server ID <em>*</em></span>
        <select v-if="registryEntries.length" v-model="form.mcpServerId" class="ai-up-input">
          <option value="" disabled>Select a registry entry</option>
          <option v-for="r in registryEntries" :key="r.id" :value="r.id">{{ r.id }}{{ r.name ? ` — ${r.name}` : '' }}</option>
        </select>
        <input v-else v-model="form.mcpServerId" class="ai-up-input" placeholder="weather-mcp" />
        <small class="ai-up-muted">Must match an existing entry from MCP Registry.</small>
      </label>
      <label class="ai-up-field">
        <span>Description</span>
        <input v-model="form.description" class="ai-up-input" placeholder="(optional)" />
      </label>
      <label class="ai-up-field">
        <span>Environment variables (one per line, KEY=value)</span>
        <textarea v-model="envText" class="ai-up-textarea" rows="4" placeholder="OPENAI_API_KEY=sk-...&#10;TIMEOUT=30s"></textarea>
      </label>
      <div v-if="createError" class="ai-up-banner ai-up-banner--error">{{ createError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeCreate">Cancel</button>
        <button class="ai-up-btn" :disabled="!canCreate || submitting" @click="submitCreate">
          {{ submitting ? 'Creating...' : 'Create' }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, computed, onMounted } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpModal from '../components/AiUpModal.vue';
import { adaptersApi, Adapter } from '../services/adapters';
import { registryApi, MCPServer } from '../services/registry';

interface ListAdapter extends Adapter {
  id?:          string;
  url?:         string;
  mcpServerId?: string;
}

function parseEnvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const k = line.slice(0, eq).trim();
    const v = line.slice(eq + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

export default defineComponent({
  name:       'MCPGateway',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal },
  setup() {
    const adapters        = ref<ListAdapter[]>([]);
    const registryEntries = ref<MCPServer[]>([]);
    const search          = ref('');
    const loading         = ref(false);
    const error           = ref<string | null>(null);
    const deleting        = ref<string | null>(null);
    const creating        = ref(false);
    const submitting      = ref(false);
    const createError     = ref<string | null>(null);
    const form            = ref({ name: '', mcpServerId: '', description: '' });
    const envText         = ref('');

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return adapters.value;
      return adapters.value.filter((a) =>
        (a.name || '').toLowerCase().includes(q)
        || (a.description || '').toLowerCase().includes(q)
        || (a.mcpServerId || '').toLowerCase().includes(q),
      );
    });

    const canCreate = computed(() => !!(form.value.name.trim() && form.value.mcpServerId.trim()));

    function statusTone(s?: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (!s) return 'neutral';
      const v = s.toLowerCase();
      if (v.includes('running') || v.includes('ready') || v.includes('healthy') || v.includes('active')) return 'success';
      if (v.includes('error') || v.includes('failed')) return 'error';
      if (v.includes('pending') || v.includes('provisioning')) return 'warning';
      return 'info';
    }

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        // Backend returns JSON `null` for an empty Go slice; coerce to [].
        adapters.value = ((await adaptersApi.list()) || []) as ListAdapter[];
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    async function loadRegistry() {
      try {
        registryEntries.value = (await registryApi.list()) || [];
      } catch {
        // Non-fatal: dropdown falls back to free-text input.
      }
    }

    function openCreate() {
      form.value        = { name: '', mcpServerId: '', description: '' };
      envText.value     = '';
      createError.value = null;
      creating.value    = true;
      loadRegistry();
    }

    function closeCreate() {
      creating.value = false;
    }

    async function submitCreate() {
      submitting.value  = true;
      createError.value = null;
      try {
        await adaptersApi.create({
          name:                 form.value.name.trim(),
          mcpServerId:          form.value.mcpServerId.trim(),
          description:          form.value.description.trim() || undefined,
          environmentVariables: parseEnvText(envText.value),
        } as any);
        closeCreate();
        await refresh();
      } catch (e: any) {
        createError.value = e?.data?.error || e?.message || 'Create failed';
      } finally {
        submitting.value = false;
      }
    }

    async function confirmDelete(a: ListAdapter) {
      if (!window.confirm(`Delete adapter "${ a.name }"? This removes the sidecar Deployment.`)) return;
      deleting.value = a.name;
      try {
        await adaptersApi.remove(a.name);
        await refresh();
      } catch (e: any) {
        error.value = e?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    onMounted(refresh);

    return {
      adapters, registryEntries, search, loading, error, deleting,
      creating, submitting, createError, form, envText,
      filtered, canCreate, statusTone,
      refresh, openCreate, closeCreate, submitCreate, confirmDelete,
    };
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-btn {
  padding:        6px 12px;
  border-radius:  6px;
  border:         1px solid var(--primary, #1d4ed8);
  background:     var(--primary, #1d4ed8);
  color:          #fff;
  font-size:      13px;
  cursor:         pointer;
}
.ai-up-btn:disabled {
  opacity: 0.55;
  cursor:  not-allowed;
}
.ai-up-btn--ghost {
  background: transparent;
  color:      var(--primary, #1d4ed8);
}
.ai-up-btn--danger {
  border-color: var(--error, #dc2626);
  background:   transparent;
  color:        var(--error, #dc2626);
}
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
}
.ai-up-input,
.ai-up-textarea {
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.ai-up-textarea {
  font-family: var(--font-mono, monospace);
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
  color: var(--muted, #888);
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
