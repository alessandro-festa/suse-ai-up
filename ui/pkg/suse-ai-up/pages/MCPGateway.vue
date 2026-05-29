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

    <AiUpModal :open="creating" :title="modalTitle" @close="closeCreate">
      <!-- Step 1: pick an MCP server from the registry -->
      <template v-if="!selected">
        <input
          v-model="pickSearch"
          type="search"
          class="ai-up-input"
          placeholder="Search registry by name, tag, category, or runtime..."
          autofocus
        />
        <div v-if="loadingRegistry" class="ai-up-empty">Loading registry...</div>
        <div v-else-if="!registryViews.length" class="ai-up-empty">
          Registry is empty. Upload an entry on the MCP Registry page first.
        </div>
        <div v-else-if="!pickFiltered.length" class="ai-up-empty">
          No entries match "{{ pickSearch }}".
        </div>
        <div v-else class="picker-list">
          <button
            v-for="v in pickFiltered"
            :key="v.id"
            type="button"
            class="picker-item"
            @click="selectEntry(v)"
          >
            <div class="picker-item__icon">
              <img v-if="v.iconUrl && !brokenIcons[v.id]" :src="v.iconUrl" alt="" referrerpolicy="no-referrer" @error="brokenIcons[v.id] = true" />
              <span v-else class="picker-item__initials">{{ v.initials }}</span>
            </div>
            <div class="picker-item__body">
              <div class="picker-item__title-row">
                <strong class="picker-item__title">{{ v.title }}</strong>
                <AiUpPill v-if="v.version" tone="info" :label="`v${ v.version }`" />
              </div>
              <p v-if="v.description" class="picker-item__desc">{{ v.description }}</p>
              <div class="picker-item__chips">
                <AiUpPill :tone="v.runtime.tone" :label="v.runtime.label" />
                <AiUpPill v-if="v.transport" tone="neutral" :label="v.transport" />
                <AiUpPill v-if="v.category" tone="neutral" :label="v.category" />
                <span v-for="t in v.tags.slice(0, 3)" :key="t" class="picker-item__tag">{{ t }}</span>
              </div>
            </div>
          </button>
        </div>
      </template>

      <!-- Step 2: configure the adapter for the selected MCP server -->
      <template v-else>
        <div class="selected-banner">
          <div class="picker-item__icon picker-item__icon--small">
            <img v-if="selected.iconUrl && !brokenIcons[selected.id]" :src="selected.iconUrl" alt="" referrerpolicy="no-referrer" @error="brokenIcons[selected.id] = true" />
            <span v-else class="picker-item__initials">{{ selected.initials }}</span>
          </div>
          <div class="selected-banner__body">
            <strong>{{ selected.title }}</strong>
            <small>{{ selected.id }}{{ selected.version ? ` · v${ selected.version }` : '' }} · {{ selected.runtime.label }}</small>
          </div>
          <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="selected = null">Change</button>
        </div>

        <label class="ai-up-field">
          <span>Adapter name <em>*</em></span>
          <input v-model="form.name" class="ai-up-input" placeholder="my-adapter" />
        </label>
        <label class="ai-up-field">
          <span>Description</span>
          <input v-model="form.description" class="ai-up-input" placeholder="(optional)" />
        </label>

        <div v-if="selected.secrets.length" class="ai-up-fieldset">
          <div class="ai-up-fieldset__legend">Configuration</div>
          <p class="ai-up-muted">Values defined in this MCP server's <code>meta.config.secrets</code>.</p>
          <label v-for="s in selected.secrets" :key="s.env" class="ai-up-field">
            <span>
              {{ s.name }}
              <em v-if="s.templated">*</em>
              <code class="ai-up-field__env">{{ s.env }}</code>
            </span>
            <input
              v-if="s.type === 'bool'"
              type="checkbox"
              :checked="vars[s.env] === 'true'"
              class="ai-up-checkbox"
              @change="vars[s.env] = ($event.target as HTMLInputElement).checked ? 'true' : 'false'"
            />
            <input
              v-else
              v-model="vars[s.env]"
              :type="s.type === 'secret' ? 'password' : 'text'"
              class="ai-up-input"
              :placeholder="s.example || (s.type === 'secret' ? '••••••••' : '')"
              :autocomplete="s.type === 'secret' ? 'new-password' : 'off'"
            />
          </label>
        </div>

        <details class="ai-up-details">
          <summary>Additional environment variables</summary>
          <p class="ai-up-muted">One <code>KEY=value</code> per line. Merged with the configuration above; keys here override.</p>
          <textarea
            v-model="envText"
            class="ai-up-textarea"
            rows="3"
            placeholder="LOG_LEVEL=debug&#10;FOO=bar"
          ></textarea>
        </details>

        <div v-if="createError" class="ai-up-banner ai-up-banner--error">{{ createError }}</div>
      </template>

      <template #actions>
        <button v-if="selected" type="button" class="ai-up-btn ai-up-btn--ghost" @click="selected = null">← Back</button>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeCreate">Cancel</button>
        <button
          v-if="selected"
          type="button"
          class="ai-up-btn"
          :disabled="!canCreate || submitting"
          @click="submitCreate"
        >
          {{ submitting ? 'Creating...' : 'Create adapter' }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, computed, onMounted, reactive, watch } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpModal from '../components/AiUpModal.vue';
import { adaptersApi, Adapter } from '../services/adapters';
import { registryApi } from '../services/registry';
import { toRegistryView, matchesQuery, RegistryView } from '../services/registry-view';

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
    const adapters       = ref<ListAdapter[]>([]);
    const registryViews  = ref<RegistryView[]>([]);
    const loadingRegistry = ref(false);
    const search         = ref('');
    const loading        = ref(false);
    const error          = ref<string | null>(null);
    const deleting       = ref<string | null>(null);
    const creating       = ref(false);
    const submitting     = ref(false);
    const createError    = ref<string | null>(null);
    const selected       = ref<RegistryView | null>(null);
    const pickSearch     = ref('');
    const form           = ref({ name: '', description: '' });
    const vars           = reactive<Record<string, string>>({});
    const envText        = ref('');
    const brokenIcons    = reactive<Record<string, boolean>>({});

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return adapters.value;
      return adapters.value.filter((a) =>
        (a.name || '').toLowerCase().includes(q)
        || (a.description || '').toLowerCase().includes(q)
        || (a.mcpServerId || '').toLowerCase().includes(q),
      );
    });

    const pickFiltered = computed(() =>
      registryViews.value.filter((v) => matchesQuery(v, pickSearch.value.trim())),
    );

    const modalTitle = computed(() => (selected.value ? `Create adapter from ${ selected.value.title }` : 'Pick an MCP server'));

    const canCreate = computed(() => !!(selected.value && form.value.name.trim()));

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
        adapters.value = ((await adaptersApi.list()) || []) as ListAdapter[];
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    async function loadRegistry() {
      loadingRegistry.value = true;
      try {
        const raw = (await registryApi.browse()) || [];
        registryViews.value = raw.map(toRegistryView);
      } catch {
        registryViews.value = [];
      } finally {
        loadingRegistry.value = false;
      }
    }

    function openCreate() {
      selected.value    = null;
      pickSearch.value  = '';
      form.value        = { name: '', description: '' };
      envText.value     = '';
      createError.value = null;
      for (const k of Object.keys(vars)) delete vars[k];
      creating.value    = true;
      loadRegistry();
    }

    function closeCreate() {
      creating.value = false;
    }

    function selectEntry(v: RegistryView) {
      selected.value = v;
      // Default the adapter name to "<id>-adapter" so the user usually just clicks Create.
      if (!form.value.name) {
        form.value.name = `${ v.id }-adapter`;
      }
      // Seed each secret field with its example (so the user sees the shape and can edit).
      // Only seed if not already filled — supports going back-and-forth without losing edits.
      for (const s of v.secrets) {
        if (vars[s.env] === undefined) {
          vars[s.env] = s.type === 'bool' ? (s.example.toLowerCase() === 'true' ? 'true' : 'false') : '';
        }
      }
    }

    // When the user clears their selection (Back), drop seeded env values that
    // came from the previous server's secrets so they don't leak into the
    // next pick. We keep any free-text additional env vars (envText) intact.
    watch(selected, (now, prev) => {
      if (prev && !now) {
        for (const s of prev.secrets) {
          delete vars[s.env];
        }
      }
    });

    async function submitCreate() {
      if (!selected.value) return;
      submitting.value  = true;
      createError.value = null;
      // Build env vars: secret-derived first, additional env text overrides.
      const env: Record<string, string> = {};
      for (const s of selected.value.secrets) {
        const v = vars[s.env];
        if (v !== undefined && v !== '') env[s.env] = v;
      }
      Object.assign(env, parseEnvText(envText.value));
      try {
        await adaptersApi.create({
          name:                 form.value.name.trim(),
          mcpServerId:          selected.value.id,
          description:          form.value.description.trim() || undefined,
          environmentVariables: env,
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
      adapters, registryViews, loadingRegistry, search, loading, error, deleting,
      creating, submitting, createError, selected, pickSearch, form, vars, envText,
      brokenIcons,
      filtered, pickFiltered, modalTitle, canCreate,
      statusTone,
      refresh, openCreate, closeCreate, selectEntry, submitCreate, confirmDelete,
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
.ai-up-field__env {
  margin-left: 6px;
  font-family: var(--font-mono, monospace);
  font-size:   11px;
  color:       var(--muted, #888);
  opacity:     0.7;
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
.ai-up-textarea  { font-family: var(--font-mono, monospace); }
.ai-up-checkbox  { width: 18px; height: 18px; }
.ai-up-fieldset {
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  padding:        10px 12px 12px;
  display:        flex;
  flex-direction: column;
  gap:            8px;
}
.ai-up-fieldset__legend {
  font-size:   12px;
  font-weight: 600;
  color:       var(--body-text, #333);
  margin-bottom: 2px;
}
.ai-up-details summary {
  cursor:    pointer;
  font-size: 12px;
  color:     var(--muted, #888);
  padding:   4px 0;
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

.picker-list {
  display:        flex;
  flex-direction: column;
  gap:            8px;
  max-height:     420px;
  overflow:       auto;
  padding-right:  4px;
}
.picker-item {
  display:        flex;
  align-items:    flex-start;
  gap:            12px;
  padding:        10px;
  background:     transparent;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  text-align:     left;
  cursor:         pointer;
  font:           inherit;
  color:          inherit;
}
.picker-item:hover {
  border-color: var(--primary, #1d4ed8);
  background:   var(--disabled-bg, rgba(136, 136, 136, 0.04));
}
.picker-item__icon {
  width:  40px;
  height: 40px;
  flex:   0 0 40px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  display:        flex;
  align-items:    center;
  justify-content: center;
  overflow:       hidden;
}
.picker-item__icon--small { width: 32px; height: 32px; flex: 0 0 32px; }
.picker-item__icon img { width: 100%; height: 100%; object-fit: contain; }
.picker-item__initials {
  font-size:   12px;
  font-weight: 600;
  color:       var(--muted, #888);
}
.picker-item__body {
  flex:           1 1 auto;
  min-width:      0;
  display:        flex;
  flex-direction: column;
  gap:            4px;
}
.picker-item__title-row {
  display:     flex;
  align-items: center;
  gap:         8px;
}
.picker-item__title {
  font-size:     14px;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
}
.picker-item__desc {
  margin:      0;
  font-size:   12px;
  color:       var(--muted, #888);
  line-height: 1.35;
  display:     -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow:    hidden;
}
.picker-item__chips {
  display:   flex;
  flex-wrap: wrap;
  gap:       4px;
  align-items: center;
}
.picker-item__tag {
  font-size:     10px;
  padding:       1px 6px;
  border-radius: 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  color:         var(--muted, #888);
}

.selected-banner {
  display:        flex;
  align-items:    center;
  gap:            10px;
  padding:        8px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--disabled-bg, rgba(136, 136, 136, 0.04));
}
.selected-banner__body {
  flex:           1 1 auto;
  min-width:      0;
  display:        flex;
  flex-direction: column;
}
.selected-banner__body strong { font-size: 13px; }
.selected-banner__body small  { font-size: 11px; color: var(--muted, #888); }
</style>
