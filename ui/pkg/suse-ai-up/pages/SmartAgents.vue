<template>
  <AiUpPage
    title="Smart Agents"
    subtitle="Agents that consume MCP routes via pluggable protocols"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search agents..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openCreate">+ New agent</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">
      Failed to load agents: {{ error }}
    </div>

    <div v-if="loading && !agents.length" class="ai-up-empty">Loading agents...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No agents match "{{ search }}".</p>
      <p v-else>No agents yet. Create one to expose MCP tools via an agent protocol.</p>
    </div>

    <AiUpGallery v-else>
      <AiUpCard
        v-for="a in filtered"
        :key="a.name"
        :title="a.name"
        :subtitle="a.description || ''"
      >
        <template #pill>
          <AiUpPill :tone="statusTone(a.status)" :label="a.status || 'unknown'" />
        </template>
        <template #meta>
          <span>Protocol: <code>{{ a.protocol }}</code></span>
          <span v-if="a.mode">Mode: {{ a.mode }}</span>
          <span>Tools: {{ a.tools?.length || 0 }}</span>
          <span v-if="a.endpointURL" class="ai-up-truncate">URL: {{ a.endpointURL }}</span>
        </template>
        <p v-if="a.createdBy" class="ai-up-muted">Created by: {{ a.createdBy }}</p>
        <template #actions>
          <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === a.name" @click="confirmDelete(a)">
            {{ deleting === a.name ? 'Deleting...' : 'Delete' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <AiUpModal :open="creating" title="Create agent" @close="closeCreate">
      <label class="ai-up-field">
        <span>Name <em>*</em></span>
        <input v-model="form.name" class="ai-up-input" placeholder="weather-bot" />
      </label>
      <label class="ai-up-field">
        <span>Protocol <em>*</em></span>
        <input v-model="form.protocol" class="ai-up-input" placeholder="a2a" list="agent-protocol-suggestions" />
        <datalist id="agent-protocol-suggestions">
          <option value="a2a" />
          <option value="smartagents" />
          <option value="openai-assistants" />
        </datalist>
        <small class="ai-up-muted">Free-form; must match a registered AgentProtocol on the backend.</small>
      </label>
      <label class="ai-up-field">
        <span>Description</span>
        <input v-model="form.description" class="ai-up-input" placeholder="(optional)" />
      </label>

      <div class="ai-up-fieldset">
        <div class="ai-up-fieldset__legend">Tools</div>
        <p class="ai-up-muted">
          The Adapters and Virtual MCP routes this agent may call. Empty means the agent has no tool access.
        </p>
        <div v-for="(t, idx) in form.tools" :key="idx" class="tool-row">
          <select v-model="t.kind" class="ai-up-input">
            <option value="adapter">Adapter</option>
            <option value="vroute">Virtual route</option>
          </select>
          <select v-if="t.kind === 'adapter'" v-model="t.name" class="ai-up-input">
            <option value="">Select adapter…</option>
            <option v-for="a in adapterOptions" :key="a" :value="a">{{ a }}</option>
          </select>
          <select v-else v-model="t.name" class="ai-up-input">
            <option value="">Select virtual route…</option>
            <option v-for="v in vrouteOptions" :key="v" :value="v">{{ v }}</option>
          </select>
          <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="removeTool(idx)">Remove</button>
        </div>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="addTool">+ Add tool</button>
      </div>

      <details class="ai-up-details">
        <summary>Runtime (optional — leave blank for in-process)</summary>
        <p class="ai-up-muted">
          When set, the operator creates a Deployment for the agent runtime.
          Otherwise the agent is served in-process by the proxy.
        </p>
        <label class="ai-up-field">
          <span>Image</span>
          <input v-model="form.runtime.image" class="ai-up-input" placeholder="ghcr.io/example/agent:latest" />
        </label>
        <label class="ai-up-field">
          <span>Port</span>
          <input v-model.number="form.runtime.port" type="number" min="1" max="65535" class="ai-up-input" placeholder="8080" />
        </label>
        <label class="ai-up-field">
          <span>Replicas</span>
          <input v-model.number="form.runtime.replicas" type="number" min="0" class="ai-up-input" placeholder="1" />
        </label>
        <label class="ai-up-field">
          <span>Environment variables</span>
          <small class="ai-up-muted">One <code>KEY=value</code> per line.</small>
          <textarea v-model="form.runtime.envText" class="ai-up-textarea" rows="3" placeholder="LOG_LEVEL=debug" />
        </label>
        <div class="ai-up-fieldset">
          <div class="ai-up-fieldset__legend">Secret / ConfigMap references</div>
          <p class="ai-up-muted">Inject values from existing Kubernetes Secrets or ConfigMaps.</p>
          <div v-for="(ef, idx) in form.envFrom" :key="idx" class="envfrom-row">
            <input v-model="ef.name" class="ai-up-input" placeholder="ENV_VAR_NAME" />
            <select v-model="ef.sourceType" class="ai-up-input">
              <option value="secret">Secret</option>
              <option value="configmap">ConfigMap</option>
            </select>
            <input v-model="ef.sourceName" class="ai-up-input" placeholder="secret-name" />
            <input v-model="ef.sourceKey" class="ai-up-input" placeholder="key" />
            <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="removeEnvFrom(idx)">Remove</button>
          </div>
          <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="addEnvFrom">+ Add reference</button>
        </div>
      </details>

      <div class="ai-up-fieldset">
        <div class="ai-up-fieldset__legend">Access control <span class="ai-up-fieldset__optional">(optional)</span></div>
        <p class="ai-up-muted">Select RouteAssignments to control who can invoke this agent.</p>
        <AiUpPickerList
          :items="raPickerItems"
          :selected="selectedAcl"
          empty-label="No route assignments found. Create them via the MCP Registry."
          search-placeholder="Filter assignments..."
          @update:selected="selectedAcl = $event"
        />
      </div>

      <div v-if="createError" class="ai-up-banner ai-up-banner--error">{{ createError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeCreate">Cancel</button>
        <button type="button" class="ai-up-btn" :disabled="!canCreate || submitting" @click="submitCreate">
          {{ submitting ? 'Creating...' : 'Create agent' }}
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
import AiUpPickerList from '../components/AiUpPickerList.vue';
import { agentsApi, Agent, AgentTool, EnvVarSource, CreateAgentRequest } from '../services/agents';
import { adaptersApi } from '../services/adapters';
import { vroutesApi } from '../services/vroutes';
import { routeAssignmentsApi } from '../services/route-assignments';

interface ToolForm { kind: 'adapter' | 'vroute'; name: string; }
interface EnvFromForm { name: string; sourceType: 'secret' | 'configmap'; sourceName: string; sourceKey: string; }

function parseEnvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of (text || '').split(/\r?\n/)) {
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
  name:       'SmartAgents',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal, AiUpPickerList },
  setup() {
    const agents      = ref<Agent[]>([]);
    const search      = ref('');
    const loading     = ref(false);
    const error       = ref<string | null>(null);
    const deleting    = ref<string | null>(null);
    const creating    = ref(false);
    const submitting  = ref(false);
    const createError = ref<string | null>(null);

    const adapterOptions = ref<string[]>([]);
    const vrouteOptions  = ref<string[]>([]);
    const raPickerItems  = ref<{ id: string; label: string; sublabel?: string }[]>([]);
    const selectedAcl    = ref<string[]>([]);

    const form = reactive({
      name:        '',
      protocol:    'a2a',
      description: '',
      tools:       [] as ToolForm[],
      runtime:     { image: '', port: undefined as number | undefined, replicas: undefined as number | undefined, envText: '' },
      envFrom:     [] as EnvFromForm[],
    });

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return agents.value;
      return agents.value.filter((a) =>
        (a.name || '').toLowerCase().includes(q)
        || (a.description || '').toLowerCase().includes(q)
        || (a.protocol || '').toLowerCase().includes(q),
      );
    });

    const canCreate = computed(() => !!form.name.trim() && !!form.protocol.trim());

    function statusTone(s?: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (!s) return 'neutral';
      const v = s.toLowerCase();
      if (v === 'ready') return 'success';
      if (v === 'error') return 'error';
      if (v === 'provisioning' || v === 'pending') return 'warning';
      return 'info';
    }

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        agents.value = ((await agentsApi.list()) || []) as Agent[];
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
        const list = (await vroutesApi.list()) || [];
        vrouteOptions.value = list.map((v) => v.name).filter(Boolean);
      } catch { vrouteOptions.value = []; }
      try {
        const list = (await routeAssignmentsApi.list()) || [];
        raPickerItems.value = list.map((ra) => ({
          id:       ra.id,
          label:    ra.id,
          sublabel: `${ ra.permissions || 'read' } · server: ${ ra.serverId || '—' }`,
        }));
      } catch { raPickerItems.value = []; }
    }

    function openCreate() {
      form.name        = '';
      form.protocol    = 'a2a';
      form.description = '';
      form.tools       = [];
      form.runtime.image    = '';
      form.runtime.port     = undefined;
      form.runtime.replicas = undefined;
      form.runtime.envText  = '';
      form.envFrom     = [];
      selectedAcl.value = [];
      createError.value = null;
      creating.value   = true;
      loadOptions();
    }

    function closeCreate() {
      creating.value = false;
    }

    function addTool() {
      form.tools.push({ kind: 'adapter', name: '' });
    }

    function removeTool(idx: number) {
      form.tools.splice(idx, 1);
    }

    function addEnvFrom() {
      form.envFrom.push({ name: '', sourceType: 'secret', sourceName: '', sourceKey: '' });
    }

    function removeEnvFrom(idx: number) {
      form.envFrom.splice(idx, 1);
    }

    async function submitCreate() {
      submitting.value  = true;
      createError.value = null;
      try {
        const tools: AgentTool[] = form.tools
          .filter((t) => t.name.trim())
          .map((t) => (t.kind === 'adapter'
            ? { adapterName: t.name.trim() }
            : { virtualMCPRouteName: t.name.trim() }
          ));

        const req: CreateAgentRequest = {
          name:        form.name.trim(),
          protocol:    form.protocol.trim(),
          description: form.description.trim() || undefined,
          tools,
          acl:         selectedAcl.value,
        };

        const env = parseEnvText(form.runtime.envText);
        const envFrom: EnvVarSource[] = form.envFrom
          .filter((ef) => ef.name.trim() && ef.sourceName.trim() && ef.sourceKey.trim())
          .map((ef) => {
            const src: EnvVarSource = { name: ef.name.trim() };
            if (ef.sourceType === 'secret') {
              src.secretKeyRef = { name: ef.sourceName.trim(), key: ef.sourceKey.trim() };
            } else {
              src.configMapKeyRef = { name: ef.sourceName.trim(), key: ef.sourceKey.trim() };
            }
            return src;
          });
        const hasRuntime = !!(form.runtime.image
          || form.runtime.port
          || form.runtime.replicas !== undefined
          || Object.keys(env).length
          || envFrom.length);
        if (hasRuntime) {
          req.runtime = {
            image:    form.runtime.image || undefined,
            port:     form.runtime.port,
            replicas: form.runtime.replicas,
            env:      Object.keys(env).length ? env : undefined,
            envFrom:  envFrom.length ? envFrom : undefined,
          };
        }

        await agentsApi.create(req);
        closeCreate();
        await refresh();
      } catch (e: any) {
        createError.value = e?.data?.error || e?.message || 'Create failed';
      } finally {
        submitting.value = false;
      }
    }

    async function confirmDelete(a: Agent) {
      if (!window.confirm(`Delete agent "${ a.name }"?`)) return;
      deleting.value = a.name;
      try {
        await agentsApi.remove(a.name);
        await refresh();
      } catch (e: any) {
        error.value = e?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    onMounted(refresh);

    return {
      agents, search, loading, error, deleting,
      creating, submitting, createError,
      form, selectedAcl, raPickerItems, adapterOptions, vrouteOptions,
      filtered, canCreate,
      statusTone, refresh, openCreate, closeCreate,
      addTool, removeTool, addEnvFrom, removeEnvFrom,
      submitCreate, confirmDelete,
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
.ai-up-fieldset__optional {
  font-weight: 400;
  color:       var(--muted, #888);
  margin-left: 4px;
}
.tool-row {
  display: grid;
  grid-template-columns: 130px 1fr auto;
  gap:     8px;
  align-items: center;
}
.envfrom-row {
  display: grid;
  grid-template-columns: 1fr 110px 1fr 1fr auto;
  gap:     8px;
  align-items: center;
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
</style>
