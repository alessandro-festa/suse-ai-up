<template>
  <AiUpPage
    title="MCP Registry"
    subtitle="Catalog of MCP servers available for adapter creation"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search registry..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openUpload">+ Upload entry</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">
      Failed to load registry: {{ error }}
    </div>

    <div v-if="loading && !entries.length" class="ai-up-empty">Loading registry...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No registry entries match "{{ search }}".</p>
      <p v-else>Registry is empty. Upload an MCP server entry to populate it.</p>
    </div>

    <AiUpGallery v-else>
      <article v-for="e in filteredView" :key="e.id" class="reg-card">
        <header class="reg-card__head">
          <div class="reg-card__icon">
            <img v-if="e.iconUrl && !e.iconBroken" :src="e.iconUrl" alt="" referrerpolicy="no-referrer" @error="onIconError(e.id)" />
            <span v-else class="reg-card__icon-fallback">{{ e.initials }}</span>
          </div>
          <div class="reg-card__title-block">
            <h3 class="reg-card__title">{{ e.title }}</h3>
            <p v-if="e.id !== e.title" class="reg-card__id">{{ e.id }}</p>
          </div>
          <AiUpPill v-if="e.version" tone="info" :label="`v${ e.version }`" />
        </header>

        <p v-if="e.description" class="reg-card__desc">{{ e.description }}</p>

        <div class="reg-card__chips">
          <AiUpPill :tone="e.runtime.tone" :label="e.runtime.label" />
          <AiUpPill v-if="e.transport" tone="neutral" :label="e.transport" />
          <AiUpPill v-if="e.category" tone="neutral" :label="e.category" />
        </div>

        <div v-if="e.tags.length" class="reg-card__tags">
          <span v-for="t in e.tags" :key="t" class="reg-card__tag">{{ t }}</span>
        </div>

        <footer class="reg-card__footer">
          <div class="reg-card__meta">
            <a v-if="e.sourceUrl" :href="e.sourceUrl" target="_blank" rel="noopener" class="reg-card__link">
              Source ↗
            </a>
            <span v-if="e.runtime.identifier" class="reg-card__identifier" :title="e.runtime.identifier">
              {{ e.runtime.identifier }}
            </span>
          </div>
          <div class="reg-card__actions">
            <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === e.id" @click="confirmDelete(e.raw)">
              {{ deleting === e.id ? 'Deleting...' : 'Delete' }}
            </button>
          </div>
        </footer>
      </article>
    </AiUpGallery>

    <AiUpModal :open="uploading" title="Upload registry entry" @close="closeUpload">
      <p class="ai-up-muted">
        Paste a YAML or JSON document. YAML matches the format used by bulk uploads
        (<code>hack/registry/mcp_registry.yaml</code>). Minimum fields: <code>name</code> (or <code>id</code>).
      </p>
      <textarea
        v-model="uploadText"
        class="ai-up-textarea ai-up-textarea--large"
        rows="14"
        spellcheck="false"
        :placeholder="examplePlaceholder"
      ></textarea>
      <div v-if="uploadError" class="ai-up-banner ai-up-banner--error">{{ uploadError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeUpload">Cancel</button>
        <button class="ai-up-btn" :disabled="!uploadText.trim() || submitting" @click="submitUpload">
          {{ submitting ? 'Uploading...' : 'Upload' }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, computed, onMounted, reactive } from 'vue';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const jsYaml: { load: (s: string) => unknown } = require('js-yaml');
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpModal from '../components/AiUpModal.vue';
import { registryApi, MCPServer } from '../services/registry';

const EXAMPLE = `name: weather-mcp
version: 0.1.0
image: ghcr.io/example/weather-mcp:0.1.0
meta:
  about:
    title: Weather MCP
    description: Forecast and current-conditions tools.
    icon: https://example.com/weather.svg
  category: weather
  tags: [demo]
`;

type RuntimeTone = 'info' | 'success' | 'warning' | 'error' | 'neutral';

interface ViewEntry {
  id:         string;
  title:      string;
  initials:   string;
  description: string;
  version:    string;
  iconUrl:    string;
  iconBroken: boolean;
  runtime:    { label: string; tone: RuntimeTone; identifier: string };
  transport:  string;
  category:   string;
  tags:       string[];
  sourceUrl:  string;
  raw:        MCPServer;
}

function safeMeta(e: MCPServer): any {
  return ((e as any)._meta || (e as any).meta || {}) as Record<string, any>;
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function classifyRuntime(e: MCPServer): { label: string; tone: RuntimeTone; identifier: string } {
  const meta    = safeMeta(e);
  const cmdType = String(meta?.sidecarConfig?.commandType || '').toLowerCase();
  const pkgs    = Array.isArray((e as any).packages) ? (e as any).packages : [];
  const firstPkg: any = pkgs[0] || {};
  const identifier = asString(firstPkg.identifier) || asString((e as any).image);

  const map: Record<string, { label: string; tone: RuntimeTone }> = {
    docker:    { label: 'Container', tone: 'info' },
    podman:    { label: 'Container', tone: 'info' },
    oci:       { label: 'Container', tone: 'info' },
    npx:       { label: 'Node.js',   tone: 'success' },
    node:      { label: 'Node.js',   tone: 'success' },
    npm:       { label: 'Node.js',   tone: 'success' },
    pip:       { label: 'Python',    tone: 'warning' },
    pipx:      { label: 'Python',    tone: 'warning' },
    python:    { label: 'Python',    tone: 'warning' },
    uvx:       { label: 'Python',    tone: 'warning' },
    pypi:      { label: 'Python',    tone: 'warning' },
    go:        { label: 'Go',        tone: 'info' },
    gomod:     { label: 'Go',        tone: 'info' },
    cargo:     { label: 'Rust',      tone: 'warning' },
    'crates.io': { label: 'Rust',    tone: 'warning' },
    maven:     { label: 'Java',      tone: 'info' },
    binary:    { label: 'Binary',    tone: 'neutral' },
  };

  if (cmdType && map[cmdType]) return { ...map[cmdType], identifier };
  const regType = String(firstPkg.registryType || '').toLowerCase();
  if (regType && map[regType]) return { ...map[regType], identifier };

  if (/^(docker\.io|ghcr\.io|quay\.io|gcr\.io|mcr\.microsoft\.com|registry\.)/i.test(identifier)) {
    return { label: 'Container', tone: 'info', identifier };
  }
  if (identifier) return { label: 'Binary', tone: 'neutral', identifier };
  return { label: 'Unknown', tone: 'neutral', identifier: '' };
}

function toView(e: MCPServer, broken: Record<string, boolean>): ViewEntry {
  const meta  = safeMeta(e);
  const about = meta?.about || {};
  const id    = asString(e.id) || asString(e.name) || '(unnamed)';
  const title = asString(about.title) || asString(e.name) || id;
  const description = asString(about.description) || asString(e.description) || '';
  const version     = asString(e.version);
  const category    = asString(meta?.category);
  const sourceUrl   = asString(meta?.source?.project) || asString((e as any).url);
  const iconUrl     = asString(about.icon);
  const tags        = Array.isArray(meta?.tags) ? meta.tags.filter((t: any) => typeof t === 'string').slice(0, 6) : [];
  const pkgs        = Array.isArray((e as any).packages) ? (e as any).packages : [];
  const transport   = asString(pkgs[0]?.transport?.type);
  const initials    = (title.match(/[A-Za-z0-9]/g) || []).slice(0, 2).join('').toUpperCase() || '?';

  return {
    id, title, initials, description, version,
    iconUrl, iconBroken: !!broken[id],
    runtime:   classifyRuntime(e),
    transport, category, tags, sourceUrl,
    raw: e,
  };
}

export default defineComponent({
  name:       'MCPRegistry',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpPill, AiUpModal },
  setup() {
    const entries     = ref<MCPServer[]>([]);
    const search      = ref('');
    const loading     = ref(false);
    const error       = ref<string | null>(null);
    const deleting    = ref<string | null>(null);
    const uploading   = ref(false);
    const submitting  = ref(false);
    const uploadText  = ref('');
    const uploadError = ref<string | null>(null);
    const brokenIcons = reactive<Record<string, boolean>>({});

    const examplePlaceholder = EXAMPLE;

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return entries.value;
      return entries.value.filter((e) => {
        const meta = safeMeta(e);
        return (e.id || '').toLowerCase().includes(q)
          || (e.name || '').toLowerCase().includes(q)
          || (e.description || '').toLowerCase().includes(q)
          || (meta?.about?.title || '').toLowerCase().includes(q)
          || (Array.isArray(meta?.tags) ? meta.tags.join(' ').toLowerCase() : '').includes(q);
      });
    });

    const filteredView = computed<ViewEntry[]>(() => filtered.value.map((e) => toView(e, brokenIcons)));

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        // Use /browse (unfiltered catalog) rather than /registry, which is
        // permission-filtered by X-User-ID and returns null for unmatched
        // callers. Backend may still emit JSON `null` for an empty Go slice
        // so coerce to [].
        entries.value = (await registryApi.browse()) || [];
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    function openUpload() {
      uploadText.value  = '';
      uploadError.value = null;
      uploading.value   = true;
    }

    function closeUpload() {
      uploading.value = false;
    }

    function parsePayload(raw: string): any {
      const text = raw.trim();
      if (!text) throw new Error('Empty payload');
      // Try JSON first (cheap); fall back to YAML.
      if (text.startsWith('{') || text.startsWith('[')) {
        try { return JSON.parse(text); } catch { /* fall through to YAML */ }
      }
      return jsYaml.load(text);
    }

    async function submitUpload() {
      let body: any;
      try {
        body = parsePayload(uploadText.value);
      } catch (e: any) {
        uploadError.value = `Invalid YAML/JSON: ${ e.message }`;
        return;
      }
      if (Array.isArray(body)) {
        uploadError.value = 'Bulk arrays not supported here yet — upload one entry at a time.';
        return;
      }
      if (!body || (!body.id && !body.name)) {
        uploadError.value = 'Document must include "id" (or "name").';
        return;
      }
      if (!body.id && body.name) body.id = body.name;
      submitting.value  = true;
      uploadError.value = null;
      try {
        await registryApi.upload(body);
        closeUpload();
        await refresh();
      } catch (e: any) {
        uploadError.value = e?.data?.error || e?.message || 'Upload failed';
      } finally {
        submitting.value = false;
      }
    }

    async function confirmDelete(e: MCPServer) {
      const id = e.id || (e as any).name;
      if (!window.confirm(`Delete registry entry "${ id }"? Adapters built from it stay in place.`)) return;
      deleting.value = id;
      try {
        await registryApi.remove(id);
        await refresh();
      } catch (err: any) {
        error.value = err?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    function onIconError(id: string) {
      brokenIcons[id] = true;
    }

    onMounted(refresh);

    return {
      entries, search, loading, error, deleting,
      uploading, submitting, uploadText, uploadError, examplePlaceholder,
      filtered, filteredView,
      refresh, openUpload, closeUpload, submitUpload, confirmDelete,
      onIconError,
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

.reg-card {
  display:        flex;
  flex-direction: column;
  gap:            10px;
  padding:        15px;
  border:         1px solid var(--border, #ddd);
  border-radius:  $ai-up-radius;
  background:     var(--body-bg, #fff);
}
.reg-card__head {
  display:     flex;
  align-items: flex-start;
  gap:         12px;
}
.reg-card__icon {
  width:           44px;
  height:          44px;
  flex:            0 0 44px;
  border:          1px solid var(--border, #ddd);
  border-radius:   8px;
  background:      var(--disabled-bg, rgba(136, 136, 136, 0.08));
  display:         flex;
  align-items:     center;
  justify-content: center;
  overflow:        hidden;
}
.reg-card__icon img {
  width:      100%;
  height:     100%;
  object-fit: contain;
}
.reg-card__icon-fallback {
  font-size:   14px;
  font-weight: 600;
  color:       var(--muted, #888);
  letter-spacing: 0.5px;
}
.reg-card__title-block {
  flex:           1 1 auto;
  min-width:      0;
  display:        flex;
  flex-direction: column;
  gap:            2px;
}
.reg-card__title {
  margin:        0;
  font-size:     15px;
  font-weight:   600;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
}
.reg-card__id {
  margin:    0;
  font-size: 11px;
  color:     var(--muted, #888);
  font-family: var(--font-mono, monospace);
}
.reg-card__desc {
  margin:      0;
  font-size:   13px;
  line-height: 1.4;
  display:     -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow:    hidden;
}
.reg-card__chips,
.reg-card__tags {
  display:   flex;
  flex-wrap: wrap;
  gap:       6px;
}
.reg-card__tag {
  font-size:     11px;
  padding:       2px 8px;
  border-radius: 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  color:         var(--muted, #888);
}
.reg-card__footer {
  display:         flex;
  justify-content: space-between;
  align-items:     center;
  gap:             10px;
  padding-top:     6px;
  border-top:      1px dashed var(--border, #ddd);
}
.reg-card__meta {
  display:        flex;
  flex-direction: column;
  gap:            2px;
  min-width:      0;
  font-size:      11px;
  color:          var(--muted, #888);
}
.reg-card__link {
  color:          var(--primary, #1d4ed8);
  text-decoration: none;
}
.reg-card__link:hover { text-decoration: underline; }
.reg-card__identifier {
  font-family:   var(--font-mono, monospace);
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
  max-width:     220px;
}
.reg-card__actions {
  display: flex;
  gap:     6px;
}

.ai-up-textarea {
  padding:        8px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      12px;
  font-family:    var(--font-mono, monospace);
  width:          100%;
  resize:         vertical;
}
.ai-up-textarea--large { min-height: 220px; }
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
  margin:    0 0 6px;
}
</style>
