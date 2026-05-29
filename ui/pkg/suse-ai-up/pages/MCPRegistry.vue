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

    <div v-else-if="!filteredView.length && !error" class="ai-up-empty">
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
      <AiUpTabs :tabs="uploadTabs" v-model:active="uploadMode" />

      <template v-if="uploadMode === 'paste'">
        <p class="ai-up-muted">
          Paste a YAML or JSON document. Single entry <strong>or</strong> a YAML list
          (matches <code>hack/registry/mcp_registry.yaml</code> bulk format). Minimum fields:
          <code>name</code> (or <code>id</code>).
        </p>
        <textarea
          v-model="uploadText"
          class="ai-up-textarea ai-up-textarea--large"
          rows="14"
          spellcheck="false"
          :placeholder="examplePlaceholder"
        ></textarea>
      </template>

      <template v-else-if="uploadMode === 'file'">
        <p class="ai-up-muted">
          Pick a <code>.yaml</code> / <code>.yml</code> / <code>.json</code> file from disk. The contents load
          below so you can review before uploading.
        </p>
        <label class="file-picker">
          <input
            type="file"
            accept=".yaml,.yml,.json,application/x-yaml,application/json"
            @change="onFilePicked"
          />
          <span class="file-picker__name">{{ filePickedName || 'Choose a file...' }}</span>
        </label>
        <textarea
          v-model="uploadText"
          class="ai-up-textarea ai-up-textarea--large"
          rows="12"
          spellcheck="false"
          placeholder="(file contents will appear here)"
        ></textarea>
      </template>

      <template v-else-if="uploadMode === 'git'">
        <p class="ai-up-muted">
          Fetch a registry YAML from a Git repo. The backend fetches it server-side, so private repos work too.
        </p>
        <label class="ai-up-field">
          <span>URL <em>*</em></span>
          <input
            v-model="git.url"
            class="ai-up-input"
            placeholder="https://github.com/SUSE/suse-ai-up"
            spellcheck="false"
          />
          <small class="ai-up-muted">
            Accepts <code>github.com/&lt;owner&gt;/&lt;repo&gt;</code>, <code>raw.githubusercontent.com</code>,
            <code>gitlab.com</code>, or any raw https:// URL returning YAML.
          </small>
        </label>
        <label class="ai-up-field">
          <span>Path <em v-if="needsPath">*</em></span>
          <input v-model="git.path" class="ai-up-input" placeholder="hack/registry/mcp_registry.yaml" />
          <small class="ai-up-muted">Required when URL is a <code>github.com</code> repo root.</small>
        </label>
        <label class="ai-up-field">
          <span>Branch</span>
          <input v-model="git.branch" class="ai-up-input" placeholder="main" />
        </label>
        <label class="ai-up-field">
          <span>Token (private repos)</span>
          <input
            v-model="git.token"
            type="password"
            class="ai-up-input"
            placeholder="ghp_..."
            autocomplete="off"
          />
          <small class="ai-up-muted">
            GitHub PAT → <code>Authorization: Bearer</code>, GitLab PAT → <code>PRIVATE-TOKEN</code>.
            Sent over HTTPS to your backend only.
          </small>
        </label>
      </template>

      <div v-if="uploadError" class="ai-up-banner ai-up-banner--error">{{ uploadError }}</div>
      <div v-if="uploadSuccess" class="ai-up-banner ai-up-banner--success">{{ uploadSuccess }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeUpload">Cancel</button>
        <button class="ai-up-btn" :disabled="!canSubmitUpload || submitting" @click="submitUploadDispatch">
          {{ submitting ? 'Uploading...' : 'Upload' }}
        </button>
      </template>
    </AiUpModal>

    <!-- Conflict resolution: shown when bulk/git upload returns 409 -->
    <AiUpModal :open="!!conflictState" title="Some entries already exist" @close="cancelConflict">
      <p>
        {{ conflictState?.ids.length }} of the entries you uploaded already exist in the registry:
      </p>
      <div class="conflict-list">
        <span v-for="id in conflictState?.ids" :key="id" class="chip chip--warning">{{ id }}</span>
      </div>
      <p class="ai-up-muted">
        <strong>Overwrite</strong> replaces each conflicting entry's spec with the uploaded version (existing
        adapters keep working). <strong>Skip</strong> leaves the existing entries untouched and creates the rest.
      </p>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="cancelConflict">Cancel</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="resolvingConflict" @click="resolveConflict('skip')">
          Skip existing
        </button>
        <button class="ai-up-btn" :disabled="resolvingConflict" @click="resolveConflict('overwrite')">
          {{ resolvingConflict ? 'Working...' : 'Overwrite' }}
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
import AiUpTabs from '../components/AiUpTabs.vue';
import { registryApi, MCPServer, ConflictMode, BulkUploadResult } from '../services/registry';
import { toRegistryView, matchesQuery, RegistryView } from '../services/registry-view';

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

// Card enrichment is shared with MCPGateway's adapter picker — see
// services/registry-view.ts for runtime classification and field mapping.
interface ViewEntry extends RegistryView {
  iconBroken: boolean;
}

function decorate(e: MCPServer, broken: Record<string, boolean>): ViewEntry {
  const v = toRegistryView(e);
  return { ...v, iconBroken: !!broken[v.id] };
}

type UploadMode = 'paste' | 'file' | 'git';

const UPLOAD_TABS = [
  { key: 'paste', label: 'Paste' },
  { key: 'file',  label: 'File' },
  { key: 'git',   label: 'Git URL' },
];

export default defineComponent({
  name:       'MCPRegistry',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpPill, AiUpModal, AiUpTabs },
  setup() {
    const entries        = ref<MCPServer[]>([]);
    const search         = ref('');
    const loading        = ref(false);
    const error          = ref<string | null>(null);
    const deleting       = ref<string | null>(null);
    const uploading      = ref(false);
    const submitting     = ref(false);
    const uploadMode     = ref<UploadMode>('paste');
    const uploadText     = ref('');
    const uploadError    = ref<string | null>(null);
    const uploadSuccess  = ref<string | null>(null);
    const filePickedName = ref<string | null>(null);
    const git            = reactive({ url: '', token: '', branch: '', path: '' });
    const brokenIcons    = reactive<Record<string, boolean>>({});
    const uploadTabs     = UPLOAD_TABS;

    // Conflict-resolution state. When a bulk/git upload returns 409 with a
    // {conflicts:[]} body, we stash the last attempt and surface a dialog
    // so the user can pick Overwrite or Skip; then we resubmit.
    interface ConflictState {
      ids:    string[];
      kind:   'bulk' | 'git';
      // The exact payload we'll resend, parameterized by mode.
      replay: (mode: ConflictMode) => Promise<BulkUploadResult>;
    }
    const conflictState     = ref<ConflictState | null>(null);
    const resolvingConflict = ref(false);

    const examplePlaceholder = EXAMPLE;

    const allViews = computed<ViewEntry[]>(() => entries.value.map((e) => decorate(e, brokenIcons)));
    const filteredView = computed<ViewEntry[]>(() => {
      const q = search.value.trim();
      if (!q) return allViews.value;
      return allViews.value.filter((v) => matchesQuery(v, q));
    });

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
      uploadMode.value     = 'paste';
      uploadText.value     = '';
      filePickedName.value = null;
      git.url = '';  git.token = ''; git.branch = ''; git.path = '';
      uploadError.value    = null;
      uploadSuccess.value  = null;
      uploading.value      = true;
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

    function ensureId(entry: any) {
      if (!entry.id && entry.name) entry.id = entry.name;
    }

    function summarize(resp: BulkUploadResult, fallback: string): string {
      const parts: string[] = [];
      if (resp?.created) parts.push(`created ${ resp.created }`);
      if (resp?.updated) parts.push(`updated ${ resp.updated }`);
      if (resp?.skipped) parts.push(`skipped ${ resp.skipped }`);
      if (resp?.failed)  parts.push(`failed ${ resp.failed }`);
      if (parts.length) return parts.join(', ');
      return resp?.message || fallback;
    }

    // Detect the 409 + conflicts envelope our backend sends back in abort
    // mode. Returns the list of conflicting ids, or null when it's a
    // different error shape.
    function parseConflictsFromError(e: any): string[] | null {
      if (e?.status !== 409) return null;
      const data = e?.data || {};
      if (Array.isArray(data.conflicts) && data.conflicts.length) {
        return data.conflicts.filter((x: any) => typeof x === 'string');
      }
      return null;
    }

    async function runBulk(items: Partial<MCPServer>[], mode?: ConflictMode): Promise<BulkUploadResult> {
      const resp = await registryApi.uploadBulk(items, mode);
      uploadSuccess.value = summarize(resp, `Uploaded ${ items.length } entries.`);
      await refresh();
      return resp;
    }

    async function runGit(mode?: ConflictMode): Promise<BulkUploadResult> {
      const resp = await registryApi.uploadGit({
        url:        git.url.trim(),
        token:      git.token.trim() || undefined,
        branch:     git.branch.trim() || undefined,
        path:       git.path.trim() || undefined,
        onConflict: mode,
      });
      uploadSuccess.value = summarize(resp, `Uploaded ${ resp?.count ?? 0 } entries.`);
      await refresh();
      return resp;
    }

    // Paste + File modes share this path: parse as YAML/JSON, dispatch
    // to /upload (single object) or /upload/bulk (array).
    async function submitText() {
      let body: any;
      try {
        body = parsePayload(uploadText.value);
      } catch (e: any) {
        uploadError.value = `Invalid YAML/JSON: ${ e.message }`;
        return;
      }
      submitting.value    = true;
      uploadError.value   = null;
      uploadSuccess.value = null;
      try {
        if (Array.isArray(body)) {
          const items = body.filter((it) => it && (it.id || it.name));
          items.forEach(ensureId);
          if (!items.length) {
            uploadError.value = 'No entries with "id" or "name" found.';
            return;
          }
          try {
            await runBulk(items);
            setTimeout(() => { if (uploading.value) closeUpload(); }, 800);
          } catch (e: any) {
            const conflicts = parseConflictsFromError(e);
            if (conflicts) {
              conflictState.value = {
                ids:    conflicts,
                kind:   'bulk',
                replay: (mode) => runBulk(items, mode),
              };
            } else {
              uploadError.value = e?.data?.error || e?.message || 'Upload failed';
            }
          }
        } else {
          if (!body || (!body.id && !body.name)) {
            uploadError.value = 'Document must include "id" (or "name").';
            return;
          }
          ensureId(body);
          await registryApi.upload(body);
          uploadSuccess.value = `Uploaded ${ body.id }.`;
          await refresh();
          setTimeout(() => { if (uploading.value) closeUpload(); }, 800);
        }
      } catch (e: any) {
        uploadError.value = e?.data?.error || e?.message || 'Upload failed';
      } finally {
        submitting.value = false;
      }
    }

    async function submitGit() {
      if (!git.url.trim()) {
        uploadError.value = 'URL is required.';
        return;
      }
      submitting.value    = true;
      uploadError.value   = null;
      uploadSuccess.value = null;
      try {
        await runGit();
        setTimeout(() => { if (uploading.value) closeUpload(); }, 800);
      } catch (e: any) {
        const conflicts = parseConflictsFromError(e);
        if (conflicts) {
          conflictState.value = {
            ids:    conflicts,
            kind:   'git',
            replay: (mode) => runGit(mode),
          };
        } else {
          uploadError.value = e?.data?.error || e?.message || 'Git upload failed';
        }
      } finally {
        submitting.value = false;
      }
    }

    async function resolveConflict(mode: ConflictMode) {
      if (!conflictState.value) return;
      resolvingConflict.value = true;
      uploadError.value       = null;
      try {
        await conflictState.value.replay(mode);
        conflictState.value = null;
        setTimeout(() => { if (uploading.value) closeUpload(); }, 800);
      } catch (e: any) {
        uploadError.value = e?.data?.error || e?.message || 'Retry failed';
      } finally {
        resolvingConflict.value = false;
      }
    }

    function cancelConflict() {
      conflictState.value = null;
    }

    function submitUploadDispatch() {
      if (uploadMode.value === 'git') return submitGit();
      return submitText();
    }

    function onFilePicked(ev: Event) {
      const input = ev.target as HTMLInputElement;
      const file  = input.files?.[0];
      if (!file) return;
      filePickedName.value = file.name;
      uploadError.value    = null;
      uploadSuccess.value  = null;
      const reader = new FileReader();
      reader.onload  = () => { uploadText.value = String(reader.result || ''); };
      reader.onerror = () => { uploadError.value = `Could not read ${ file.name }`; };
      reader.readAsText(file);
    }

    const canSubmitUpload = computed(() => {
      if (uploadMode.value === 'git') return !!git.url.trim();
      return !!uploadText.value.trim();
    });

    const needsPath = computed(() => /^https?:\/\/github\.com\/[^/]+\/[^/]+\/?$/i.test(git.url.trim()));

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
      uploading, submitting, uploadMode, uploadTabs,
      uploadText, uploadError, uploadSuccess, filePickedName, git,
      examplePlaceholder, needsPath, canSubmitUpload,
      filteredView,
      refresh, openUpload, closeUpload,
      submitUploadDispatch, onFilePicked,
      confirmDelete, onIconError,
      conflictState, resolvingConflict, resolveConflict, cancelConflict,
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
.ai-up-banner--success {
  background: var(--success-banner-bg, rgba(22, 101, 52, 0.1));
  color:      var(--success, #166534);
  border:     1px solid var(--success, #166534);
}
.conflict-list {
  display:   flex;
  flex-wrap: wrap;
  gap:       6px;
  margin:    4px 0 8px;
}
.chip {
  font-size:     11px;
  padding:       2px 8px;
  border-radius: 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  color:         var(--muted, #888);
}
.chip--warning {
  // Darker amber for WCAG AA on the pale warning bg — same color we use
  // in AiUpPill's warning tone.
  background: var(--warning-banner-bg, rgba(244, 161, 41, 0.15));
  color:      #8a5a07;
  border:     1px solid rgba(138, 90, 7, 0.25);
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
  margin:     0 4px;
}
.ai-up-input {
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.file-picker {
  display:        flex;
  align-items:    center;
  gap:            10px;
  padding:        8px 10px;
  border:         1px dashed var(--border, #ddd);
  border-radius:  6px;
  cursor:         pointer;
  font-size:      13px;
}
.file-picker input[type='file'] {
  font-size: 12px;
}
.file-picker__name {
  color:     var(--muted, #888);
  font-size: 12px;
  font-family: var(--font-mono, monospace);
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
