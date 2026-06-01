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
      <AiUpCard
        v-for="e in filtered"
        :key="e.id"
        :title="e.id"
        :subtitle="e.name || ''"
      >
        <template #pill>
          <AiUpPill v-if="e.version" tone="info" :label="`v${ e.version }`" />
          <AiUpPill v-else tone="neutral" label="unversioned" />
        </template>
        <template #meta>
          <span v-if="e.image" class="ai-up-truncate">Image: {{ e.image }}</span>
          <span v-if="e.url" class="ai-up-truncate">URL: {{ e.url }}</span>
        </template>
        <p v-if="e.description" class="ai-up-body">{{ e.description }}</p>
        <template #footer v-if="e.routeAssignments?.length">
          {{ e.routeAssignments.length }} route assignment{{ e.routeAssignments.length === 1 ? '' : 's' }}
        </template>
        <template #actions>
          <button class="ai-up-btn ai-up-btn--ghost" @click="viewRaw(e)">View JSON</button>
          <button class="ai-up-btn ai-up-btn--danger" :disabled="deleting === e.id" @click="confirmDelete(e)">
            {{ deleting === e.id ? 'Deleting...' : 'Delete' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <AiUpModal :open="uploading" title="Upload registry entry" @close="closeUpload">
      <p class="ai-up-muted">
        Paste a JSON document matching the MCPServer schema. Minimum fields: <code>id</code>, <code>name</code>.
      </p>
      <textarea
        v-model="uploadJson"
        class="ai-up-textarea ai-up-textarea--large"
        rows="14"
        spellcheck="false"
        :placeholder="examplePlaceholder"
      ></textarea>
      <div v-if="uploadError" class="ai-up-banner ai-up-banner--error">{{ uploadError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeUpload">Cancel</button>
        <button class="ai-up-btn" :disabled="!uploadJson.trim() || submitting" @click="submitUpload">
          {{ submitting ? 'Uploading...' : 'Upload' }}
        </button>
      </template>
    </AiUpModal>

    <AiUpModal :open="!!viewing" :title="viewing?.id || ''" @close="viewing = null">
      <pre class="ai-up-pre">{{ viewingJson }}</pre>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="viewing = null">Close</button>
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
import { registryApi, MCPServer } from '../services/registry';

const EXAMPLE = `{
  "id": "weather-mcp",
  "name": "Weather MCP",
  "description": "Forecast and current-conditions tools.",
  "version": "0.1.0",
  "image": "ghcr.io/example/weather-mcp:0.1.0"
}`;

export default defineComponent({
  name:       'MCPRegistry',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal },
  setup() {
    const entries     = ref<MCPServer[]>([]);
    const search      = ref('');
    const loading     = ref(false);
    const error       = ref<string | null>(null);
    const deleting    = ref<string | null>(null);
    const uploading   = ref(false);
    const submitting  = ref(false);
    const uploadJson  = ref('');
    const uploadError = ref<string | null>(null);
    const viewing     = ref<MCPServer | null>(null);

    const examplePlaceholder = EXAMPLE;

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return entries.value;
      return entries.value.filter((e) =>
        (e.id || '').toLowerCase().includes(q)
        || (e.name || '').toLowerCase().includes(q)
        || (e.description || '').toLowerCase().includes(q),
      );
    });

    const viewingJson = computed(() => (viewing.value ? JSON.stringify(viewing.value, null, 2) : ''));

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        entries.value = await registryApi.list();
      } catch (e: any) {
        error.value = e?.message || 'Unknown error';
      } finally {
        loading.value = false;
      }
    }

    function openUpload() {
      uploadJson.value  = '';
      uploadError.value = null;
      uploading.value   = true;
    }

    function closeUpload() {
      uploading.value = false;
    }

    async function submitUpload() {
      let body: any;
      try {
        body = JSON.parse(uploadJson.value);
      } catch (e: any) {
        uploadError.value = `Invalid JSON: ${ e.message }`;
        return;
      }
      if (!body.id) {
        uploadError.value = 'JSON must include an "id" field.';
        return;
      }
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

    function viewRaw(e: MCPServer) {
      viewing.value = e;
    }

    async function confirmDelete(e: MCPServer) {
      if (!window.confirm(`Delete registry entry "${ e.id }"? Adapters built from it stay in place.`)) return;
      deleting.value = e.id;
      try {
        await registryApi.remove(e.id);
        await refresh();
      } catch (err: any) {
        error.value = err?.message || 'Delete failed';
      } finally {
        deleting.value = null;
      }
    }

    onMounted(refresh);

    return {
      entries, search, loading, error, deleting,
      uploading, submitting, uploadJson, uploadError, examplePlaceholder,
      viewing, viewingJson,
      filtered,
      refresh, openUpload, closeUpload, submitUpload, viewRaw, confirmDelete,
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
.ai-up-textarea--large {
  min-height: 220px;
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
  margin:    0 0 6px;
}
.ai-up-body {
  margin:      0;
  font-size:   13px;
  line-height: 1.4;
}
.ai-up-truncate {
  display:       inline-block;
  max-width:     100%;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
  font-family:   var(--font-mono, monospace);
  font-size:     12px;
}
.ai-up-pre {
  margin:        0;
  padding:       10px 12px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  font-family:   var(--font-mono, monospace);
  font-size:     12px;
  white-space:   pre;
  overflow:      auto;
  max-height:    60vh;
}
</style>
