<template>
  <AiUpPage title="Settings" subtitle="How the extension reaches the suse-ai-up backend">
    <AiUpGallery>
      <AiUpCard title="Backend connection">
        <template #pill>
          <AiUpPill :tone="mode === 'proxy' ? 'info' : 'warning'" :label="mode === 'proxy' ? 'In-cluster proxy' : 'Direct URL'" />
        </template>
        <template #meta>
          <span>Effective base URL:</span>
          <code class="ai-up-truncate">{{ effectiveUrl }}</code>
        </template>

        <p>
          By default, the extension routes requests through the Rancher cluster proxy to the
          <code>{{ service.name }}</code> Service in namespace <code>{{ service.namespace }}</code>
          on cluster <code>{{ service.cluster }}</code> (port <code>{{ service.port }}</code>).
          Same-origin HTTPS via your Rancher session — no Mixed Content blocking, no extra auth.
        </p>

        <fieldset class="ai-up-fieldset">
          <legend>In-cluster Service</legend>
          <div class="ai-up-grid">
            <label>Cluster ID
              <input v-model="form.cluster" class="ai-up-input" placeholder="local" />
            </label>
            <label>Namespace
              <input v-model="form.namespace" class="ai-up-input" placeholder="suse-ai-up" />
            </label>
            <label>Service name
              <input v-model="form.name" class="ai-up-input" placeholder="suse-ai-up" />
            </label>
            <label>Port
              <input v-model.number="form.port" class="ai-up-input" type="number" min="1" max="65535" />
            </label>
          </div>
          <div class="ai-up-actions">
            <button class="ai-up-btn" @click="saveService">Save Service</button>
            <button class="ai-up-btn ai-up-btn--ghost" @click="resetService">Reset to defaults</button>
          </div>
        </fieldset>

        <fieldset class="ai-up-fieldset">
          <legend>Direct URL override (dev only)</legend>
          <p class="ai-up-muted">
            Use this when running outside Rancher (e.g. <code>yarn dev</code> against a local backend on <code>http://localhost:8911</code>).
            When set, requests bypass the cluster proxy entirely. Leave empty to use the in-cluster Service above.
          </p>
          <div class="ai-up-form-row">
            <input v-model="directUrlInput" type="text" class="ai-up-input" placeholder="http://localhost:8911" />
            <button class="ai-up-btn" @click="saveDirect">Save</button>
            <button class="ai-up-btn ai-up-btn--ghost" @click="clearDirect">Clear</button>
          </div>
        </fieldset>

        <template #footer v-if="savedAt">Saved at {{ savedAt }}.</template>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, computed } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import {
  describeBaseUrl,
  getServiceLocation,
  setServiceLocation,
  getDirectBackendUrl,
  setDirectBackendUrl,
  DEFAULT_SERVICE_LOCATION,
  ServiceLocation,
} from '../config/api-config';

export default defineComponent({
  name:       'Settings',
  components: { AiUpPage, AiUpGallery, AiUpCard, AiUpPill },
  setup() {
    const service        = ref<ServiceLocation>({ ...getServiceLocation() });
    const form           = ref<ServiceLocation>({ ...service.value });
    const directUrlInput = ref<string>(getDirectBackendUrl());
    const savedAt        = ref<string | null>(null);

    const effectiveUrl = computed(() => describeBaseUrl().url);
    const mode         = computed(() => describeBaseUrl().mode);

    function stamp() {
      savedAt.value = new Date().toLocaleTimeString();
    }

    function saveService() {
      const loc: ServiceLocation = {
        cluster:   form.value.cluster.trim() || DEFAULT_SERVICE_LOCATION.cluster,
        namespace: form.value.namespace.trim() || DEFAULT_SERVICE_LOCATION.namespace,
        name:      form.value.name.trim() || DEFAULT_SERVICE_LOCATION.name,
        port:      Number(form.value.port) || DEFAULT_SERVICE_LOCATION.port,
      };
      setServiceLocation(loc);
      service.value = loc;
      form.value    = { ...loc };
      stamp();
    }

    function resetService() {
      const loc = { ...DEFAULT_SERVICE_LOCATION };
      setServiceLocation(loc);
      service.value = loc;
      form.value    = { ...loc };
      stamp();
    }

    function saveDirect() {
      setDirectBackendUrl(directUrlInput.value.trim());
      stamp();
    }

    function clearDirect() {
      directUrlInput.value = '';
      setDirectBackendUrl('');
      stamp();
    }

    return {
      service, form, directUrlInput, savedAt,
      effectiveUrl, mode,
      saveService, resetService, saveDirect, clearDirect,
    };
  },
});
</script>

<style lang="scss" scoped>
.ai-up-fieldset {
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  padding:       12px 14px 14px;
  margin:        0;
  display:       flex;
  flex-direction: column;
  gap:           10px;
}
.ai-up-fieldset legend {
  font-size:   12px;
  font-weight: 600;
  color:       var(--body-text, #333);
  padding:     0 6px;
}
.ai-up-grid {
  display:               grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap:                   10px;
}
.ai-up-grid label {
  display:        flex;
  flex-direction: column;
  gap:            4px;
  font-size:      12px;
  color:          var(--muted, #888);
}
.ai-up-actions,
.ai-up-form-row {
  display:     flex;
  flex-wrap:   wrap;
  gap:         8px;
  align-items: center;
}
.ai-up-input {
  flex:           1;
  min-width:      0;
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.ai-up-btn {
  padding:        6px 12px;
  border-radius:  6px;
  border:         1px solid var(--primary, #1d4ed8);
  background:     var(--primary, #1d4ed8);
  color:          #fff;
  font-size:      13px;
  cursor:         pointer;
}
.ai-up-btn--ghost {
  background: transparent;
  color:      var(--primary, #1d4ed8);
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
