<template>
  <AiUpPage title="SUSE AI Up" subtitle="Universal MCP proxy gateway">
    <div v-if="healthError" class="ai-up-banner ai-up-banner--error">
      Backend unreachable: {{ healthError }}
    </div>
    <AiUpGallery>
      <AiUpCard title="Backend health">
        <template #pill>
          <AiUpPill v-if="health" tone="success" label="OK" />
          <AiUpPill v-else-if="healthError" tone="error" label="Unreachable" />
          <AiUpPill v-else tone="neutral" label="Checking..." />
        </template>
        <template #meta>
          <span>Backend: {{ backendUrl }}</span>
        </template>
        <p v-if="health">Version <strong>{{ health.version || 'n/a' }}</strong> at {{ health.timestamp }}.</p>
        <p v-else-if="healthError" class="ai-up-muted">{{ healthError }}</p>
        <template #footer>Polled once on page load.</template>
      </AiUpCard>
      <AiUpCard title="Get started" subtitle="Next steps for new operators">
        <ul class="ai-up-list">
          <li>Register an MCP adapter from the registry.</li>
          <li>Assign users or groups to expose routes.</li>
          <li>Compose virtual MCP routes across adapters.</li>
        </ul>
      </AiUpCard>
      <AiUpCard title="Documentation">
        <p>SUSE AI Up bundles the Rancher extension with the backend operator and HTTP gateway.</p>
        <template #actions>
          <a href="https://github.com/SUSE/suse-ai-up" target="_blank" rel="noopener">Open repository</a>
        </template>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, onMounted } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import { healthApi, HealthResponse } from '../services/health';
import { getBackendUrl } from '../config/api-config';

export default defineComponent({
  name:       'Home',
  components: { AiUpPage, AiUpCard, AiUpPill, AiUpGallery },
  setup() {
    const health      = ref<HealthResponse | null>(null);
    const healthError = ref<string | null>(null);
    const backendUrl  = ref(getBackendUrl());

    onMounted(async () => {
      try {
        health.value = await healthApi.check();
      } catch (e: any) {
        healthError.value = e?.message || 'Unknown error';
      }
    });

    return { health, healthError, backendUrl };
  },
});
</script>

<style lang="scss" scoped>
.ai-up-banner {
  padding:       10px 12px;
  border-radius: 6px;
  font-size:     13px;
}
.ai-up-banner--error {
  background: var(--error-banner-bg, rgba(220, 38, 38, 0.1));
  color:      var(--error, #dc2626);
  border:     1px solid var(--error, #dc2626);
}
.ai-up-list {
  margin:      0;
  padding-left: 18px;
  font-size:   13px;
  line-height: 1.5;
}
.ai-up-muted {
  color: var(--muted, #888);
}
</style>
