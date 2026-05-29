<template>
  <AiUpPage
    title="Smart Agents"
    subtitle="Agents that consume MCP routes via pluggable protocols"
  >
    <AiUpGallery>
      <AiUpCard title="No HTTP API yet" subtitle="Agent CRs aren't exposed via the backend HTTP surface">
        <template #pill>
          <AiUpPill tone="warning" label="Operator-only" />
        </template>
        <p>
          Agent registration, protocol selection (A2A and future protocols), and ACL bindings will live here.
          The CRD (<code>agents.mcp.suse.com</code>) and reconciler are in place — but the backend HTTP API
          doesn't yet expose CRUD endpoints for them.
        </p>
        <p>For now, manage agents with <code>kubectl</code> directly:</p>
        <pre class="ai-up-pre">kubectl --namespace suse-ai-up get agents</pre>
        <template #footer>Tracking: this page will wire up once the HTTP surface lands.</template>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';

export default defineComponent({
  name:       'SmartAgents',
  components: { AiUpPage, AiUpGallery, AiUpCard, AiUpPill },
});
</script>

<style lang="scss" scoped>
.ai-up-pre {
  margin:        8px 0 0;
  padding:       8px 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  font-family:   var(--font-mono, monospace);
  font-size:     12px;
}
</style>
