<template>
  <AiUpPage
    title="Smart Agents"
    subtitle="Agents that consume MCP routes via pluggable protocols"
  >
    <AiUpGallery>
      <AiUpCard title="Coming soon" subtitle="Agent CRs will be listed here">
        <template #pill>
          <AiUpPill tone="info" label="Preview" />
        </template>
        <p>Agent registration, protocol selection (A2A and others), and ACL bindings will live here.</p>
        <template #footer>Phase B stub.</template>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script>
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
