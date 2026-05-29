<template>
  <AiUpPage
    title="Virtual MCP"
    subtitle="Composed routes that aggregate tools across adapters"
  >
    <AiUpGallery>
      <AiUpCard title="Coming soon" subtitle="Virtual MCP routes will appear here">
        <template #pill>
          <AiUpPill tone="info" label="Preview" />
        </template>
        <p>Virtual MCP composes tools, resources, and prompts from multiple adapters into a single addressable route.</p>
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
  name:       'VirtualMCP',
  components: { AiUpPage, AiUpGallery, AiUpCard, AiUpPill },
});
</script>
