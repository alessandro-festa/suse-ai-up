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
        <button class="ai-up-btn" disabled>Upload entry</button>
      </template>
    </AiUpToolbar>
    <AiUpGallery>
      <AiUpCard
        v-for="i in 3"
        :key="i"
        :title="`mcp-server-${ i }`"
        subtitle="Placeholder — wiring lands in a follow-up PR"
      >
        <template #pill>
          <AiUpPill tone="neutral" label="Stub" />
        </template>
        <template #meta>
          <span>v0.0.0</span>
          <span>Source: placeholder-registry</span>
        </template>
        <p>Card will show description, tools, packages, and route assignment hooks.</p>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script>
import { defineComponent, ref } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';

export default defineComponent({
  name:       'MCPRegistry',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill },
  setup() {
    return { search: ref('') };
  },
});
</script>

<style lang="scss" scoped>
.ai-up-btn {
  padding:        6px 12px;
  border-radius:  6px;
  border:         1px solid var(--border, #ddd);
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
  cursor:         not-allowed;
  opacity:        0.6;
}
</style>
