<template>
  <AiUpPage title="Settings" subtitle="Backend connection and global preferences">
    <AiUpGallery>
      <AiUpCard title="Backend URL">
        <template #meta>
          <span>Currently: {{ backendUrl }}</span>
        </template>
        <p>The Rancher extension talks to the suse-ai-up backend over HTTP. Configure the base URL here; the value is stored in your browser.</p>
        <div class="ai-up-form-row">
          <input
            v-model="backendInput"
            type="text"
            class="ai-up-input"
            placeholder="http://localhost:8911"
          />
          <button class="ai-up-btn" @click="save">Save</button>
        </div>
        <template #footer v-if="savedAt">
          Saved at {{ savedAt }}.
        </template>
      </AiUpCard>
    </AiUpGallery>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import { getBackendUrl, setBackendUrl } from '../config/api-config';

export default defineComponent({
  name:       'Settings',
  components: { AiUpPage, AiUpGallery, AiUpCard },
  setup() {
    const backendUrl   = ref(getBackendUrl());
    const backendInput = ref(getBackendUrl());
    const savedAt      = ref<string | null>(null);

    function save() {
      const v = backendInput.value.trim();
      if (!v) {
        return;
      }
      setBackendUrl(v);
      backendUrl.value = v;
      savedAt.value    = new Date().toLocaleTimeString();
    }

    return { backendUrl, backendInput, savedAt, save };
  },
});
</script>

<style lang="scss" scoped>
.ai-up-form-row {
  display:     flex;
  gap:         8px;
  align-items: center;
}
.ai-up-input {
  flex:           1;
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
</style>
