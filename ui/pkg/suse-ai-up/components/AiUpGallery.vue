<template>
  <div class="ai-up-gallery">
    <slot />
  </div>
</template>

<script>
import { defineComponent } from 'vue';

export default defineComponent({ name: 'AiUpGallery' });
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-gallery {
  display:               grid;
  grid-template-columns: repeat(auto-fill, minmax($ai-up-card-min-width, 1fr));
  gap:                   $ai-up-gap-lg;
}
</style>
