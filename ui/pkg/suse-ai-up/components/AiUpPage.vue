<template>
  <div class="ai-up-page">
    <header v-if="$slots.header || title" class="ai-up-page__header">
      <slot name="header">
        <h1>{{ title }}</h1>
        <p v-if="subtitle" class="ai-up-page__subtitle">{{ subtitle }}</p>
      </slot>
    </header>
    <div class="ai-up-page__body">
      <slot />
    </div>
  </div>
</template>

<script>
import { defineComponent } from 'vue';

export default defineComponent({
  name:  'AiUpPage',
  props: {
    title:    { type: String, default: '' },
    subtitle: { type: String, default: '' },
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-page {
  padding:        $ai-up-pad-pg;
  display:        flex;
  flex-direction: column;
  gap:            $ai-up-gap-lg;
}
.ai-up-page__header h1 {
  margin:    0;
  font-size: 24px;
}
.ai-up-page__subtitle {
  margin:    4px 0 0;
  color:     var(--muted, #888);
  font-size: 13px;
}
.ai-up-page__body {
  display:        flex;
  flex-direction: column;
  gap:            $ai-up-gap-lg;
}
</style>
