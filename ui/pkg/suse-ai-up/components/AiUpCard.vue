<template>
  <div class="ai-up-card">
    <header v-if="$slots.header || title" class="ai-up-card__header">
      <slot name="header">
        <div class="ai-up-card__title-row">
          <h3 class="ai-up-card__title">{{ title }}</h3>
          <slot name="pill" />
        </div>
        <p v-if="subtitle" class="ai-up-card__subtitle">{{ subtitle }}</p>
      </slot>
    </header>
    <div v-if="$slots.meta" class="ai-up-card__meta">
      <slot name="meta" />
    </div>
    <div v-if="$slots.default" class="ai-up-card__body">
      <slot />
    </div>
    <div v-if="$slots.footer" class="ai-up-card__footer">
      <slot name="footer" />
    </div>
    <div v-if="$slots.actions" class="ai-up-card__actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script>
import { defineComponent } from 'vue';

export default defineComponent({
  name:  'AiUpCard',
  props: {
    title:    { type: String, default: '' },
    subtitle: { type: String, default: '' },
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-card {
  display:        flex;
  flex-direction: column;
  gap:            $ai-up-gap-md;
  padding:        $ai-up-gap-lg;
  border:         1px solid var(--border, #ddd);
  border-radius:  $ai-up-radius;
  background:     var(--body-bg, #fff);
}
.ai-up-card__title-row {
  display:         flex;
  justify-content: space-between;
  align-items:     center;
  gap:             $ai-up-gap-sm;
}
.ai-up-card__title {
  margin:    0;
  font-size: 14px;
  font-weight: 600;
}
.ai-up-card__subtitle {
  margin:    4px 0 0;
  color:     var(--muted, #888);
  font-size: 12px;
}
.ai-up-card__meta {
  display:    flex;
  flex-wrap:  wrap;
  gap:        6px;
  font-size:  12px;
  color:      var(--muted, #888);
}
.ai-up-card__body {
  font-size:    13px;
  line-height:  1.4;
}
.ai-up-card__footer {
  font-size: 12px;
  color:     var(--muted, #888);
}
.ai-up-card__actions {
  display:         flex;
  justify-content: flex-end;
  gap:             6px;
}
</style>
