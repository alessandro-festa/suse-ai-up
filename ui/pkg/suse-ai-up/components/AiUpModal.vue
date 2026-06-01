<template>
  <Teleport to="body">
    <div v-if="open" class="ai-up-modal__backdrop" @click.self="$emit('close')">
      <div class="ai-up-modal" role="dialog" aria-modal="true">
        <header class="ai-up-modal__header">
          <h2 class="ai-up-modal__title">{{ title }}</h2>
          <button type="button" class="ai-up-modal__close" aria-label="Close" @click="$emit('close')">×</button>
        </header>
        <div class="ai-up-modal__body">
          <slot />
        </div>
        <footer v-if="$slots.actions" class="ai-up-modal__footer">
          <slot name="actions" />
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

export default defineComponent({
  name:  'AiUpModal',
  props: {
    open:  { type: Boolean, required: true },
    title: { type: String, default: '' },
  },
  emits: ['close'],
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-modal__backdrop {
  position:        fixed;
  inset:           0;
  background:      rgba(0, 0, 0, 0.45);
  display:         flex;
  align-items:     center;
  justify-content: center;
  z-index:         1000;
  padding:         20px;
}
.ai-up-modal {
  background:    var(--body-bg, #fff);
  color:         var(--body-text, #333);
  border:        1px solid var(--border, #ddd);
  border-radius: $ai-up-radius;
  width:         min(560px, 100%);
  max-height:    90vh;
  display:       flex;
  flex-direction: column;
  box-shadow:    0 10px 30px rgba(0, 0, 0, 0.25);
}
.ai-up-modal__header {
  display:         flex;
  align-items:     center;
  justify-content: space-between;
  padding:         12px 14px;
  border-bottom:   1px solid var(--border, #ddd);
}
.ai-up-modal__title {
  margin:    0;
  font-size: 16px;
  font-weight: 600;
}
.ai-up-modal__close {
  background:    transparent;
  border:        none;
  font-size:     22px;
  line-height:   1;
  color:         var(--muted, #888);
  cursor:        pointer;
  padding:       0 6px;
}
.ai-up-modal__body {
  padding:    14px;
  overflow:   auto;
  display:    flex;
  flex-direction: column;
  gap:        10px;
  font-size:  13px;
}
.ai-up-modal__footer {
  display:         flex;
  justify-content: flex-end;
  gap:             8px;
  padding:         10px 14px;
  border-top:      1px solid var(--border, #ddd);
}
</style>
