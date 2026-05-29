<template>
  <span class="ai-up-pill" :class="`ai-up-pill--${tone}`">
    <slot>{{ label }}</slot>
  </span>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

const TONES = ['info', 'success', 'warning', 'error', 'neutral'];

export default defineComponent({
  name:  'AiUpPill',
  props: {
    tone:  {
      type:      String,
      default:   'neutral',
      validator: (v: string) => TONES.includes(v),
    },
    label: { type: String, default: '' },
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-pill {
  display:        inline-flex;
  align-items:    center;
  padding:        2px 8px;
  border-radius:  $ai-up-radius-pill;
  font-size:      11px;
  font-weight:    500;
  line-height:    1.6;
  white-space:    nowrap;
  background:     var(--border, #eee);
  color:          var(--body-text, #333);
}
.ai-up-pill--info {
  background: var(--info-banner-bg, rgba(29, 78, 216, 0.1));
  color:      var(--primary, #1d4ed8);
}
.ai-up-pill--success {
  background: var(--success-banner-bg, rgba(22, 101, 52, 0.1));
  color:      var(--success, #166534);
}
.ai-up-pill--warning {
  background: var(--warning-banner-bg, rgba(244, 161, 41, 0.15));
  color:      var(--warning, #f4a129);
}
.ai-up-pill--error {
  background: var(--error-banner-bg, rgba(220, 38, 38, 0.1));
  color:      var(--error, #dc2626);
}
.ai-up-pill--neutral {
  background: var(--disabled-bg, rgba(136, 136, 136, 0.12));
  color:      var(--muted, #888);
}
</style>
