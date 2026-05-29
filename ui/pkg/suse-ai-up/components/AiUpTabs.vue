<template>
  <div class="ai-up-tabs">
    <div class="ai-up-tabs__bar" role="tablist">
      <button
        v-for="t in tabs"
        :key="t.key"
        type="button"
        role="tab"
        :aria-selected="active === t.key"
        class="ai-up-tabs__tab"
        :class="{ 'ai-up-tabs__tab--active': active === t.key }"
        @click="$emit('update:active', t.key)"
      >
        {{ t.label }}
        <span v-if="t.badge !== undefined && t.badge !== null" class="ai-up-tabs__badge">{{ t.badge }}</span>
      </button>
    </div>
    <div class="ai-up-tabs__panel" role="tabpanel">
      <slot />
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from 'vue';

export interface TabDef {
  key:    string;
  label:  string;
  badge?: string | number;
}

export default defineComponent({
  name:  'AiUpTabs',
  props: {
    tabs:   { type: Array as PropType<TabDef[]>, required: true },
    active: { type: String, required: true },
  },
  emits: ['update:active'],
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-tabs__bar {
  display:       flex;
  gap:           4px;
  border-bottom: 1px solid var(--border, #ddd);
  margin-bottom: 14px;
}
.ai-up-tabs__tab {
  display:        inline-flex;
  align-items:    center;
  gap:            6px;
  padding:        8px 14px;
  background:     transparent;
  border:         none;
  border-bottom:  2px solid transparent;
  color:          var(--muted, #888);
  font:           inherit;
  font-size:      13px;
  cursor:         pointer;
  margin-bottom:  -1px;
}
.ai-up-tabs__tab:hover {
  color: var(--body-text, #333);
}
.ai-up-tabs__tab--active {
  color:        var(--primary, #1d4ed8);
  border-bottom-color: var(--primary, #1d4ed8);
  font-weight:  600;
}
.ai-up-tabs__badge {
  font-size:     11px;
  padding:       1px 7px;
  border-radius: 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.12));
  color:         var(--muted, #888);
  font-weight:   500;
}
.ai-up-tabs__panel {
  display:        flex;
  flex-direction: column;
  gap:            $ai-up-gap-lg;
}
</style>
