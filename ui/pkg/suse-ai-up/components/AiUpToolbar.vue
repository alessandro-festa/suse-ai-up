<template>
  <div class="ai-up-toolbar">
    <input
      v-if="search !== undefined"
      :value="search"
      class="ai-up-toolbar__search"
      type="search"
      :placeholder="searchPlaceholder"
      @input="$emit('update:search', $event.target.value)"
    />
    <div v-if="$slots.filters" class="ai-up-toolbar__filters">
      <slot name="filters" />
    </div>
    <div v-if="$slots.actions" class="ai-up-toolbar__actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script>
import { defineComponent } from 'vue';

export default defineComponent({
  name:    'AiUpToolbar',
  props:   {
    search:            { type: String, default: undefined },
    searchPlaceholder: { type: String, default: 'Search...' },
  },
  emits:   ['update:search'],
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-toolbar {
  display:     flex;
  flex-wrap:   wrap;
  gap:         $ai-up-gap-md;
  align-items: center;
}
.ai-up-toolbar__search {
  flex:           1 1 240px;
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  $ai-up-radius;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.ai-up-toolbar__filters,
.ai-up-toolbar__actions {
  display:     flex;
  gap:         $ai-up-gap-sm;
  align-items: center;
}
</style>
