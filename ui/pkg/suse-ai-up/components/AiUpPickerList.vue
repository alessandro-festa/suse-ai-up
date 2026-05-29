<template>
  <div class="picker-multi">
    <input
      v-if="searchable"
      v-model="query"
      type="search"
      class="picker-multi__search"
      :placeholder="searchPlaceholder"
    />
    <div v-if="!items.length" class="picker-multi__empty">{{ emptyLabel }}</div>
    <div v-else-if="!filtered.length" class="picker-multi__empty">No matches for "{{ query }}".</div>
    <div v-else class="picker-multi__list">
      <label
        v-for="it in filtered"
        :key="it.id"
        class="picker-multi__row"
        :class="{ 'picker-multi__row--selected': isSelected(it.id) }"
      >
        <input
          type="checkbox"
          :checked="isSelected(it.id)"
          class="picker-multi__check"
          @change="toggle(it.id, ($event.target as HTMLInputElement).checked)"
        />
        <div class="picker-multi__body">
          <span class="picker-multi__label">{{ it.label }}</span>
          <span v-if="it.sublabel" class="picker-multi__sublabel">{{ it.sublabel }}</span>
        </div>
      </label>
    </div>
    <div v-if="selected.length" class="picker-multi__footer">
      {{ selected.length }} selected
      <button type="button" class="picker-multi__clear" @click="clearAll">Clear</button>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, computed, PropType } from 'vue';

export interface PickerItem {
  id:        string;
  label:     string;
  sublabel?: string;
}

export default defineComponent({
  name:  'AiUpPickerList',
  props: {
    items:             { type: Array as PropType<PickerItem[]>, required: true },
    selected:          { type: Array as PropType<string[]>, required: true },
    searchable:        { type: Boolean, default: true },
    searchPlaceholder: { type: String, default: 'Search...' },
    emptyLabel:        { type: String, default: 'No items available.' },
  },
  emits: ['update:selected'],
  setup(props, { emit }) {
    const query = ref('');

    const filtered = computed(() => {
      const q = query.value.trim().toLowerCase();
      if (!q) return props.items;
      return props.items.filter((it) =>
        it.label.toLowerCase().includes(q)
        || (it.sublabel || '').toLowerCase().includes(q)
        || it.id.toLowerCase().includes(q),
      );
    });

    const selectedSet = computed(() => new Set(props.selected));
    function isSelected(id: string) { return selectedSet.value.has(id); }

    function toggle(id: string, on: boolean) {
      const next = new Set(props.selected);
      if (on) next.add(id);
      else    next.delete(id);
      emit('update:selected', Array.from(next));
    }

    function clearAll() {
      emit('update:selected', []);
    }

    return { query, filtered, isSelected, toggle, clearAll };
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.picker-multi {
  display:        flex;
  flex-direction: column;
  gap:            8px;
}
.picker-multi__search {
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.picker-multi__empty {
  padding:    12px;
  text-align: center;
  font-size:  12px;
  color:      var(--muted, #888);
  border:     1px dashed var(--border, #ddd);
  border-radius: 6px;
}
.picker-multi__list {
  max-height:   200px;
  overflow-y:   auto;
  overflow-x:   hidden;
  border:       1px solid var(--border, #ddd);
  border-radius: 6px;
}
.picker-multi__row {
  display:       grid;
  grid-template-columns: 20px 1fr;
  align-items:   center;
  gap:           10px;
  padding:       8px 12px;
  cursor:        pointer;
  user-select:   none;
  border-bottom: 1px solid var(--border, #eee);
  font-size:     13px;
}
.picker-multi__row:last-child { border-bottom: none; }
.picker-multi__row:hover      { background: var(--disabled-bg, rgba(136, 136, 136, 0.04)); }
.picker-multi__row--selected  { background: var(--info-banner-bg, rgba(29, 78, 216, 0.07)); }
.picker-multi__check { width: 16px; height: 16px; cursor: pointer; }
.picker-multi__body {
  display:        flex;
  flex-direction: column;
  min-width:      0;
}
.picker-multi__label {
  font-weight:   500;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
}
.picker-multi__sublabel {
  font-size:     11px;
  color:         var(--muted, #888);
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
}
.picker-multi__footer {
  display:         flex;
  justify-content: space-between;
  align-items:     center;
  font-size:       11px;
  color:           var(--muted, #888);
}
.picker-multi__clear {
  background:  transparent;
  border:      none;
  color:       var(--primary, #1d4ed8);
  cursor:      pointer;
  font-size:   11px;
  padding:     0;
}
</style>
