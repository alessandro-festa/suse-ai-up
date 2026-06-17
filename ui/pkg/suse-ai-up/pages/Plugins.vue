<template>
  <AiUpPage
    title="Plugins"
    subtitle="External services registered with the proxy"
  >
    <AiUpToolbar
      v-model:search="search"
      search-placeholder="Search services..."
    >
      <template #actions>
        <button class="ai-up-btn" @click="openRegister">Register service</button>
        <button class="ai-up-btn ai-up-btn--ghost" :disabled="loading" @click="refresh">
          {{ loading ? 'Loading...' : 'Refresh' }}
        </button>
      </template>
    </AiUpToolbar>

    <div v-if="error" class="ai-up-banner ai-up-banner--error">{{ error }}</div>

    <div v-if="loading && !services.length" class="ai-up-empty">Loading services...</div>

    <div v-else-if="!filtered.length && !error" class="ai-up-empty">
      <p v-if="search">No services match "{{ search }}".</p>
      <p v-else>No registered services. Register one to extend the proxy with external capabilities.</p>
    </div>

    <AiUpGallery v-else>
      <AiUpCard
        v-for="s in filtered"
        :key="s.id"
        :title="s.name || s.id"
        :subtitle="s.url || ''"
      >
        <template #pill>
          <AiUpPill :tone="statusTone(s.status)" :label="s.status || 'unknown'" />
        </template>
        <template #meta>
          <span>Type: <code>{{ s.type }}</code></span>
          <span v-if="s.version">Version: {{ s.version }}</span>
          <span v-if="s.healthy !== undefined">
            Health: <AiUpPill :tone="s.healthy ? 'success' : 'error'" :label="s.healthy ? 'healthy' : 'unhealthy'" />
          </span>
        </template>
        <div v-if="s.capabilities && s.capabilities.length" class="plugin-caps">
          <span v-for="c in s.capabilities" :key="c" class="plugin-cap">{{ c }}</span>
        </div>
        <template #actions>
          <button
            class="ai-up-btn ai-up-btn--ghost"
            :disabled="checking === s.id"
            @click="checkHealth(s)"
          >
            {{ checking === s.id ? 'Checking...' : 'Health check' }}
          </button>
          <button
            class="ai-up-btn ai-up-btn--danger"
            :disabled="removing === s.id"
            @click="confirmUnregister(s)"
          >
            {{ removing === s.id ? 'Removing...' : 'Unregister' }}
          </button>
        </template>
      </AiUpCard>
    </AiUpGallery>

    <AiUpModal :open="registering" title="Register service" @close="closeRegister">
      <label class="ai-up-field">
        <span>Service ID <em>*</em></span>
        <input v-model="regForm.serviceId" class="ai-up-input" placeholder="my-agent-service" />
      </label>
      <label class="ai-up-field">
        <span>Service type <em>*</em></span>
        <select v-model="regForm.serviceType" class="ai-up-input">
          <option value="smartagents">smartagents</option>
          <option value="registry">registry</option>
          <option value="virtualmcp">virtualmcp</option>
        </select>
      </label>
      <label class="ai-up-field">
        <span>Service URL <em>*</em></span>
        <input v-model="regForm.serviceUrl" class="ai-up-input" placeholder="http://agent-svc:8080" />
      </label>
      <label class="ai-up-field">
        <span>Version</span>
        <input v-model="regForm.version" class="ai-up-input" placeholder="1.0.0" />
      </label>
      <label class="ai-up-field">
        <span>Capabilities</span>
        <small class="ai-up-muted">Comma-separated capability names.</small>
        <input v-model="regForm.capabilities" class="ai-up-input" placeholder="tools,prompts" />
      </label>

      <div v-if="regError" class="ai-up-banner ai-up-banner--error">{{ regError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeRegister">Cancel</button>
        <button type="button" class="ai-up-btn" :disabled="!canRegister || submitting" @click="submitRegister">
          {{ submitting ? 'Registering...' : 'Register' }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, reactive, computed, onMounted } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpToolbar from '../components/AiUpToolbar.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpModal from '../components/AiUpModal.vue';
import { pluginsApi } from '../services/plugins';

interface ServiceView {
  id:            string;
  name:          string;
  type:          string;
  status?:       string;
  url?:          string;
  version?:      string;
  healthy?:      boolean;
  capabilities?: string[];
  [key: string]: unknown;
}

export default defineComponent({
  name:       'Plugins',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal },
  setup() {
    const services    = ref<ServiceView[]>([]);
    const search      = ref('');
    const loading     = ref(false);
    const error       = ref<string | null>(null);
    const removing    = ref<string | null>(null);
    const checking    = ref<string | null>(null);
    const registering = ref(false);
    const submitting  = ref(false);
    const regError    = ref<string | null>(null);

    const regForm = reactive({
      serviceId:    '',
      serviceType:  'smartagents',
      serviceUrl:   '',
      version:      '',
      capabilities: '',
    });

    const filtered = computed(() => {
      const q = search.value.trim().toLowerCase();
      if (!q) return services.value;
      return services.value.filter((s) =>
        (s.name || '').toLowerCase().includes(q)
        || (s.id || '').toLowerCase().includes(q)
        || (s.type || '').toLowerCase().includes(q),
      );
    });

    const canRegister = computed(() =>
      !!regForm.serviceId.trim()
      && !!regForm.serviceType
      && !!regForm.serviceUrl.trim(),
    );

    function statusTone(s?: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (!s) return 'neutral';
      if (s === 'registered' || s === 'active' || s === 'healthy') return 'success';
      if (s === 'error' || s === 'failed') return 'error';
      if (s === 'provisioning') return 'warning';
      return 'info';
    }

    async function refresh() {
      loading.value = true;
      error.value   = null;
      try {
        const raw = (await pluginsApi.list()) || [];
        services.value = raw.map((s: any) => ({
          id:           s.serviceId || s.id || s.service_id,
          name:         s.name || s.serviceId || s.id || '',
          type:         s.serviceType || s.type || s.service_type || '',
          status:       s.status || 'registered',
          url:          s.serviceURL || s.url || s.service_url || '',
          version:      s.version || '',
          capabilities: s.capabilities || [],
        }));
      } catch (e: any) {
        error.value = e?.message || 'Failed to load services';
      } finally {
        loading.value = false;
      }
    }

    function openRegister() {
      regForm.serviceId    = '';
      regForm.serviceType  = 'smartagents';
      regForm.serviceUrl   = '';
      regForm.version      = '';
      regForm.capabilities = '';
      regError.value       = null;
      registering.value    = true;
    }

    function closeRegister() {
      registering.value = false;
    }

    async function submitRegister() {
      submitting.value = true;
      regError.value   = null;
      try {
        const caps = regForm.capabilities.split(',').map((s) => s.trim()).filter(Boolean);
        await pluginsApi.register({
          service_id:   regForm.serviceId.trim(),
          service_type: regForm.serviceType,
          service_url:  regForm.serviceUrl.trim(),
          version:      regForm.version.trim() || undefined,
          capabilities: caps.length ? caps : undefined,
        } as any);
        closeRegister();
        await refresh();
      } catch (e: any) {
        regError.value = e?.data?.error || e?.message || 'Registration failed';
      } finally {
        submitting.value = false;
      }
    }

    async function checkHealth(s: ServiceView) {
      checking.value = s.id;
      try {
        const result = await pluginsApi.health(s.id) as any;
        s.healthy = result?.healthy ?? result?.status === 'healthy';
      } catch {
        s.healthy = false;
      } finally {
        checking.value = null;
      }
    }

    async function confirmUnregister(s: ServiceView) {
      if (!window.confirm(`Unregister service "${ s.name || s.id }"?`)) return;
      removing.value = s.id;
      try {
        await pluginsApi.unregister(s.id);
        await refresh();
      } catch (e: any) {
        error.value = e?.message || 'Unregister failed';
      } finally {
        removing.value = null;
      }
    }

    onMounted(refresh);

    return {
      services, search, loading, error, removing, checking,
      registering, submitting, regError, regForm,
      filtered, canRegister,
      statusTone,
      refresh, openRegister, closeRegister, submitRegister, checkHealth, confirmUnregister,
    };
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.ai-up-btn {
  padding:       6px 12px;
  border-radius: 6px;
  border:        1px solid var(--primary, #1d4ed8);
  background:    var(--primary, #1d4ed8);
  color:         #fff;
  font-size:     13px;
  cursor:        pointer;
}
.ai-up-btn:disabled { opacity: 0.55; cursor: not-allowed; }
.ai-up-btn--ghost   { background: transparent; color: var(--primary, #1d4ed8); }
.ai-up-btn--danger  { border-color: var(--error, #dc2626); background: transparent; color: var(--error, #dc2626); }

.ai-up-field {
  display:        flex;
  flex-direction: column;
  gap:            4px;
  font-size:      12px;
  color:          var(--muted, #888);
}
.ai-up-field em {
  color:      var(--error, #dc2626);
  font-style: normal;
  margin:     0 4px;
}
.ai-up-input {
  padding:       6px 10px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  background:    var(--body-bg, #fff);
  color:         var(--body-text, #333);
  font-size:     13px;
}
.ai-up-banner {
  padding:       8px 10px;
  border-radius: 6px;
  font-size:     12px;
}
.ai-up-banner--error {
  background: var(--error-banner-bg, rgba(220, 38, 38, 0.1));
  color:      var(--error, #dc2626);
  border:     1px solid var(--error, #dc2626);
}
.ai-up-empty {
  padding:    20px;
  text-align: center;
  color:      var(--muted, #888);
  font-size:  13px;
}
.ai-up-muted {
  color:     var(--muted, #888);
  font-size: 12px;
  margin:    0;
}
.plugin-caps {
  display:   flex;
  flex-wrap: wrap;
  gap:       4px;
  margin-top: 4px;
}
.plugin-cap {
  font-size:     10px;
  padding:       1px 6px;
  border-radius: 10px;
  background:    var(--disabled-bg, rgba(136, 136, 136, 0.08));
  color:         var(--muted, #888);
}
</style>
