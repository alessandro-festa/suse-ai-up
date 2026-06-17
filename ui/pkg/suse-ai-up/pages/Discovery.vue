<template>
  <AiUpPage
    title="Discovery"
    subtitle="Scan your network for MCP servers"
  >
    <AiUpTabs :tabs="tabs" :active="activeTab" @update:active="activeTab = $event" />

    <!-- Scan Jobs tab -->
    <template v-if="activeTab === 'jobs'">
      <AiUpToolbar v-model:search="jobSearch" search-placeholder="Search jobs...">
        <template #actions>
          <button class="ai-up-btn" @click="openScan">Start scan</button>
          <button class="ai-up-btn ai-up-btn--ghost" :disabled="loadingJobs" @click="refreshJobs">
            {{ loadingJobs ? 'Loading...' : 'Refresh' }}
          </button>
        </template>
      </AiUpToolbar>

      <div v-if="jobError" class="ai-up-banner ai-up-banner--error">{{ jobError }}</div>

      <div v-if="loadingJobs && !jobs.length" class="ai-up-empty">Loading scan jobs...</div>

      <div v-else-if="!filteredJobs.length && !jobError" class="ai-up-empty">
        <p v-if="jobSearch">No jobs match "{{ jobSearch }}".</p>
        <p v-else>No scan jobs yet. Start a scan to discover MCP servers on your network.</p>
      </div>

      <AiUpGallery v-else>
        <AiUpCard
          v-for="j in filteredJobs"
          :key="j.jobId"
          :title="j.jobId"
          :subtitle="j.startedAt ? `Started ${ j.startedAt }` : ''"
        >
          <template #pill>
            <AiUpPill :tone="jobTone(j.status)" :label="j.status" />
          </template>
          <template #meta>
            <span v-if="j.endedAt">Ended: {{ j.endedAt }}</span>
          </template>
          <template #actions>
            <button
              v-if="j.status === 'running'"
              class="ai-up-btn ai-up-btn--danger"
              :disabled="cancelling === j.jobId"
              @click="cancelJob(j)"
            >
              {{ cancelling === j.jobId ? 'Cancelling...' : 'Cancel' }}
            </button>
          </template>
        </AiUpCard>
      </AiUpGallery>
    </template>

    <!-- Results tab -->
    <template v-if="activeTab === 'results'">
      <AiUpToolbar v-model:search="resultSearch" search-placeholder="Search discovered servers...">
        <template #actions>
          <button class="ai-up-btn ai-up-btn--ghost" :disabled="loadingResults" @click="refreshResults">
            {{ loadingResults ? 'Loading...' : 'Refresh' }}
          </button>
        </template>
      </AiUpToolbar>

      <div v-if="resultError" class="ai-up-banner ai-up-banner--error">{{ resultError }}</div>

      <div v-if="loadingResults && !results.length" class="ai-up-empty">Loading results...</div>

      <div v-else-if="!filteredResults.length && !resultError" class="ai-up-empty">
        <p v-if="resultSearch">No servers match "{{ resultSearch }}".</p>
        <p v-else>No discovered servers. Complete a scan first.</p>
      </div>

      <AiUpGallery v-else>
        <AiUpCard
          v-for="s in filteredResults"
          :key="s.id"
          :title="s.name || s.id"
          :subtitle="s.address || ''"
        >
          <template #pill>
            <AiUpPill :tone="serverTone(s.status)" :label="s.status || 'unknown'" />
          </template>
          <template #meta>
            <span v-if="s.protocol">Protocol: {{ s.protocol }}</span>
            <span v-if="s.connection">Connection: {{ s.connection }}</span>
            <span v-if="s.server_version">Version: {{ s.server_version }}</span>
            <span v-if="s.capabilities">
              Tools: {{ s.capabilities.tools ? '✓' : '—' }}
              Resources: {{ s.capabilities.resources ? '✓' : '—' }}
              Prompts: {{ s.capabilities.prompts ? '✓' : '—' }}
            </span>
          </template>
          <p v-if="s.vulnerability_score" class="ai-up-muted">
            Risk: <code>{{ s.vulnerability_score }}</code>
          </p>
        </AiUpCard>
      </AiUpGallery>
    </template>

    <!-- Start Scan modal -->
    <AiUpModal :open="scanning" title="Start network scan" @close="closeScan">
      <label class="ai-up-field">
        <span>Scan ranges</span>
        <small class="ai-up-muted">CIDR blocks or IP ranges, one per line.</small>
        <textarea v-model="scanForm.ranges" class="ai-up-textarea" rows="3" placeholder="192.168.1.0/24&#10;10.0.0.1-10.0.0.10" />
      </label>
      <label class="ai-up-field">
        <span>Ports</span>
        <small class="ai-up-muted">Comma-separated ports or ranges.</small>
        <input v-model="scanForm.ports" class="ai-up-input" placeholder="8000,8001,9000-9100" />
      </label>
      <label class="ai-up-field">
        <span>Timeout</span>
        <input v-model="scanForm.timeout" class="ai-up-input" placeholder="30s" />
      </label>
      <label class="ai-up-field">
        <span>Max concurrent</span>
        <input v-model.number="scanForm.maxConcurrent" type="number" min="1" class="ai-up-input" placeholder="10" />
      </label>

      <div v-if="scanError" class="ai-up-banner ai-up-banner--error">{{ scanError }}</div>

      <template #actions>
        <button type="button" class="ai-up-btn ai-up-btn--ghost" @click="closeScan">Cancel</button>
        <button type="button" class="ai-up-btn" :disabled="submitting" @click="submitScan">
          {{ submitting ? 'Starting...' : 'Start scan' }}
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
import AiUpTabs from '../components/AiUpTabs.vue';
import { discoveryApi, ScanJob } from '../services/discovery';

interface DiscoveredResult {
  id:                  string;
  name?:               string;
  address?:            string;
  protocol?:           string;
  connection?:         string;
  status?:             string;
  vulnerability_score?: string;
  server_version?:     string;
  capabilities?:       { tools?: boolean; resources?: boolean; prompts?: boolean };
  [key: string]:       unknown;
}

export default defineComponent({
  name:       'Discovery',
  components: { AiUpPage, AiUpToolbar, AiUpGallery, AiUpCard, AiUpPill, AiUpModal, AiUpTabs },
  setup() {
    const activeTab     = ref('jobs');
    const tabs          = [
      { key: 'jobs',    label: 'Scan Jobs' },
      { key: 'results', label: 'Results' },
    ];

    const jobs          = ref<ScanJob[]>([]);
    const jobSearch     = ref('');
    const loadingJobs   = ref(false);
    const jobError      = ref<string | null>(null);
    const cancelling    = ref<string | null>(null);

    const results       = ref<DiscoveredResult[]>([]);
    const resultSearch  = ref('');
    const loadingResults = ref(false);
    const resultError   = ref<string | null>(null);

    const scanning      = ref(false);
    const submitting    = ref(false);
    const scanError     = ref<string | null>(null);
    const scanForm      = reactive({ ranges: '', ports: '', timeout: '30s', maxConcurrent: 10 });

    const filteredJobs = computed(() => {
      const q = jobSearch.value.trim().toLowerCase();
      if (!q) return jobs.value;
      return jobs.value.filter((j) =>
        j.jobId.toLowerCase().includes(q)
        || (j.status || '').toLowerCase().includes(q),
      );
    });

    const filteredResults = computed(() => {
      const q = resultSearch.value.trim().toLowerCase();
      if (!q) return results.value;
      return results.value.filter((s) =>
        (s.name || '').toLowerCase().includes(q)
        || (s.address || '').toLowerCase().includes(q)
        || (s.id || '').toLowerCase().includes(q)
        || (s.protocol || '').toLowerCase().includes(q),
      );
    });

    function jobTone(s: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (s === 'completed') return 'success';
      if (s === 'failed' || s === 'error') return 'error';
      if (s === 'running') return 'warning';
      if (s === 'cancelled') return 'neutral';
      return 'info';
    }

    function serverTone(s?: string): 'success' | 'error' | 'warning' | 'info' | 'neutral' {
      if (!s) return 'neutral';
      if (s === 'healthy' || s === 'active') return 'success';
      if (s === 'error' || s === 'unreachable') return 'error';
      return 'info';
    }

    async function refreshJobs() {
      loadingJobs.value = true;
      jobError.value    = null;
      try {
        jobs.value = ((await discoveryApi.listJobs()) || []) as ScanJob[];
      } catch (e: any) {
        jobError.value = e?.message || 'Failed to load scan jobs';
      } finally {
        loadingJobs.value = false;
      }
    }

    async function refreshResults() {
      loadingResults.value = true;
      resultError.value    = null;
      try {
        const data = await discoveryApi.results();
        results.value = (Array.isArray(data) ? data : []) as DiscoveredResult[];
      } catch (e: any) {
        resultError.value = e?.message || 'Failed to load results';
      } finally {
        loadingResults.value = false;
      }
    }

    function openScan() {
      scanForm.ranges        = '';
      scanForm.ports         = '';
      scanForm.timeout       = '30s';
      scanForm.maxConcurrent = 10;
      scanError.value        = null;
      scanning.value         = true;
    }

    function closeScan() {
      scanning.value = false;
    }

    async function submitScan() {
      submitting.value = true;
      scanError.value  = null;
      try {
        const body: Record<string, unknown> = {};
        const ranges = scanForm.ranges.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        if (ranges.length) body.scanRanges = ranges;
        const ports = scanForm.ports.split(',').map((s) => s.trim()).filter(Boolean);
        if (ports.length) body.ports = ports;
        if (scanForm.timeout) body.timeout = scanForm.timeout;
        if (scanForm.maxConcurrent > 0) body.maxConcurrent = scanForm.maxConcurrent;
        await discoveryApi.scan(body);
        closeScan();
        await refreshJobs();
      } catch (e: any) {
        scanError.value = e?.data?.error || e?.message || 'Scan failed';
      } finally {
        submitting.value = false;
      }
    }

    async function cancelJob(j: ScanJob) {
      cancelling.value = j.jobId;
      try {
        await discoveryApi.cancelJob(j.jobId);
        await refreshJobs();
      } catch (e: any) {
        jobError.value = e?.message || 'Cancel failed';
      } finally {
        cancelling.value = null;
      }
    }

    onMounted(() => {
      refreshJobs();
      refreshResults();
    });

    return {
      activeTab, tabs,
      jobs, jobSearch, loadingJobs, jobError, cancelling,
      results, resultSearch, loadingResults, resultError,
      scanning, submitting, scanError, scanForm,
      filteredJobs, filteredResults,
      jobTone, serverTone,
      refreshJobs, refreshResults, openScan, closeScan, submitScan, cancelJob,
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
.ai-up-input,
.ai-up-textarea {
  padding:       6px 10px;
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  background:    var(--body-bg, #fff);
  color:         var(--body-text, #333);
  font-size:     13px;
}
.ai-up-textarea { font-family: var(--font-mono, monospace); }
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
</style>
