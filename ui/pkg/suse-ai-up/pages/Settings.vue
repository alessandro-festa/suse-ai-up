<template>
  <AiUpPage title="Settings" subtitle="Backend connection, users, and groups">
    <AiUpTabs :tabs="tabs" v-model:active="activeTab" />

    <!-- =========== Backend tab =========== -->
    <AiUpGallery v-if="activeTab === 'backend'">
      <AiUpCard title="Backend connection">
        <template #pill>
          <AiUpPill :tone="mode === 'proxy' ? 'info' : 'warning'" :label="mode === 'proxy' ? 'In-cluster proxy' : 'Direct URL'" />
        </template>
        <template #meta>
          <span>Effective base URL:</span>
          <code class="ai-up-truncate">{{ effectiveUrl }}</code>
        </template>

        <p>
          By default, the extension routes requests through the Rancher cluster proxy to the
          <code>{{ service.name }}</code> Service in namespace <code>{{ service.namespace }}</code>
          on cluster <code>{{ service.cluster }}</code> (port <code>{{ service.port }}</code>).
          Same-origin HTTPS via your Rancher session — no Mixed Content blocking, no extra auth.
        </p>

        <fieldset class="ai-up-fieldset">
          <legend>In-cluster Service</legend>
          <div class="ai-up-grid">
            <label>Cluster ID
              <input v-model="serviceForm.cluster" class="ai-up-input" placeholder="local" />
            </label>
            <label>Namespace
              <input v-model="serviceForm.namespace" class="ai-up-input" placeholder="suse-ai-up" />
            </label>
            <label>Service name
              <input v-model="serviceForm.name" class="ai-up-input" placeholder="suse-ai-up" />
            </label>
            <label>Port
              <input v-model.number="serviceForm.port" class="ai-up-input" type="number" min="1" max="65535" />
            </label>
          </div>
          <div class="ai-up-actions">
            <button class="ai-up-btn" @click="saveService">Save Service</button>
            <button class="ai-up-btn ai-up-btn--ghost" @click="resetService">Reset to defaults</button>
          </div>
        </fieldset>

        <fieldset class="ai-up-fieldset">
          <legend>Direct URL override (dev only)</legend>
          <p class="ai-up-muted">
            Use this when running outside Rancher (e.g. <code>yarn dev</code> against a local backend on <code>http://localhost:8911</code>).
            When set, requests bypass the cluster proxy entirely. Leave empty to use the in-cluster Service above.
          </p>
          <div class="ai-up-form-row">
            <input v-model="directUrlInput" type="text" class="ai-up-input" placeholder="http://localhost:8911" />
            <button class="ai-up-btn" @click="saveDirect">Save</button>
            <button class="ai-up-btn ai-up-btn--ghost" @click="clearDirect">Clear</button>
          </div>
        </fieldset>

        <template #footer v-if="savedAt">Saved at {{ savedAt }}.</template>
      </AiUpCard>
    </AiUpGallery>

    <!-- =========== Users tab =========== -->
    <template v-else-if="activeTab === 'users'">
      <div class="tab-toolbar">
        <input v-model="userSearch" type="search" class="ai-up-input tab-toolbar__search" placeholder="Search users..." />
        <button class="ai-up-btn" :disabled="loadingUsers" @click="loadUsers">{{ loadingUsers ? 'Loading...' : 'Refresh' }}</button>
        <button class="ai-up-btn" @click="openCreateUser">+ New user</button>
      </div>
      <div v-if="usersError" class="ai-up-banner ai-up-banner--error">{{ usersError }}</div>
      <div v-if="loadingUsers && !users.length" class="ai-up-empty">Loading users...</div>
      <div v-else-if="!filteredUsers.length" class="ai-up-empty">
        <p v-if="userSearch">No users match "{{ userSearch }}".</p>
        <p v-else>No users yet. Create one to grant adapter access.</p>
      </div>
      <AiUpGallery v-else>
        <AiUpCard v-for="u in filteredUsers" :key="u.id" :title="u.name || u.id" :subtitle="u.email || ''">
          <template #pill>
            <AiUpPill :tone="(u as any).authProvider === 'local' || !(u as any).authProvider ? 'neutral' : 'info'" :label="(u as any).authProvider || 'local'" />
          </template>
          <template #meta>
            <span>ID: <code>{{ u.id }}</code></span>
          </template>
          <div v-if="u.groups?.length" class="chip-row">
            <span v-for="g in u.groups" :key="g" class="chip">{{ g }}</span>
          </div>
          <template #actions>
            <button class="ai-up-btn ai-up-btn--ghost" @click="openEditUser(u)">Edit</button>
            <button class="ai-up-btn ai-up-btn--danger" :disabled="deletingUser === u.id" @click="confirmDeleteUser(u)">
              {{ deletingUser === u.id ? 'Deleting...' : 'Delete' }}
            </button>
          </template>
        </AiUpCard>
      </AiUpGallery>
    </template>

    <!-- =========== Groups tab =========== -->
    <template v-else-if="activeTab === 'groups'">
      <div class="tab-toolbar">
        <input v-model="groupSearch" type="search" class="ai-up-input tab-toolbar__search" placeholder="Search groups..." />
        <button class="ai-up-btn" :disabled="loadingGroups" @click="loadGroups">{{ loadingGroups ? 'Loading...' : 'Refresh' }}</button>
        <button class="ai-up-btn" @click="openCreateGroup">+ New group</button>
      </div>
      <div v-if="groupsError" class="ai-up-banner ai-up-banner--error">{{ groupsError }}</div>
      <div v-if="loadingGroups && !groups.length" class="ai-up-empty">Loading groups...</div>
      <div v-else-if="!filteredGroups.length" class="ai-up-empty">
        <p v-if="groupSearch">No groups match "{{ groupSearch }}".</p>
        <p v-else>No groups yet. Create one to grant adapter access to multiple users at once.</p>
      </div>
      <AiUpGallery v-else>
        <AiUpCard v-for="g in filteredGroups" :key="g.id" :title="g.name || g.id">
          <template #meta>
            <span>ID: <code>{{ g.id }}</code></span>
            <span>{{ g.members?.length || 0 }} member{{ (g.members?.length || 0) === 1 ? '' : 's' }}</span>
          </template>
          <div v-if="g.members?.length" class="chip-row">
            <span v-for="m in g.members.slice(0, 8)" :key="m" class="chip">{{ m }}</span>
            <span v-if="g.members.length > 8" class="chip chip--muted">+{{ g.members.length - 8 }}</span>
          </div>
          <template #actions>
            <button class="ai-up-btn ai-up-btn--ghost" @click="openManageMembers(g)">Manage members</button>
            <button class="ai-up-btn ai-up-btn--danger" :disabled="deletingGroup === g.id" @click="confirmDeleteGroup(g)">
              {{ deletingGroup === g.id ? 'Deleting...' : 'Delete' }}
            </button>
          </template>
        </AiUpCard>
      </AiUpGallery>
    </template>

    <!-- =========== User create/edit modal =========== -->
    <AiUpModal :open="userModalOpen" :title="userForm.editing ? `Edit user ${ userForm.id }` : 'Create user'" @close="closeUserModal">
      <label class="ai-up-field" v-if="!userForm.editing">
        <span>ID <em>*</em></span>
        <input v-model="userForm.id" class="ai-up-input" placeholder="alice" />
      </label>
      <label class="ai-up-field">
        <span>Name</span>
        <input v-model="userForm.name" class="ai-up-input" placeholder="Alice Example" />
      </label>
      <label class="ai-up-field">
        <span>Email</span>
        <input v-model="userForm.email" type="email" class="ai-up-input" placeholder="alice@example.com" />
      </label>
      <label class="ai-up-field">
        <span>{{ userForm.editing ? 'New password (leave empty to keep current)' : 'Password' }}</span>
        <input v-model="userForm.password" type="password" class="ai-up-input" autocomplete="new-password" />
      </label>
      <fieldset class="ai-up-fieldset">
        <legend>Groups</legend>
        <AiUpPickerList
          :items="groupPickerItems"
          :selected="userForm.groups"
          empty-label="No groups defined. Create some on the Groups tab."
          search-placeholder="Filter groups..."
          @update:selected="userForm.groups = $event"
        />
      </fieldset>
      <div v-if="userModalError" class="ai-up-banner ai-up-banner--error">{{ userModalError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeUserModal">Cancel</button>
        <button class="ai-up-btn" :disabled="!canSaveUser || savingUser" @click="saveUser">
          {{ savingUser ? 'Saving...' : (userForm.editing ? 'Save' : 'Create') }}
        </button>
      </template>
    </AiUpModal>

    <!-- =========== Group create modal =========== -->
    <AiUpModal :open="groupModalOpen" :title="`Create group`" @close="closeGroupModal">
      <label class="ai-up-field">
        <span>ID <em>*</em></span>
        <input v-model="groupForm.id" class="ai-up-input" placeholder="mcp-admins" />
      </label>
      <label class="ai-up-field">
        <span>Name</span>
        <input v-model="groupForm.name" class="ai-up-input" placeholder="MCP Admins" />
      </label>
      <div v-if="groupModalError" class="ai-up-banner ai-up-banner--error">{{ groupModalError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeGroupModal">Cancel</button>
        <button class="ai-up-btn" :disabled="!groupForm.id.trim() || savingGroup" @click="saveGroup">
          {{ savingGroup ? 'Saving...' : 'Create' }}
        </button>
      </template>
    </AiUpModal>

    <!-- =========== Group members modal =========== -->
    <AiUpModal :open="!!membersGroup" :title="membersGroup ? `Manage members of ${ membersGroup.name || membersGroup.id }` : ''" @close="membersGroup = null">
      <p class="ai-up-muted">Pick which users belong to this group. Changes apply on Save.</p>
      <AiUpPickerList
        :items="userPickerItems"
        :selected="membersSelected"
        empty-label="No users defined. Create some on the Users tab."
        search-placeholder="Filter users..."
        @update:selected="membersSelected = $event"
      />
      <div v-if="membersError" class="ai-up-banner ai-up-banner--error">{{ membersError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="membersGroup = null">Cancel</button>
        <button class="ai-up-btn" :disabled="savingMembers" @click="saveMembers">
          {{ savingMembers ? 'Saving...' : 'Save' }}
        </button>
      </template>
    </AiUpModal>
  </AiUpPage>
</template>

<script lang="ts">
import { defineComponent, ref, computed, reactive, onMounted, watch } from 'vue';
import AiUpPage from '../components/AiUpPage.vue';
import AiUpGallery from '../components/AiUpGallery.vue';
import AiUpCard from '../components/AiUpCard.vue';
import AiUpPill from '../components/AiUpPill.vue';
import AiUpTabs from '../components/AiUpTabs.vue';
import AiUpModal from '../components/AiUpModal.vue';
import AiUpPickerList from '../components/AiUpPickerList.vue';
import {
  describeBaseUrl,
  getServiceLocation,
  setServiceLocation,
  getDirectBackendUrl,
  setDirectBackendUrl,
  DEFAULT_SERVICE_LOCATION,
  ServiceLocation,
} from '../config/api-config';
import { usersApi, User } from '../services/users';
import { groupsApi, Group } from '../services/groups';

const TABS = [
  { key: 'backend', label: 'Backend' },
  { key: 'users',   label: 'Users' },
  { key: 'groups',  label: 'Groups' },
];

interface UserFormState {
  editing:  boolean;
  id:       string;
  name:     string;
  email:    string;
  password: string;
  groups:   string[];
}

export default defineComponent({
  name:       'Settings',
  components: { AiUpPage, AiUpGallery, AiUpCard, AiUpPill, AiUpTabs, AiUpModal, AiUpPickerList },
  setup() {
    // -------------------------------------------------- shared
    const tabs      = TABS;
    const activeTab = ref<'backend' | 'users' | 'groups'>('backend');

    // -------------------------------------------------- Backend tab
    const service        = ref<ServiceLocation>({ ...getServiceLocation() });
    const serviceForm    = ref<ServiceLocation>({ ...service.value });
    const directUrlInput = ref<string>(getDirectBackendUrl());
    const savedAt        = ref<string | null>(null);

    const effectiveUrl = computed(() => describeBaseUrl().url);
    const mode         = computed(() => describeBaseUrl().mode);
    const stamp        = () => { savedAt.value = new Date().toLocaleTimeString(); };

    function saveService() {
      const loc: ServiceLocation = {
        cluster:   serviceForm.value.cluster.trim()   || DEFAULT_SERVICE_LOCATION.cluster,
        namespace: serviceForm.value.namespace.trim() || DEFAULT_SERVICE_LOCATION.namespace,
        name:      serviceForm.value.name.trim()      || DEFAULT_SERVICE_LOCATION.name,
        port:      Number(serviceForm.value.port)     || DEFAULT_SERVICE_LOCATION.port,
      };
      setServiceLocation(loc);
      service.value     = loc;
      serviceForm.value = { ...loc };
      stamp();
    }
    function resetService() {
      const loc = { ...DEFAULT_SERVICE_LOCATION };
      setServiceLocation(loc);
      service.value     = loc;
      serviceForm.value = { ...loc };
      stamp();
    }
    function saveDirect() { setDirectBackendUrl(directUrlInput.value.trim()); stamp(); }
    function clearDirect() { directUrlInput.value = ''; setDirectBackendUrl(''); stamp(); }

    // -------------------------------------------------- Users tab
    const users         = ref<User[]>([]);
    const loadingUsers  = ref(false);
    const usersError    = ref<string | null>(null);
    const userSearch    = ref('');
    const deletingUser  = ref<string | null>(null);

    const filteredUsers = computed(() => {
      const q = userSearch.value.trim().toLowerCase();
      if (!q) return users.value;
      return users.value.filter((u) =>
        u.id.toLowerCase().includes(q)
        || (u.name || '').toLowerCase().includes(q)
        || (u.email || '').toLowerCase().includes(q)
        || (u.groups || []).join(' ').toLowerCase().includes(q),
      );
    });

    async function loadUsers() {
      loadingUsers.value = true; usersError.value = null;
      try { users.value = (await usersApi.list()) || []; }
      catch (e: any) { usersError.value = e?.message || 'Failed to load users'; }
      finally { loadingUsers.value = false; }
    }

    async function confirmDeleteUser(u: User) {
      if (!window.confirm(`Delete user "${ u.id }"?`)) return;
      deletingUser.value = u.id;
      try { await usersApi.remove(u.id); await loadUsers(); }
      catch (e: any) { usersError.value = e?.message || 'Delete failed'; }
      finally { deletingUser.value = null; }
    }

    // user modal
    const userModalOpen  = ref(false);
    const savingUser     = ref(false);
    const userModalError = ref<string | null>(null);
    const userForm       = reactive<UserFormState>({
      editing: false, id: '', name: '', email: '', password: '', groups: [],
    });

    function openCreateUser() {
      Object.assign(userForm, { editing: false, id: '', name: '', email: '', password: '', groups: [] });
      userModalError.value = null;
      userModalOpen.value  = true;
    }
    function openEditUser(u: User) {
      Object.assign(userForm, {
        editing: true, id: u.id, name: u.name || '', email: u.email || '',
        password: '', groups: [...(u.groups || [])],
      });
      userModalError.value = null;
      userModalOpen.value  = true;
    }
    function closeUserModal() { userModalOpen.value = false; }

    const canSaveUser = computed(() => !!(userForm.id.trim() && (userForm.editing || userForm.password.trim())));

    async function saveUser() {
      savingUser.value     = true;
      userModalError.value = null;
      try {
        if (userForm.editing) {
          const body: Partial<User> & { password?: string } = {
            name: userForm.name.trim(),
            email: userForm.email.trim(),
            groups: userForm.groups,
          };
          if (userForm.password.trim()) body.password = userForm.password;
          await usersApi.update(userForm.id, body as Partial<User>);
        } else {
          await usersApi.create({
            id: userForm.id.trim(),
            name: userForm.name.trim(),
            email: userForm.email.trim(),
            groups: userForm.groups,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            password: userForm.password,
          } as any);
        }
        closeUserModal();
        await loadUsers();
      } catch (e: any) {
        userModalError.value = e?.data?.error || e?.message || 'Save failed';
      } finally {
        savingUser.value = false;
      }
    }

    // -------------------------------------------------- Groups tab
    const groups        = ref<Group[]>([]);
    const loadingGroups = ref(false);
    const groupsError   = ref<string | null>(null);
    const groupSearch   = ref('');
    const deletingGroup = ref<string | null>(null);

    const filteredGroups = computed(() => {
      const q = groupSearch.value.trim().toLowerCase();
      if (!q) return groups.value;
      return groups.value.filter((g) =>
        g.id.toLowerCase().includes(q)
        || (g.name || '').toLowerCase().includes(q),
      );
    });

    async function loadGroups() {
      loadingGroups.value = true; groupsError.value = null;
      try { groups.value = (await groupsApi.list()) || []; }
      catch (e: any) { groupsError.value = e?.message || 'Failed to load groups'; }
      finally { loadingGroups.value = false; }
    }

    async function confirmDeleteGroup(g: Group) {
      if (!window.confirm(`Delete group "${ g.id }"? Users keep existing.`)) return;
      deletingGroup.value = g.id;
      try { await groupsApi.remove(g.id); await loadGroups(); await loadUsers(); }
      catch (e: any) { groupsError.value = e?.message || 'Delete failed'; }
      finally { deletingGroup.value = null; }
    }

    // group create modal
    const groupModalOpen  = ref(false);
    const savingGroup     = ref(false);
    const groupModalError = ref<string | null>(null);
    const groupForm       = reactive({ id: '', name: '' });

    function openCreateGroup() {
      groupForm.id   = ''; groupForm.name = '';
      groupModalError.value = null;
      groupModalOpen.value  = true;
    }
    function closeGroupModal() { groupModalOpen.value = false; }

    async function saveGroup() {
      savingGroup.value      = true;
      groupModalError.value  = null;
      try {
        await groupsApi.create({ id: groupForm.id.trim(), name: groupForm.name.trim() });
        closeGroupModal();
        await loadGroups();
      } catch (e: any) {
        groupModalError.value = e?.data?.error || e?.message || 'Create failed';
      } finally {
        savingGroup.value = false;
      }
    }

    // member management modal
    const membersGroup    = ref<Group | null>(null);
    const membersSelected = ref<string[]>([]);
    const savingMembers   = ref(false);
    const membersError    = ref<string | null>(null);

    function openManageMembers(g: Group) {
      membersGroup.value    = g;
      membersSelected.value = [...(g.members || [])];
      membersError.value    = null;
      // ensure user picker has fresh data
      if (!users.value.length) loadUsers();
    }

    async function saveMembers() {
      if (!membersGroup.value) return;
      savingMembers.value = true;
      membersError.value  = null;
      const before = new Set(membersGroup.value.members || []);
      const after  = new Set(membersSelected.value);
      const toAdd    = membersSelected.value.filter((id) => !before.has(id));
      const toRemove = (membersGroup.value.members || []).filter((id) => !after.has(id));
      try {
        for (const uid of toAdd)    await groupsApi.addMember(membersGroup.value.id, uid);
        for (const uid of toRemove) await groupsApi.removeMember(membersGroup.value.id, uid);
        membersGroup.value = null;
        await loadGroups();
        await loadUsers();
      } catch (e: any) {
        membersError.value = e?.data?.error || e?.message || 'Member update failed';
      } finally {
        savingMembers.value = false;
      }
    }

    // -------------------------------------------------- picker source lists
    const userPickerItems  = computed(() => users.value.map((u) => ({
      id: u.id, label: u.name || u.id, sublabel: u.email,
    })));
    const groupPickerItems = computed(() => groups.value.map((g) => ({
      id: g.id, label: g.name || g.id, sublabel: `${ g.members?.length || 0 } members`,
    })));

    // Load lazily — first time the tab is opened.
    watch(activeTab, (t) => {
      if (t === 'users'  && !users.value.length)  loadUsers();
      if (t === 'groups' && !groups.value.length) loadGroups();
    }, { immediate: false });

    onMounted(() => {
      // Prime both lists so the user/group multipickers (used by other modals)
      // have data even before the user clicks into the tabs.
      loadUsers();
      loadGroups();
    });

    return {
      // shared
      tabs, activeTab,
      // backend
      service, serviceForm, directUrlInput, savedAt,
      effectiveUrl, mode,
      saveService, resetService, saveDirect, clearDirect,
      // users
      users, loadingUsers, usersError, userSearch, deletingUser,
      filteredUsers, loadUsers, confirmDeleteUser,
      userModalOpen, savingUser, userModalError, userForm,
      openCreateUser, openEditUser, closeUserModal, canSaveUser, saveUser,
      // groups
      groups, loadingGroups, groupsError, groupSearch, deletingGroup,
      filteredGroups, loadGroups, confirmDeleteGroup,
      groupModalOpen, savingGroup, groupModalError, groupForm,
      openCreateGroup, closeGroupModal, saveGroup,
      membersGroup, membersSelected, savingMembers, membersError,
      openManageMembers, saveMembers,
      // picker items
      userPickerItems, groupPickerItems,
    };
  },
});
</script>

<style lang="scss" scoped>
@import '../styles/tokens.scss';

.tab-toolbar {
  display:     flex;
  gap:         8px;
  align-items: center;
  flex-wrap:   wrap;
}
.tab-toolbar__search { flex: 1 1 240px; min-width: 200px; }

.ai-up-fieldset {
  border:        1px solid var(--border, #ddd);
  border-radius: 6px;
  padding:       12px 14px 14px;
  margin:        0;
  display:       flex;
  flex-direction: column;
  gap:           10px;
}
.ai-up-fieldset legend {
  font-size:   12px;
  font-weight: 600;
  color:       var(--body-text, #333);
  padding:     0 6px;
}
.ai-up-grid {
  display:               grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap:                   10px;
}
.ai-up-grid label {
  display:        flex;
  flex-direction: column;
  gap:            4px;
  font-size:      12px;
  color:          var(--muted, #888);
}
.ai-up-actions,
.ai-up-form-row {
  display:     flex;
  flex-wrap:   wrap;
  gap:         8px;
  align-items: center;
}
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
  flex:           1;
  min-width:      0;
  padding:        6px 10px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  color:          var(--body-text, #333);
  font-size:      13px;
}
.ai-up-btn {
  padding:        6px 12px;
  border-radius:  6px;
  border:         1px solid var(--primary, #1d4ed8);
  background:     var(--primary, #1d4ed8);
  color:          #fff;
  font-size:      13px;
  cursor:         pointer;
}
.ai-up-btn:disabled { opacity: 0.55; cursor: not-allowed; }
.ai-up-btn--ghost  { background: transparent; color: var(--primary, #1d4ed8); }
.ai-up-btn--danger { border-color: var(--error, #dc2626); background: transparent; color: var(--error, #dc2626); }

.ai-up-muted {
  color:     var(--muted, #888);
  font-size: 12px;
  margin:    0;
}
.ai-up-truncate {
  display:       inline-block;
  max-width:     100%;
  overflow:      hidden;
  text-overflow: ellipsis;
  white-space:   nowrap;
  font-family:   var(--font-mono, monospace);
}
.ai-up-empty {
  padding:    20px;
  text-align: center;
  color:      var(--muted, #888);
  font-size:  13px;
  border:     1px dashed var(--border, #ddd);
  border-radius: 6px;
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

.chip-row {
  display:   flex;
  flex-wrap: wrap;
  gap:       4px;
  margin-top: 4px;
}
.chip {
  font-size:     11px;
  padding:       2px 8px;
  border-radius: 10px;
  background:    var(--info-banner-bg, rgba(29, 78, 216, 0.07));
  color:         var(--primary, #1d4ed8);
}
.chip--muted {
  background: var(--disabled-bg, rgba(136, 136, 136, 0.08));
  color:      var(--muted, #888);
}
</style>
