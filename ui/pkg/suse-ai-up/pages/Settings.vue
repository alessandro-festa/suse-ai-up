<template>
  <AiUpPage title="Settings" subtitle="Backend connection, users, and groups">
    <!-- Account banner: shown above the tabs because every mutation depends on it. -->
    <div class="account-bar">
      <template v-if="authUser">
        <div class="account-bar__info">
          <strong>Signed in as {{ authUser.name || authUser.id }}</strong>
          <span v-if="authUser.email" class="ai-up-muted">{{ authUser.email }}</span>
          <span class="ai-up-muted">
            Identity source: <strong>{{ isRancherMode ? 'Rancher RBAC (read-only)' : 'Local' }}</strong>
            <template v-if="isRancherMode">. Local admin sign-in is still required to apply Access Control changes.</template>
          </span>
        </div>
        <button class="ai-up-btn ai-up-btn--ghost" @click="signOut">Sign out</button>
      </template>
      <template v-else>
        <div class="account-bar__info">
          <strong>Not signed in</strong>
          <span class="ai-up-muted">
            Creating users, groups, or any other mutation requires authentication.
          </span>
          <span class="ai-up-muted">Identity source: <strong>{{ isRancherMode ? 'Rancher RBAC' : 'Local' }}</strong></span>
        </div>
        <button class="ai-up-btn" @click="openSignIn">Sign in</button>
      </template>
    </div>

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

    <!-- =========== Identity tab =========== -->
    <AiUpGallery v-else-if="activeTab === 'identity'">
      <AiUpCard title="Identity source">
        <template #pill>
          <AiUpPill :tone="isRancherMode ? 'info' : 'neutral'" :label="isRancherMode ? 'Rancher RBAC' : 'Local'" />
        </template>
        <p>
          Choose where the Users and Groups visible in this extension come from. Adapter Access Control
          uses the selected source's principals.
        </p>
        <fieldset class="ai-up-fieldset">
          <legend>Source</legend>
          <label class="acl-row">
            <input type="radio" value="local" :checked="effectiveProvider === 'local'" @change="pickProvider('local')" />
            <span>
              <strong>Local</strong> — manage Users/Groups inside suse-ai-up (CRDs in the operator's namespace).
            </span>
          </label>
          <label class="acl-row">
            <input type="radio" value="rancher" :checked="effectiveProvider === 'rancher'" @change="pickProvider('rancher')" />
            <span>
              <strong>Rancher RBAC</strong> — read users and groups directly from Rancher
              (<code>management.cattle.io.users</code> and <code>/v3/principals</code>).
              Read-only in v1; the local admin sign-in is still required to apply mutations.
            </span>
          </label>
        </fieldset>
      </AiUpCard>

      <AiUpCard v-if="isRancherMode" title="Role mapping">
        <p class="ai-up-muted">
          Rules applied to Rancher principals when computing local-group membership for ACL purposes.
          The default rule marks any Rancher user with the <code>admin</code> global role as a member of
          <code>mcp-admins</code>.
        </p>
        <table class="role-map">
          <thead>
            <tr>
              <th>Source kind</th>
              <th>Source (role name or principal ID)</th>
              <th>Target group</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(rule, idx) in roleMap" :key="idx">
              <td>
                <select v-model="rule.sourceKind" class="ai-up-input">
                  <option value="globalRole">globalRole</option>
                  <option value="principal">principal</option>
                </select>
              </td>
              <td><input v-model="rule.source" class="ai-up-input" :placeholder="rule.sourceKind === 'globalRole' ? 'admin' : 'keycloak_group://...'" /></td>
              <td><input v-model="rule.target" class="ai-up-input" placeholder="mcp-admins" /></td>
              <td><button class="ai-up-btn ai-up-btn--danger" @click="deleteRoleRule(idx)">Remove</button></td>
            </tr>
            <tr v-if="!roleMap.length">
              <td colspan="4" class="ai-up-empty">No rules. Rancher principals will not be auto-mapped to any local group.</td>
            </tr>
          </tbody>
        </table>
        <div class="ai-up-actions">
          <button class="ai-up-btn ai-up-btn--ghost" @click="addRoleRule">+ Add rule</button>
          <button class="ai-up-btn" @click="saveRoleMap">Save mapping</button>
          <button class="ai-up-btn ai-up-btn--ghost" @click="resetRoleMap">Reset to default</button>
        </div>
      </AiUpCard>
    </AiUpGallery>

    <!-- =========== Users tab =========== -->
    <template v-else-if="activeTab === 'users'">
      <div class="tab-toolbar">
        <input v-model="userSearch" type="search" class="ai-up-input tab-toolbar__search" placeholder="Search users..." />
        <button class="ai-up-btn" :disabled="isRancherMode ? false : loadingUsers" @click="isRancherMode ? loadRancher() : loadUsers()">
          {{ (isRancherMode ? false : loadingUsers) ? 'Loading...' : 'Refresh' }}
        </button>
        <button
          class="ai-up-btn"
          :disabled="isRancherMode"
          :title="isRancherMode ? 'Users come from Rancher. Manage them in Rancher → Users & Authentication.' : ''"
          @click="openCreateUser"
        >+ New user</button>
      </div>

      <div v-if="isRancherMode && rancherError" class="ai-up-banner ai-up-banner--error">{{ rancherError }}</div>
      <div v-if="!isRancherMode && usersError" class="ai-up-banner ai-up-banner--error">{{ usersError }}</div>

      <!-- Rancher mode -->
      <template v-if="isRancherMode">
        <div v-if="!rancherFilteredUsers.length" class="ai-up-empty">
          <p v-if="userSearch">No Rancher users match "{{ userSearch }}".</p>
          <p v-else>No Rancher users visible. Are you logged in as a Rancher admin?</p>
        </div>
        <AiUpGallery v-else>
          <AiUpCard v-for="u in rancherFilteredUsers" :key="u.id" :title="u.name" :subtitle="u.username || u.id">
            <template #pill>
              <AiUpPill tone="info" label="Rancher" />
            </template>
            <template #meta>
              <span>ID: <code>{{ u.id }}</code></span>
              <span v-if="!u.enabled" class="ai-up-muted">disabled</span>
            </template>
            <div class="chip-row">
              <AiUpPill v-if="rancherUserIsAdmin(u.id)" tone="warning" label="Admin" />
              <span v-for="g in rancherUserLocalGroups(u.id)" :key="g" class="chip">{{ g }}</span>
            </div>
            <template #footer v-if="u.principalIds.length">
              <span class="ai-up-truncate">{{ u.principalIds[0] }}</span>
            </template>
          </AiUpCard>
        </AiUpGallery>
      </template>

      <!-- Local mode (default) -->
      <template v-else>
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
    </template>

    <!-- =========== Groups tab =========== -->
    <template v-else-if="activeTab === 'groups'">
      <div class="tab-toolbar">
        <input v-model="groupSearch" type="search" class="ai-up-input tab-toolbar__search" placeholder="Search groups..." />
        <button class="ai-up-btn" :disabled="isRancherMode ? false : loadingGroups" @click="isRancherMode ? loadRancher() : loadGroups()">
          {{ (isRancherMode ? false : loadingGroups) ? 'Loading...' : 'Refresh' }}
        </button>
        <button
          class="ai-up-btn"
          :disabled="isRancherMode"
          :title="isRancherMode ? 'Groups come from Rancher. Manage them in Rancher → Users & Authentication.' : ''"
          @click="openCreateGroup"
        >+ New group</button>
      </div>

      <div v-if="isRancherMode && rancherError" class="ai-up-banner ai-up-banner--error">{{ rancherError }}</div>
      <div v-if="!isRancherMode && groupsError" class="ai-up-banner ai-up-banner--error">{{ groupsError }}</div>

      <!-- Rancher mode -->
      <template v-if="isRancherMode">
        <div v-if="!rancherFilteredGroups.length" class="ai-up-empty">
          <p v-if="groupSearch">No Rancher groups match "{{ groupSearch }}".</p>
          <p v-else>
            Rancher groups come from external IDPs (LDAP, OIDC, SAML, Active Directory).
            None configured in Rancher → Users &amp; Authentication.
          </p>
        </div>
        <AiUpGallery v-else>
          <AiUpCard v-for="g in rancherFilteredGroups" :key="g.id" :title="g.name">
            <template #pill>
              <AiUpPill tone="info" label="Rancher" />
            </template>
            <template #meta>
              <span class="ai-up-truncate">ID: <code>{{ g.id }}</code></span>
              <span v-if="g.provider">Provider: {{ g.provider }}</span>
            </template>
          </AiUpCard>
        </AiUpGallery>
      </template>

      <!-- Local mode (default) -->
      <template v-else>
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
    </template>

    <!-- =========== First-login identity-provider modal =========== -->
    <AiUpModal :open="firstLoginOpen" title="Choose your identity source" @close="firstLoginOpen = false">
      <p class="ai-up-muted">
        suse-ai-up can manage its own Users and Groups, or use the ones already configured in Rancher.
        You can change this later from Settings &rarr; Identity.
      </p>
      <div class="provider-cards">
        <button type="button" class="provider-card" @click="pickProvider('local')">
          <strong>Local</strong>
          <span>
            Manage Users and Groups inside suse-ai-up (CRDs in the operator's namespace).
            Good for standalone deployments.
          </span>
        </button>
        <button type="button" class="provider-card" @click="pickProvider('rancher')">
          <strong>Rancher RBAC</strong>
          <span>
            Read Users and Groups directly from Rancher. Rancher administrators are automatically
            considered MCP admins. Read-only in this version &mdash; mutations still require the
            local admin sign-in.
          </span>
        </button>
      </div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="firstLoginOpen = false">Decide later</button>
      </template>
    </AiUpModal>

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

    <!-- =========== Sign-in modal =========== -->
    <AiUpModal :open="signInOpen" title="Sign in" @close="closeSignIn">
      <p class="ai-up-muted">
        Use the admin credentials from your Helm release (default
        <code>admin / admin</code> from <code>charts/suse-ai-up/values.yaml</code>
        <code>auth.local.defaultAdminPassword</code>).
      </p>
      <label class="ai-up-field">
        <span>User ID <em>*</em></span>
        <input v-model="signInForm.userId" class="ai-up-input" autocomplete="username" placeholder="admin" autofocus />
      </label>
      <label class="ai-up-field">
        <span>Password <em>*</em></span>
        <input v-model="signInForm.password" type="password" class="ai-up-input" autocomplete="current-password" @keyup.enter="signIn" />
      </label>
      <div v-if="signInError" class="ai-up-banner ai-up-banner--error">{{ signInError }}</div>
      <template #actions>
        <button class="ai-up-btn ai-up-btn--ghost" @click="closeSignIn">Cancel</button>
        <button class="ai-up-btn" :disabled="!canSignIn || signingIn" @click="signIn">
          {{ signingIn ? 'Signing in...' : 'Sign in' }}
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
import { defineComponent, ref, computed, reactive, onMounted, onUnmounted, watch } from 'vue';
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
import {
  authApi, AuthUser,
  setStoredToken, setStoredUser, getStoredUser,
} from '../services/auth';
import {
  IdentityProvider, RoleMapRule, IDENTITY_DEFAULT_RULES,
  getIdentityProvider, setIdentityProvider,
  getRancherRoleMap, setRancherRoleMap, localGroupsFor,
} from '../config/identity';
import {
  listUsers as listRancherUsers,
  listGroupPrincipals,
  listGlobalRoleBindings,
  indexGlobalRoles,
  RancherUser, RancherGroupPrincipal,
} from '../services/rancher';

const TABS = [
  { key: 'backend',  label: 'Backend' },
  { key: 'identity', label: 'Identity' },
  { key: 'users',    label: 'Users' },
  { key: 'groups',   label: 'Groups' },
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
    const activeTab = ref<'backend' | 'identity' | 'users' | 'groups'>('backend');

    // -------------------------------------------------- identity provider
    // null until the admin has picked — triggers the first-login modal.
    const identityProvider = ref<IdentityProvider | null>(getIdentityProvider());
    const effectiveProvider = computed<IdentityProvider>(() => identityProvider.value || 'local');
    const isRancherMode    = computed(() => effectiveProvider.value === 'rancher');
    const firstLoginOpen   = ref(false);
    const roleMap          = ref<RoleMapRule[]>(getRancherRoleMap());

    function pickProvider(p: IdentityProvider) {
      identityProvider.value = p;
      setIdentityProvider(p);
      firstLoginOpen.value = false;
      // Reload the provider-dependent lists so tabs reflect the new source.
      loadUsers();
      loadGroups();
    }

    function addRoleRule() {
      roleMap.value = [...roleMap.value, { source: '', sourceKind: 'globalRole', target: 'mcp-users' }];
    }
    function deleteRoleRule(idx: number) {
      roleMap.value = roleMap.value.filter((_, i) => i !== idx);
    }
    function saveRoleMap() {
      setRancherRoleMap(roleMap.value);
    }
    function resetRoleMap() {
      roleMap.value = [...IDENTITY_DEFAULT_RULES];
      setRancherRoleMap(roleMap.value);
    }

    // -------------------------------------------------- Rancher data (read-only)
    const rancherUsers       = ref<RancherUser[]>([]);
    const rancherGroups      = ref<RancherGroupPrincipal[]>([]);
    const rancherAdminRoles  = ref<Record<string, string[]>>({});
    const rancherError       = ref<string | null>(null);

    async function loadRancher() {
      rancherError.value = null;
      try {
        const [users, groups, bindings] = await Promise.all([
          listRancherUsers(),
          listGroupPrincipals(),
          listGlobalRoleBindings(),
        ]);
        rancherUsers.value      = users;
        rancherGroups.value     = groups;
        rancherAdminRoles.value = indexGlobalRoles(bindings);
      } catch (e: any) {
        const status = e?.response?.status || e?.status;
        if (status === 401 || status === 403) {
          rancherError.value = 'Cannot read Rancher RBAC — your Rancher user needs `get` on management.cattle.io users / globalrolebindings / principals.';
        } else {
          rancherError.value = e?.message || 'Failed to load Rancher RBAC';
        }
      }
    }

    function rancherUserIsAdmin(userId: string): boolean {
      const roles = rancherAdminRoles.value[userId] || [];
      const groups = localGroupsFor(userId, roles, roleMap.value);
      return groups.includes('mcp-admins') || roles.includes('admin');
    }

    // -------------------------------------------------- account / sign-in
    const authUser    = ref<AuthUser | null>(getStoredUser());
    const signInOpen  = ref(false);
    const signingIn   = ref(false);
    const signInError = ref<string | null>(null);
    const signInForm  = reactive({ userId: 'admin', password: '' });
    const canSignIn   = computed(() => !!(signInForm.userId.trim() && signInForm.password));

    function openSignIn() {
      signInForm.password = '';
      signInError.value   = null;
      signInOpen.value    = true;
    }
    function closeSignIn() { signInOpen.value = false; }

    async function signIn() {
      signingIn.value   = true;
      signInError.value = null;
      try {
        const { token, user } = await authApi.login(signInForm.userId.trim(), signInForm.password);
        if (!token) {
          signInError.value = 'Login succeeded but no token returned.';
          return;
        }
        setStoredToken(token);
        setStoredUser(user);
        authUser.value = user;
        signInOpen.value = false;
        // Re-prime user/group lists now that we may see more.
        loadUsers();
        loadGroups();
      } catch (e: any) {
        signInError.value = e?.data?.error || e?.message || 'Sign-in failed';
      } finally {
        signingIn.value = false;
      }
    }

    async function signOut() {
      try { await authApi.logout(); } catch { /* token may already be cleared */ }
      setStoredToken(null);
      setStoredUser(null);
      authUser.value = null;
    }

    // Auto-open the sign-in modal when any request returned 401
    // (base-api.ts dispatches this event from its response interceptor).
    function onAuthRequired() {
      authUser.value = null;
      openSignIn();
    }

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

    // Filtered views over the Rancher-sourced lists. Mirrors the local
    // filteredUsers/filteredGroups shape so the template branches stay
    // similar.
    const rancherFilteredUsers = computed<RancherUser[]>(() => {
      const q = userSearch.value.trim().toLowerCase();
      if (!q) return rancherUsers.value;
      return rancherUsers.value.filter((u) =>
        u.id.toLowerCase().includes(q)
        || u.name.toLowerCase().includes(q)
        || u.username.toLowerCase().includes(q),
      );
    });
    const rancherFilteredGroups = computed<RancherGroupPrincipal[]>(() => {
      const q = groupSearch.value.trim().toLowerCase();
      if (!q) return rancherGroups.value;
      return rancherGroups.value.filter((g) =>
        g.id.toLowerCase().includes(q)
        || g.name.toLowerCase().includes(q)
        || (g.provider || '').toLowerCase().includes(q),
      );
    });

    function rancherUserLocalGroups(userId: string): string[] {
      const roles = rancherAdminRoles.value[userId] || [];
      return localGroupsFor(userId, roles, roleMap.value);
    }

    // Load lazily — first time the tab is opened.
    watch(activeTab, (t) => {
      if (isRancherMode.value) {
        if ((t === 'users' || t === 'groups') && !rancherUsers.value.length && !rancherError.value) loadRancher();
      } else {
        if (t === 'users'  && !users.value.length)  loadUsers();
        if (t === 'groups' && !groups.value.length) loadGroups();
      }
    }, { immediate: false });

    onMounted(() => {
      window.addEventListener('suse-ai-up:auth-required', onAuthRequired);
      // First-login: prompt for identity provider if not yet chosen.
      if (identityProvider.value === null) {
        firstLoginOpen.value = true;
      }
      // Prime user/group sources for whatever the current provider is.
      if (isRancherMode.value) {
        loadRancher();
      } else {
        loadUsers();
        loadGroups();
      }
    });
    onUnmounted(() => {
      window.removeEventListener('suse-ai-up:auth-required', onAuthRequired);
    });

    return {
      // shared
      tabs, activeTab,
      // account
      authUser, signInOpen, signingIn, signInError, signInForm, canSignIn,
      openSignIn, closeSignIn, signIn, signOut,
      // identity
      identityProvider, effectiveProvider, isRancherMode, firstLoginOpen,
      roleMap, pickProvider, addRoleRule, deleteRoleRule, saveRoleMap, resetRoleMap,
      // rancher
      rancherUsers, rancherGroups, rancherError, loadRancher,
      rancherFilteredUsers, rancherFilteredGroups,
      rancherUserIsAdmin, rancherUserLocalGroups,
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

.account-bar {
  display:         flex;
  align-items:     center;
  justify-content: space-between;
  gap:             12px;
  padding:         10px 14px;
  border:          1px solid var(--border, #ddd);
  border-radius:   6px;
  background:      var(--disabled-bg, rgba(136, 136, 136, 0.04));
  margin-bottom:   12px;
}
.account-bar__info {
  display:        flex;
  flex-direction: column;
  gap:            2px;
  font-size:      13px;
}

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

.acl-row {
  display:     flex;
  align-items: flex-start;
  gap:         8px;
  font-size:   12px;
  color:       var(--body-text, #333);
}
.acl-row input { margin-top: 3px; }

.provider-cards {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.provider-card {
  display:        flex;
  flex-direction: column;
  gap:            6px;
  padding:        14px;
  border:         1px solid var(--border, #ddd);
  border-radius:  6px;
  background:     var(--body-bg, #fff);
  text-align:     left;
  cursor:         pointer;
  font:           inherit;
  color:          inherit;
}
.provider-card:hover {
  border-color: var(--primary, #1d4ed8);
  background:   var(--disabled-bg, rgba(136, 136, 136, 0.04));
}
.provider-card strong { font-size: 14px; }
.provider-card span   { font-size: 12px; color: var(--muted, #888); line-height: 1.4; }

.role-map {
  width:           100%;
  border-collapse: collapse;
  font-size:       12px;
}
.role-map th {
  text-align:    left;
  padding:       6px 8px;
  border-bottom: 1px solid var(--border, #ddd);
  color:         var(--muted, #888);
  font-weight:   600;
}
.role-map td {
  padding:       6px 8px;
  border-bottom: 1px solid var(--border, #eee);
  vertical-align: middle;
}
.role-map .ai-up-input { width: 100%; }
</style>
