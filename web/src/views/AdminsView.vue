<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { api, type AdminAccount } from '../api'
import UiBadge from '../components/UiBadge.vue'
import UiButton from '../components/UiButton.vue'
import UiMenu, { type MenuItem } from '../components/UiMenu.vue'
import UiNotice from '../components/UiNotice.vue'
import { ago, errorMessage, roleLabel } from '../format'
import { confirm, notify, session } from '../state'
import AdminDrawer from './admins/AdminDrawer.vue'
import ResetPasswordModal from './admins/ResetPasswordModal.vue'

const admins = ref<AdminAccount[]>([])
const loading = ref(true)
const error = ref('')
const drawerOpen = ref(false)
const editing = ref<AdminAccount | null>(null)
const resetting = ref<AdminAccount | null>(null)

async function load() {
  try {
    admins.value = await api.admins()
    error.value = ''
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

function add() {
  editing.value = null
  drawerOpen.value = true
}

function edit(admin: AdminAccount) {
  editing.value = admin
  drawerOpen.value = true
}

async function saved() {
  drawerOpen.value = false
  resetting.value = null
  await load()
}

function menu(admin: AdminAccount): MenuItem[] {
  const own = admin.id === session.me?.id
  const items: MenuItem[] = [{ label: 'Edit', icon: 'edit', action: () => edit(admin) }]
  if (own) {
    return items
  }
  items.push({ label: 'New password', icon: 'key', action: () => (resetting.value = admin) })
  if (admin.totp) {
    items.push({
      label: 'Remove authenticator',
      icon: 'close',
      action: async () => {
        const ok = await confirm(
          `Remove the authenticator of ${admin.username}?`,
          'For an administrator who lost the phone. They are logged out; the next login asks only for the password, and sets up a new authenticator when the settings require one.',
          'Remove',
        )
        if (ok) {
          try {
            await api.removeAdminTotp(admin.id)
            notify('Authenticator removed.')
          } catch (e) {
            notify(errorMessage(e), 'error')
          }
          load()
        }
      },
    })
  }
  items.push({
    label: 'Delete',
    icon: 'trash',
    danger: true,
    action: async () => {
      const ok = await confirm(`Delete ${admin.username}?`, "They are logged out now. This can't be undone.", 'Delete administrator')
      if (ok) {
        try {
          await api.deleteAdmin(admin.id)
          notify(`${admin.username} deleted.`)
        } catch (e) {
          notify(errorMessage(e), 'error')
        }
        load()
      }
    },
  })
  return items
}
</script>

<template>
  <div class="mx-auto max-w-7xl">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Administrators</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          The people who log in on this web UI. Administrators do everything, Operators manage the users and the peers,
          Read-only sees without changing.
        </p>
      </div>
      <UiButton variant="primary" icon="plus" @click="add">Add administrator</UiButton>
    </div>

    <UiNotice v-if="error" tone="error" class="mt-6">{{ error }}</UiNotice>
    <div v-if="loading" class="mt-10 text-sm text-slate-500">Loading…</div>
    <div
      v-else-if="admins.length"
      class="relative mt-6 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
        <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
          <tr>
            <th scope="col" class="px-4 py-3">Administrator</th>
            <th scope="col" class="px-4 py-3">Role</th>
            <th scope="col" class="px-4 py-3">Authenticator</th>
            <th scope="col" class="px-4 py-3">Latest login</th>
            <th scope="col" class="px-4 py-3">Status</th>
            <th scope="col" class="px-4 py-3"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
          <tr v-for="admin in admins" :key="admin.id">
            <td class="px-4 py-3">
              <p class="font-medium">
                {{ admin.username }}
                <UiBadge v-if="admin.id === session.me?.id" tone="sky" class="ml-1">You</UiBadge>
              </p>
              <p v-if="admin.full_name" class="text-slate-500 dark:text-slate-400">{{ admin.full_name }}</p>
            </td>
            <td class="px-4 py-3">{{ roleLabel(admin.role) }}</td>
            <td class="px-4 py-3">
              <UiBadge :tone="admin.totp ? 'green' : 'gray'">{{ admin.totp ? 'On' : 'Off' }}</UiBadge>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
              <p>{{ ago(admin.last_login_at) }}</p>
              <p v-if="admin.last_login_from" class="font-mono text-xs text-slate-500 dark:text-slate-400">{{ admin.last_login_from }}</p>
            </td>
            <td class="px-4 py-3">
              <div class="flex flex-wrap gap-1.5">
                <UiBadge v-if="admin.disabled" tone="red">Disabled</UiBadge>
                <UiBadge v-else-if="admin.must_change_password" tone="amber">New password at next login</UiBadge>
                <UiBadge v-else tone="gray">Active</UiBadge>
              </div>
            </td>
            <td class="px-4 py-3 text-right">
              <UiMenu :items="menu(admin)" :label="`Actions of ${admin.username}`" />
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <AdminDrawer :open="drawerOpen" :admin="editing" @close="drawerOpen = false" @saved="saved" />
    <ResetPasswordModal :admin="resetting" @close="resetting = null" @saved="saved" />
  </div>
</template>
