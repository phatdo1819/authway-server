<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { api, type TotpSetup, type User } from '../api'
import UiBadge from '../components/UiBadge.vue'
import UiButton from '../components/UiButton.vue'
import UiEmpty from '../components/UiEmpty.vue'
import UiMenu, { type MenuItem } from '../components/UiMenu.vue'
import UiNotice from '../components/UiNotice.vue'
import { errorMessage } from '../format'
import { canManage, confirm, notify } from '../state'
import ImportModal from './users/ImportModal.vue'
import TotpModal from './users/TotpModal.vue'
import UserDrawer from './users/UserDrawer.vue'

const users = ref<User[]>([])
const loading = ref(true)
const error = ref('')
const search = ref('')
const drawerOpen = ref(false)
const editing = ref<User | null>(null)
const totp = ref<{ user: User; setup: TotpSetup } | null>(null)
const importing = ref(false)

const filtered = computed(() => {
  const text = search.value.trim().toLowerCase()
  return text
    ? users.value.filter((user) => user.username.toLowerCase().includes(text) || user.full_name.toLowerCase().includes(text))
    : users.value
})

async function load() {
  try {
    users.value = await api.users()
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

function edit(user: User) {
  editing.value = user
  drawerOpen.value = true
}

async function saved() {
  drawerOpen.value = false
  await load()
}

async function setupTotp(user: User) {
  if (user.totp) {
    const ok = await confirm(
      `New authenticator for ${user.username}?`,
      'The codes of the current authenticator stop working, and the user is logged out.',
      'Set up again',
    )
    if (!ok) {
      return
    }
  }
  try {
    totp.value = { user, setup: await api.setupTotp(user.id) }
    await load()
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
}

function menu(user: User): MenuItem[] {
  const items: MenuItem[] = [
    { label: 'Edit', icon: 'edit', action: () => edit(user) },
    { label: user.totp ? 'New authenticator' : 'Set up authenticator', icon: 'shield', action: () => setupTotp(user) },
  ]
  if (user.totp) {
    items.push({
      label: 'Remove authenticator',
      icon: 'close',
      action: async () => {
        const ok = await confirm(
          `Remove the authenticator of ${user.username}?`,
          "On the servers that ask for a code, the user can't log in until a new authenticator is set up.",
          'Remove',
        )
        if (ok) {
          try {
            await api.removeTotp(user.id)
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
      const peers = user.peers.length
        ? `\n\nIts peers are deleted too, and their configuration files stop working:\n${user.peers.join('\n')}`
        : ''
      const ok = await confirm(`Delete ${user.username}?`, `This can't be undone.${peers}`, 'Delete user')
      if (ok) {
        try {
          await api.deleteUser(user.id)
          notify(`${user.username} deleted.`)
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
        <h1 class="text-2xl font-semibold tracking-tight">Users</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          The people who log in on the servers with login. Each user has at most one peer on each server.
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <input
          v-if="users.length"
          v-model="search"
          type="search"
          placeholder="Search users"
          aria-label="Search users"
          class="w-56 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900"
        />
        <UiButton v-if="canManage()" icon="upload" @click="importing = true">Import</UiButton>
        <UiButton v-if="canManage()" variant="primary" icon="plus" @click="add">Add user</UiButton>
      </div>
    </div>

    <UiNotice v-if="error" tone="error" class="mt-6">{{ error }}</UiNotice>
    <div v-if="loading" class="mt-10 text-sm text-slate-500">Loading…</div>
    <UiEmpty
      v-else-if="!users.length && !error"
      class="mt-8"
      icon="users"
      title="No user yet"
      text="Add the users, then give each one a peer on the servers they use. Many at once: Import, from a CSV file."
    />
    <div
      v-else-if="users.length"
      class="mt-6 relative overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
        <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
          <tr>
            <th scope="col" class="px-4 py-3">User</th>
            <th scope="col" class="px-4 py-3">Authenticator</th>
            <th scope="col" class="px-4 py-3">Peers</th>
            <th scope="col" class="px-4 py-3">Status</th>
            <th scope="col" class="px-4 py-3"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
          <tr v-for="user in filtered" :key="user.id">
            <td class="px-4 py-3">
              <p class="font-medium">{{ user.username }}</p>
              <p v-if="user.full_name" class="text-slate-500 dark:text-slate-400">{{ user.full_name }}</p>
            </td>
            <td class="px-4 py-3">
              <UiBadge :tone="user.totp ? 'green' : 'gray'">{{ user.totp ? 'Set up' : 'None' }}</UiBadge>
            </td>
            <td class="px-4 py-3 text-slate-600 dark:text-slate-300">
              <span v-if="!user.peers.length" class="text-slate-400">—</span>
              <ul v-else>
                <li v-for="peer in user.peers" :key="peer">{{ peer }}</li>
              </ul>
            </td>
            <td class="px-4 py-3">
              <div class="flex flex-wrap gap-1.5">
                <UiBadge v-if="user.disabled" tone="red">Disabled</UiBadge>
                <UiBadge v-else-if="user.sessions" tone="sky">Logged in</UiBadge>
                <UiBadge v-else tone="gray">Active</UiBadge>
              </div>
            </td>
            <td class="px-4 py-3 text-right">
              <UiMenu v-if="canManage()" :items="menu(user)" :label="`Actions of ${user.username}`" />
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="5" class="px-4 py-6 text-center text-slate-500">No user matches "{{ search }}".</td>
          </tr>
        </tbody>
      </table>
    </div>

    <UserDrawer :open="drawerOpen" :user="editing" @close="drawerOpen = false" @saved="saved" />
    <TotpModal :data="totp" @close="totp = null" />
    <ImportModal :open="importing" @close="importing = false" @imported="load" />
  </div>
</template>
