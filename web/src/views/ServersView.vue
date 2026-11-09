<script setup lang="ts">
import { computed, inject, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Server } from '../api'
import UiButton from '../components/UiButton.vue'
import UiEmpty from '../components/UiEmpty.vue'
import UiNotice from '../components/UiNotice.vue'
import { errorMessage } from '../format'
import { isAdmin } from '../state'
import ServerDrawer from './servers/ServerDrawer.vue'
import ServerPanel from './servers/ServerPanel.vue'

const route = useRoute()
const router = useRouter()
const refreshStatus = inject<() => void>('refreshStatus', () => {})

const servers = ref<Server[]>([])
const loading = ref(true)
const error = ref('')
const drawerOpen = ref(false)
const editing = ref<Server | null>(null)

const selected = computed(() => {
  const id = Number(route.params.id)
  return servers.value.find((server) => server.id === id) ?? servers.value[0] ?? null
})

async function load() {
  try {
    servers.value = await api.servers()
    error.value = ''
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}

function add() {
  editing.value = null
  drawerOpen.value = true
}

function edit(server: Server) {
  editing.value = server
  drawerOpen.value = true
}

async function saved(server: Server) {
  drawerOpen.value = false
  await load()
  refreshStatus()
  router.replace({ name: 'servers', params: { id: server.id } })
}

async function deleted() {
  await load()
  refreshStatus()
  router.replace({ name: 'servers', params: { id: servers.value[0]?.id ?? '' } })
}

onMounted(load)
</script>

<template>
  <div class="mx-auto max-w-7xl">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">WireGuard servers</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Each server has its own port, network and peers. A server with login lets its peers through only after their
          user logs in.
        </p>
      </div>
      <UiButton v-if="servers.length && isAdmin()" variant="primary" icon="plus" @click="add">Add server</UiButton>
    </div>

    <UiNotice v-if="error" tone="error" class="mt-6">{{ error }}</UiNotice>

    <div v-if="loading" class="mt-10 text-sm text-slate-500">Loading…</div>

    <UiEmpty
      v-else-if="!servers.length && !error"
      class="mt-8"
      icon="server"
      title="No WireGuard server yet"
      text="Add a server, then its peers: each peer gets a configuration file for the WireGuard apps or for Authway."
    >
      <UiButton v-if="isAdmin()" variant="primary" icon="plus" @click="add">Add server</UiButton>
    </UiEmpty>

    <template v-else-if="selected">
      <div class="mt-6 border-b border-slate-200 dark:border-slate-800">
        <nav class="-mb-px flex gap-6 overflow-x-auto" aria-label="Servers">
          <RouterLink
            v-for="server in servers"
            :key="server.id"
            :to="{ name: 'servers', params: { id: server.id } }"
            class="flex items-center gap-2 border-b-2 px-1 pb-3 text-sm font-medium whitespace-nowrap"
            :class="
              server.id === selected.id
                ? 'border-sky-700 text-sky-800 dark:border-sky-400 dark:text-sky-300'
                : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            "
            :aria-current="server.id === selected.id ? 'page' : undefined"
          >
            <span
              class="h-2 w-2 rounded-full"
              :class="server.enabled ? 'bg-emerald-500' : 'bg-slate-400'"
              aria-hidden="true"
            />
            {{ server.name }}
          </RouterLink>
        </nav>
      </div>
      <ServerPanel
        :key="selected.id"
        :server="selected"
        :servers="servers"
        class="mt-6"
        @edit="edit"
        @deleted="deleted"
        @changed="load"
      />
    </template>

    <ServerDrawer :open="drawerOpen" :server="editing" :servers="servers" @close="drawerOpen = false" @saved="saved" />
  </div>
</template>
