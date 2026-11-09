<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Status } from '../api'
import AppIcon, { type IconName } from '../components/AppIcon.vue'
import UiButton from '../components/UiButton.vue'
import UiNotice from '../components/UiNotice.vue'
import { dateTime, errorMessage, roleLabel } from '../format'
import { isAdmin, notify, session } from '../state'

const router = useRouter()
const route = useRoute()
const status = ref<Status | null>(null)
const menuOpen = ref(false)

const links = computed(() => {
  const list: { to: string; label: string; icon: IconName }[] = [
    { to: '/servers', label: 'WireGuard servers', icon: 'server' },
    { to: '/users', label: 'Users', icon: 'users' },
    { to: '/activity', label: 'Activity', icon: 'activity' },
    { to: '/system', label: 'System', icon: 'gauge' },
  ]
  if (isAdmin()) {
    list.push({ to: '/admins', label: 'Administrators', icon: 'lock' })
  }
  list.push({ to: '/settings', label: 'Settings', icon: 'settings' })
  return list
})

// for the link of the account, at the bottom of the menu
const initials = computed(() => {
  const name = (session.me?.full_name || session.me?.username || '?').trim()
  const words = name.split(/\s+/).filter(Boolean)
  return (words.length > 1 ? words[0][0] + words[words.length - 1][0] : name.slice(0, 2)).toUpperCase()
})

// /servers/2 is in the servers too
function active(path: string): boolean {
  return route.path === path || route.path.startsWith(path + '/')
}

async function refreshStatus() {
  try {
    status.value = await api.status()
  } catch {
    // the pages say it when the server doesn't answer
  }
}
// the pages call it after a change, so the warning of the top follows
provide('refreshStatus', refreshStatus)

// the address of the Docker host changed: an Administrator says the router has the new routes
const confirming = ref(false)
async function confirmRoutes() {
  confirming.value = true
  try {
    await api.confirmHostAddresses()
    await refreshStatus()
  } catch (e) {
    notify(errorMessage(e), 'error')
  } finally {
    confirming.value = false
  }
}

let timer: number | undefined
onMounted(() => {
  refreshStatus()
  timer = window.setInterval(refreshStatus, 15000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(
  () => route.fullPath,
  () => (menuOpen.value = false),
)

async function logout() {
  try {
    await api.logout()
  } catch {
    notify("The server doesn't answer: the session ends anyway when you close the browser.", 'error')
  }
  session.me = null
  router.push({ name: 'login' })
}
</script>

<template>
  <div class="min-h-screen lg:flex">
    <header
      class="sticky top-0 z-30 flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 lg:hidden dark:border-slate-800 dark:bg-slate-900"
    >
      <div class="flex items-center gap-2.5">
        <img src="/icon.svg" alt="" width="28" height="28" />
        <span class="font-semibold">Authway Server</span>
      </div>
      <button
        type="button"
        class="rounded-md p-2 hover:bg-slate-100 dark:hover:bg-slate-800"
        :aria-expanded="menuOpen"
        aria-label="Menu"
        @click="menuOpen = !menuOpen"
      >
        <AppIcon :name="menuOpen ? 'close' : 'menu'" />
      </button>
    </header>

    <nav
      class="z-20 w-full shrink-0 flex-col border-r border-slate-200 bg-white lg:sticky lg:top-0 lg:flex lg:h-screen lg:w-64 dark:border-slate-800 dark:bg-slate-900"
      :class="menuOpen ? 'flex' : 'hidden'"
      aria-label="Main"
    >
      <div class="hidden items-center gap-3 px-5 py-5 lg:flex">
        <img src="/icon.svg" alt="" width="32" height="32" />
        <div>
          <p class="leading-tight font-semibold">Authway Server</p>
          <p class="text-xs text-slate-500 dark:text-slate-400">WireGuard with login</p>
        </div>
      </div>
      <ul class="flex-1 space-y-1 px-3 py-3 lg:py-0">
        <li v-for="link in links" :key="link.to">
          <RouterLink
            :to="link.to"
            class="flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium"
            :class="
              active(link.to)
                ? 'bg-sky-50 text-sky-800 dark:bg-sky-500/10 dark:text-sky-300'
                : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
            "
            :aria-current="active(link.to) ? 'page' : undefined"
          >
            <AppIcon :name="link.icon" />
            {{ link.label }}
          </RouterLink>
        </li>
      </ul>
      <div class="border-t border-slate-200 px-3 py-3 dark:border-slate-800">
        <div class="flex items-center justify-between gap-1">
          <RouterLink
            to="/account"
            class="flex min-w-0 flex-1 items-center gap-2.5 rounded-md px-2 py-1.5"
            :class="
              active('/account')
                ? 'bg-sky-50 text-sky-800 dark:bg-sky-500/10 dark:text-sky-300'
                : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'
            "
            :aria-current="active('/account') ? 'page' : undefined"
            title="Your account: authenticator app and password"
          >
            <span
              class="flex size-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-xs font-semibold text-sky-800 dark:bg-sky-500/15 dark:text-sky-300"
              aria-hidden="true"
            >
              {{ initials }}
            </span>
            <span class="min-w-0">
              <span class="block truncate text-sm font-medium">{{ session.me?.username }}</span>
              <span class="block truncate text-xs text-slate-500 dark:text-slate-400">{{ roleLabel(session.me?.role ?? 'viewer') }}</span>
              <span class="sr-only">, your account</span>
            </span>
          </RouterLink>
          <button
            type="button"
            class="inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1.5 text-sm text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
            @click="logout"
          >
            <AppIcon name="logout" :size="18" />Log out
          </button>
        </div>
        <p v-if="status?.version" class="mt-2 px-2 text-xs text-slate-400 dark:text-slate-500">Authway Server {{ status.version }}</p>
      </div>
    </nav>

    <main class="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-10 lg:py-8">
      <UiNotice v-if="status?.apply_error" tone="error" title="The configuration isn't applied" class="mb-6">
        <p class="break-words">{{ status.apply_error }}</p>
        <p class="mt-1">The server tries again every few seconds. Check the log of the container.</p>
      </UiNotice>
      <UiNotice v-if="status?.host_changes?.length" tone="warning" title="The address of the Docker host changed" class="mb-6">
        <p>
          The router of the networks of the routed servers still sends the tunnels to the address of before, so the networks
          don't answer the peers. Change these routes on the router:
        </p>
        <ul class="mt-1.5 space-y-0.5">
          <li v-for="change in status.host_changes" :key="change.tunnel" class="break-words">
            {{ change.server }}:
            <span class="font-mono font-medium">{{ change.tunnel }} via {{ change.address }}</span>, instead of via
            <span class="font-mono">{{ change.previous }}</span>
            <span class="opacity-75"> · since {{ dateTime(change.at) }}</span>
          </li>
        </ul>
        <p class="mt-1.5">Give the Docker host a fixed address, a DHCP reservation for example, so it doesn't change again.</p>
        <div v-if="isAdmin()" class="mt-3">
          <UiButton size="sm" icon="check" :loading="confirming" @click="confirmRoutes">The router has the new routes</UiButton>
        </div>
        <p v-else class="mt-1.5">An Administrator clears this warning once the router has the new routes.</p>
      </UiNotice>
      <RouterView />
    </main>
  </div>
</template>
