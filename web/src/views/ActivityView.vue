<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import {
  api,
  type Alert,
  type Connection,
  type EventItem,
  type HistoryFilter,
  type HistoryList,
  type Page,
  type Server,
  type Session,
} from '../api'
import UiBadge from '../components/UiBadge.vue'
import UiButton from '../components/UiButton.vue'
import UiNotice from '../components/UiNotice.vue'
import { alertKind, dateTime, duration, endReason, errorMessage, eventKind, eventTone, formatBytes, isWebEvent } from '../format'
import { canManage, confirm, download, notify } from '../state'

type Tab = 'sessions' | 'history' | 'connections' | 'alerts' | 'events'
const pageSize = 100

const tab = ref<Tab>('sessions')
const sessions = ref<Session[]>([])
const alerts = ref<Alert[]>([])
const history = ref<Session[]>([])
const connections = ref<Connection[]>([])
const events = ref<EventItem[]>([])
// the page of the list of the tab, from the server: how many rows match, which ones are shown
const total = ref(0)
const offset = ref(0)
const servers = ref<Server[]>([])
const error = ref('')
const csvBusy = ref(false)
// the setting, for the sentence at the top
const historyDays = ref(0)

// the filters, the same on every tab: the logins, the connections and the events are filtered by the server, the
// sessions open and the alerts here
const search = ref('')
const words = ref('')
const server = ref(0)
const from = ref('')
const to = ref('')
const kind = ref<'' | 'web' | 'vpn'>('')

const paged = computed(() => tab.value === 'history' || tab.value === 'connections' || tab.value === 'events')
const filtered = computed(() =>
  Boolean(words.value || server.value || (paged.value && (from.value || to.value)) || (tab.value === 'events' && kind.value)),
)
const backwards = computed(() => Boolean(paged.value && from.value && to.value && from.value > to.value))
const placeholder = computed(() =>
  tab.value === 'events' ? 'User, peer, server, administrator, IP, detail' : 'User, peer, server, IP',
)
const rangeText = computed(() => {
  const shown = tab.value === 'history' ? history.value.length : tab.value === 'connections' ? connections.value.length : events.value.length
  return `${(offset.value + 1).toLocaleString()}–${(offset.value + shown).toLocaleString()} of ${total.value.toLocaleString()}`
})

// a day of the date fields, at local midnight; the end date counts whole
function unixOf(date: string, dayAfter = false): number | undefined {
  if (!date) {
    return undefined
  }
  const [year, month, day] = date.split('-').map(Number)
  return Math.floor(new Date(year, month - 1, day + (dayAfter ? 1 : 0)).getTime() / 1000)
}

function filter(): HistoryFilter {
  return {
    q: words.value,
    server: server.value,
    since: unixOf(from.value),
    until: unixOf(to.value, true),
    type: tab.value === 'events' ? kind.value : '',
    limit: pageSize,
    offset: offset.value,
  }
}

// each word in one of the texts, whatever the case
function matches(texts: string[], serverId: number): boolean {
  if (server.value && serverId !== server.value) {
    return false
  }
  const text = texts.join(' ').toLowerCase()
  return words.value
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((word) => text.includes(word))
}
const shownSessions = computed(() =>
  sessions.value.filter((s) => matches([s.username, s.peer_name, s.server_name, s.address, s.endpoint], s.server_id)),
)
const shownAlerts = computed(() =>
  alerts.value.filter((a) => matches([a.username, a.peer_name, a.server_name, ...a.addresses], a.server_id)),
)

function fetchPage(current: Tab): Promise<Page<Session> | Page<Connection> | Page<EventItem> | null> {
  switch (current) {
    case 'history':
      return api.history(filter())
    case 'connections':
      return api.connections(filter())
    case 'events':
      return api.events(filter())
    default:
      return Promise.resolve(null)
  }
}

// an answer to an older request is dropped: the tab or the filters changed meanwhile
let generation = 0
async function load() {
  const mine = ++generation
  const current = tab.value
  try {
    const [open, latest, page] = await Promise.all([api.sessions(), api.alerts(), fetchPage(current)])
    if (mine !== generation) {
      return
    }
    sessions.value = open
    alerts.value = latest
    error.value = ''
    if (!page) {
      return
    }
    // fewer rows than before: the last page that has some
    if (page.total > 0 && offset.value >= page.total) {
      offset.value = Math.floor((page.total - 1) / pageSize) * pageSize
      return load()
    }
    total.value = page.total
    if (current === 'history') {
      history.value = page.items as Session[]
    } else if (current === 'connections') {
      connections.value = page.items as Connection[]
    } else {
      events.value = page.items as EventItem[]
    }
  } catch (e) {
    if (mine === generation) {
      error.value = errorMessage(e)
    }
  }
}

function go(pages: number) {
  offset.value = Math.max(0, offset.value + pages * pageSize)
  load()
}

function clearFilters() {
  search.value = ''
  words.value = ''
  server.value = 0
  from.value = ''
  to.value = ''
  kind.value = ''
}

// the search applies once the typing pauses
let typing: number | undefined
watch(search, (text) => {
  clearTimeout(typing)
  typing = window.setTimeout(() => (words.value = text.trim()), 300)
})
watch([tab, words, server, from, to, kind], () => {
  offset.value = 0
  total.value = 0
  load()
})

// how long a connection lasted, or lasts
function lasted(connection: Connection): string {
  const end = connection.connected ? connection.last_seen : connection.ended_at
  const seconds = Math.max(0, end - connection.started_at)
  return seconds < 60 ? 'less than 1 min' : duration(seconds - (seconds % 60))
}

// every row that matches the filters, not only the page: the server makes the file
async function downloadCSV() {
  csvBusy.value = true
  try {
    const file = await api.historyCSV(tab.value as HistoryList, filter())
    download(file.name, file.text, 'text/csv')
  } catch (e) {
    notify(errorMessage(e), 'error')
  } finally {
    csvBusy.value = false
  }
}

let timer: number | undefined
onMounted(async () => {
  load()
  timer = window.setInterval(load, 10000)
  try {
    servers.value = await api.servers()
  } catch {
    // the filter of the server waits for the next visit
  }
  try {
    historyDays.value = (await api.settings()).history_days
  } catch {
    // the sentence says it without the number
  }
})
onBeforeUnmount(() => {
  clearInterval(timer)
  clearTimeout(typing)
})

async function end(session: Session) {
  const ok = await confirm(
    `End the session of ${session.username}?`,
    `The traffic of ${session.peer_name} stops until ${session.username} logs in again.`,
    'End session',
  )
  if (!ok) {
    return
  }
  try {
    await api.endSession(session.id)
    notify('Session ended.')
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
  load()
}

async function clearAlerts(alert: Alert) {
  const ok = await confirm(
    `Clear the alerts of ${alert.peer_name}?`,
    alert.blocked ? 'The peer is unblocked: its user can log in again.' : 'They are deleted.',
    alert.blocked ? 'Clear and unblock' : 'Clear',
    false,
  )
  if (!ok) {
    return
  }
  try {
    await api.clearPeerAlerts(alert.peer_id)
    notify('Alerts cleared.')
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
  load()
}

// where an event happened: its server and peer, the web UI, or nowhere in particular
function eventPlace(event: EventItem): string {
  if (event.server_name) {
    return event.peer_name ? `${event.server_name} · ${event.peer_name}` : event.server_name
  }
  return isWebEvent(event.kind) ? 'Web UI' : '—'
}

const tabs: { id: Tab; label: string }[] = [
  { id: 'sessions', label: 'Logged in' },
  { id: 'history', label: 'Login history' },
  { id: 'connections', label: 'Connections' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'events', label: 'Events' },
]

const th = 'px-4 py-3'
const control =
  'block rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 dark:[color-scheme:dark]'
const caption = 'mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400'
</script>

<template>
  <div class="mx-auto max-w-7xl">
    <h1 class="text-2xl font-semibold tracking-tight">Activity</h1>
    <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
      The sessions of the servers with login, the connections of all the peers, the alerts, and what happened: the
      logins, and every change made in the web UI, by whom. The newest are on top.
      {{ historyDays ? `The history keeps ${historyDays} ${historyDays === 1 ? 'day' : 'days'} (Settings).` : '' }}
    </p>

    <UiNotice v-if="error" tone="error" class="mt-6">{{ error }}</UiNotice>

    <div class="mt-6 border-b border-slate-200 dark:border-slate-800">
      <nav class="-mb-px flex gap-6 overflow-x-auto" aria-label="Activity">
        <button
          v-for="entry in tabs"
          :key="entry.id"
          type="button"
          class="flex items-center gap-2 border-b-2 px-1 pb-3 text-sm font-medium whitespace-nowrap"
          :class="
            tab === entry.id
              ? 'border-sky-700 text-sky-800 dark:border-sky-400 dark:text-sky-300'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          "
          :aria-current="tab === entry.id ? 'page' : undefined"
          @click="tab = entry.id"
        >
          {{ entry.label }}
          <UiBadge v-if="entry.id === 'sessions'" tone="sky">{{ sessions.length }}</UiBadge>
          <UiBadge v-if="entry.id === 'alerts' && alerts.length" tone="red">{{ alerts.length }}</UiBadge>
        </button>
      </nav>
    </div>

    <form class="mt-5 flex flex-wrap items-end gap-3" role="search" aria-label="Filters" @submit.prevent>
      <label class="block min-w-0 grow basis-full sm:basis-64">
        <span :class="caption">Search</span>
        <input v-model="search" type="search" :placeholder="placeholder" :class="[control, 'w-full']" />
      </label>
      <label class="block grow sm:grow-0">
        <span :class="caption">Server</span>
        <select v-model.number="server" :class="[control, 'w-full']">
          <option :value="0">All servers</option>
          <option v-for="entry in servers" :key="entry.id" :value="entry.id">{{ entry.name }}</option>
        </select>
      </label>
      <template v-if="paged">
        <label class="block grow sm:grow-0">
          <span :class="caption">From</span>
          <input v-model="from" type="date" :max="to || undefined" :class="[control, 'w-full']" />
        </label>
        <label class="block grow sm:grow-0">
          <span :class="caption">To</span>
          <input v-model="to" type="date" :min="from || undefined" :class="[control, 'w-full']" />
        </label>
      </template>
      <label v-if="tab === 'events'" class="block grow sm:grow-0">
        <span :class="caption">Events</span>
        <select v-model="kind" :class="[control, 'w-full']">
          <option value="">All</option>
          <option value="vpn">Of the peers: logins, copies, devices</option>
          <option value="web">Of the web UI: administrators and changes</option>
        </select>
      </label>
      <UiButton v-if="filtered || search" variant="ghost" @click="clearFilters">Clear filters</UiButton>
      <UiButton v-if="paged" icon="download" :loading="csvBusy" class="sm:ml-auto" @click="downloadCSV">
        Download CSV
      </UiButton>
    </form>
    <p v-if="backwards" class="mt-2 text-sm text-amber-700 dark:text-amber-400">The end date is before the start date.</p>
    <p v-if="tab === 'connections'" class="mt-3 text-sm text-slate-500 dark:text-slate-400">
      A connection is a run of handshakes from one public IP: WireGuard has none of its own. The times are precise to the
      minute. The dates find the connections that overlap them.
    </p>
    <p v-else-if="paged" class="mt-3 text-sm text-slate-500 dark:text-slate-400">
      The CSV file has every row that matches the filters, not only this page.
    </p>

    <div class="mt-4 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div class="relative overflow-x-auto">
        <table v-if="tab === 'sessions' || tab === 'history'" class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" :class="th">User</th>
              <th scope="col" :class="th">Server · peer</th>
              <th scope="col" :class="th">Login from</th>
              <th scope="col" :class="th">Started</th>
              <th scope="col" :class="th">{{ tab === 'sessions' ? 'Ends' : 'Ended' }}</th>
              <th scope="col" :class="th"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="session in tab === 'sessions' ? shownSessions : history" :key="session.id">
              <td class="px-4 py-3 font-medium">
                {{ session.username }}
                <UiBadge v-if="tab === 'sessions' && session.paused_at" tone="amber" class="ml-1.5">Paused</UiBadge>
              </td>
              <td class="px-4 py-3">
                {{ session.server_name }} · {{ session.peer_name }}
                <p class="font-mono text-xs text-slate-500">{{ session.address }}</p>
              </td>
              <td class="px-4 py-3 font-mono whitespace-nowrap">{{ session.endpoint || '—' }}</td>
              <td class="px-4 py-3 whitespace-nowrap">{{ dateTime(session.started_at) }}</td>
              <td class="px-4 py-3 whitespace-nowrap">
                <template v-if="tab === 'sessions'">
                  {{ dateTime(session.expires_at) }}
                  <p v-if="session.paused_at" class="text-xs text-amber-700 dark:text-amber-300">
                    Paused since {{ dateTime(session.paused_at) }}: another public IP
                  </p>
                </template>
                <template v-else>
                  {{ dateTime(session.ended_at) }}
                  <p class="text-xs text-slate-500">{{ endReason(session.end_reason) }}</p>
                </template>
              </td>
              <td class="px-4 py-3 text-right">
                <UiButton v-if="tab === 'sessions' && canManage()" size="sm" icon="logout" @click="end(session)">End</UiButton>
              </td>
            </tr>
            <tr v-if="!(tab === 'sessions' ? shownSessions : history).length">
              <td colspan="6" class="px-4 py-8 text-center text-slate-500">
                {{ filtered ? 'Nothing matches the filters.' : tab === 'sessions' ? 'Nobody is logged in.' : 'No session ended yet.' }}
              </td>
            </tr>
          </tbody>
        </table>

        <table v-else-if="tab === 'connections'" class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" :class="th">Server · peer</th>
              <th scope="col" :class="th">User</th>
              <th scope="col" :class="th">From</th>
              <th scope="col" :class="th">Started</th>
              <th scope="col" :class="th">Lasted</th>
              <th scope="col" :class="th">Traffic</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="connection in connections" :key="connection.id">
              <td class="px-4 py-3">
                {{ connection.server_name }} · {{ connection.peer_name }}
                <p class="font-mono text-xs text-slate-500">{{ connection.address }}</p>
              </td>
              <td class="px-4 py-3">{{ connection.username || '—' }}</td>
              <td class="px-4 py-3 font-mono whitespace-nowrap">{{ connection.endpoint || '—' }}</td>
              <td class="px-4 py-3 whitespace-nowrap">{{ dateTime(connection.started_at) }}</td>
              <td class="px-4 py-3 whitespace-nowrap">
                <UiBadge v-if="connection.connected" tone="green" dot>Connected</UiBadge>
                <template v-else>{{ lasted(connection) }}</template>
                <p class="text-xs text-slate-500">
                  {{ connection.connected ? `for ${lasted(connection)}` : `until ${dateTime(connection.ended_at)}` }}
                </p>
              </td>
              <td class="px-4 py-3 whitespace-nowrap text-slate-600 dark:text-slate-300">
                ↓ {{ formatBytes(connection.received) }} · ↑ {{ formatBytes(connection.sent) }}
              </td>
            </tr>
            <tr v-if="!connections.length">
              <td colspan="6" class="px-4 py-8 text-center text-slate-500">
                {{ filtered ? 'Nothing matches the filters.' : 'No connection yet.' }}
              </td>
            </tr>
          </tbody>
        </table>

        <table v-else-if="tab === 'alerts'" class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" :class="th">When</th>
              <th scope="col" :class="th">Alert</th>
              <th scope="col" :class="th">Server · peer</th>
              <th scope="col" :class="th">User</th>
              <th scope="col" :class="th">Public IPs</th>
              <th scope="col" :class="th"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="alert in shownAlerts" :key="alert.id">
              <td class="px-4 py-3 whitespace-nowrap">{{ dateTime(alert.at) }}</td>
              <td class="px-4 py-3">
                <div class="flex flex-wrap gap-1.5">
                  <UiBadge :tone="alert.kind === 'copy' ? 'red' : 'amber'">{{ alertKind(alert.kind) }}</UiBadge>
                  <UiBadge v-if="alert.blocked" tone="red">Peer blocked</UiBadge>
                </div>
              </td>
              <td class="px-4 py-3">
                <RouterLink :to="{ name: 'servers', params: { id: alert.server_id } }" class="hover:underline">
                  {{ alert.server_name }} · {{ alert.peer_name }}
                </RouterLink>
              </td>
              <td class="px-4 py-3">{{ alert.username || '—' }}</td>
              <td class="px-4 py-3 font-mono">{{ alert.addresses.join(', ') || '—' }}</td>
              <td class="px-4 py-3 text-right">
                <UiButton v-if="canManage()" size="sm" @click="clearAlerts(alert)">{{ alert.blocked ? 'Unblock' : 'Clear' }}</UiButton>
              </td>
            </tr>
            <tr v-if="!shownAlerts.length">
              <td colspan="6" class="px-4 py-8 text-center text-slate-500">{{ filtered ? 'Nothing matches the filters.' : 'No alert.' }}</td>
            </tr>
          </tbody>
        </table>

        <table v-else class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" :class="th">When</th>
              <th scope="col" :class="th">What</th>
              <th scope="col" :class="th">Server · peer</th>
              <th scope="col" :class="th">User</th>
              <th scope="col" :class="th">By</th>
              <th scope="col" :class="th">From</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="event in events" :key="event.id">
              <td class="px-4 py-3 whitespace-nowrap">{{ dateTime(event.at) }}</td>
              <td class="max-w-md px-4 py-3">
                <UiBadge :tone="eventTone(event.kind)">{{ eventKind(event.kind) }}</UiBadge>
                <p v-if="event.detail" class="mt-1 text-xs break-words text-slate-500">{{ event.detail }}</p>
              </td>
              <td class="px-4 py-3">{{ eventPlace(event) }}</td>
              <td class="px-4 py-3">{{ event.username || '—' }}</td>
              <td class="px-4 py-3">{{ event.by || '—' }}</td>
              <td class="px-4 py-3 font-mono whitespace-nowrap">{{ event.source || '—' }}</td>
            </tr>
            <tr v-if="!events.length">
              <td colspan="6" class="px-4 py-8 text-center text-slate-500">{{ filtered ? 'Nothing matches the filters.' : 'Nothing yet.' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        v-if="paged && total > 0"
        class="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 px-4 py-3 text-sm dark:border-slate-800"
      >
        <p class="text-slate-500 dark:text-slate-400">{{ rangeText }}</p>
        <div class="flex gap-2">
          <UiButton size="sm" :disabled="offset === 0" aria-label="Newer page" @click="go(-1)">Newer</UiButton>
          <UiButton size="sm" :disabled="offset + pageSize >= total" aria-label="Older page" @click="go(1)">Older</UiButton>
        </div>
      </div>
    </div>
  </div>
</template>
