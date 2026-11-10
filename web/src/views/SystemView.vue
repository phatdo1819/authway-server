<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import {
  api,
  type CheckStatus,
  type LogEntry,
  type Server,
  type SystemCheck,
  type SystemDisk,
  type SystemInterface,
  type SystemPoint,
  type SystemSnapshot,
} from '../api'
import AppIcon, { type IconName } from '../components/AppIcon.vue'
import LineChart from '../components/LineChart.vue'
import UiBadge from '../components/UiBadge.vue'
import UiButton from '../components/UiButton.vue'
import UiNotice from '../components/UiNotice.vue'
import { dateTime, errorMessage, formatBytes, formatPercent, formatRate, uptime } from '../format'

// The System page: the checks of what goes wrong most, the resources of the host and of Authway Server, their
// history, the network interfaces, the disks and the latest lines of the log, in tabs. The snapshot is read again
// every 5 seconds; the history and the log only while their tab is open.
type Tab = 'overview' | 'history' | 'network' | 'host' | 'log'
const tabs: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'history', label: 'History' },
  { id: 'network', label: 'Network' },
  { id: 'host', label: 'Host' },
  { id: 'log', label: 'Log' },
]
const ranges = [
  { seconds: 900, label: '15 min' },
  { seconds: 3600, label: '1 hour' },
  { seconds: 21600, label: '6 hours' },
  { seconds: 86400, label: '24 hours' },
]
// past this difference with the clock of this computer, authenticator codes start to fail
const skewLimit = 30

const card = 'rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900'
const th = 'px-4 py-2.5 font-semibold whitespace-nowrap'

const route = useRoute()
const router = useRouter()
// the tab open, in the address: a link or a reload keeps it
const tab = ref<Tab>(tabs.some((entry) => entry.id === route.query.tab) ? (route.query.tab as Tab) : 'overview')
const tabButtons = ref<HTMLButtonElement[]>([])
const range = ref(3600)
const snapshot = ref<SystemSnapshot | null>(null)
const points = ref<SystemPoint[]>([])
const step = ref(5)
const memoryTotal = ref(0)
const servers = ref<Server[]>([])
const log = ref<LogEntry[]>([])
const logAll = ref(false)
const error = ref('')
const historyError = ref('')
// the clock of the server less the one of this computer, in seconds
const skew = ref(0)
const chosen = ref('')

async function loadSnapshot() {
  const asked = Date.now()
  try {
    const result = await api.system()
    skew.value = Math.round(result.at - (asked + Date.now()) / 2000)
    snapshot.value = result
    error.value = ''
  } catch (err) {
    error.value = errorMessage(err)
  }
}

// a change of the range drops the answers asked before it
let generation = 0
async function loadHistory(full: boolean) {
  const mine = full ? ++generation : generation
  const last = points.value[points.value.length - 1]?.at ?? 0
  try {
    const result = await api.systemHistory(range.value, full ? 0 : last)
    if (mine !== generation) {
      return
    }
    step.value = result.step
    memoryTotal.value = result.memory_total
    if (full) {
      points.value = result.points
    } else {
      const newest = points.value[points.value.length - 1]?.at ?? 0
      const from = (result.points[result.points.length - 1]?.at ?? newest) - range.value
      points.value = [...points.value, ...result.points.filter((point) => point.at > newest)].filter((point) => point.at > from)
    }
    historyError.value = ''
  } catch (err) {
    historyError.value = errorMessage(err)
  }
}

async function loadLog() {
  try {
    log.value = await api.systemLog(logAll.value)
  } catch {
    // the snapshot says when the server doesn't answer
  }
}

let timer: number | undefined
let ticks = 0
function tick() {
  if (document.hidden) {
    return
  }
  ticks++
  loadSnapshot()
  // the points of a minute come every minute; a tab opened again gets the ones it missed
  if (tab.value === 'history' && (range.value <= 3600 || ticks % 12 === 0)) {
    loadHistory(false)
  }
  if (tab.value === 'log' && ticks % 3 === 0) {
    loadLog()
  }
}

watch(tab, (now) => {
  router.replace({ query: { ...route.query, tab: now === 'overview' ? undefined : now } })
  if (now === 'history') {
    loadHistory(false)
  } else if (now === 'log') {
    loadLog()
  }
})

// the arrows, Home and End move between the tabs, as in the tabs of the systems
function onTabKey(event: KeyboardEvent, index: number) {
  const moves: Record<string, number> = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 }
  if (!(event.key in moves)) {
    return
  }
  event.preventDefault()
  const next = (moves[event.key] + tabs.length) % tabs.length
  tab.value = tabs[next].id
  nextTick(() => tabButtons.value[next]?.focus())
}

// a dot on a tab with something wrong in it
const tabAlert = computed<Partial<Record<Tab, 'red' | 'amber'>>>(() => {
  const alerts: Partial<Record<Tab, 'red' | 'amber'>> = {}
  if (problems.value.errors || problems.value.warnings) {
    alerts.overview = problems.value.errors ? 'red' : 'amber'
  }
  const logCheck = checks.value.find((check) => check.id === 'log')
  if (logCheck && (logCheck.status === 'error' || logCheck.status === 'warning')) {
    alerts.log = logCheck.status === 'error' ? 'red' : 'amber'
  }
  return alerts
})

onMounted(async () => {
  loadSnapshot()
  loadHistory(true)
  loadLog()
  try {
    servers.value = await api.servers()
  } catch {
    // the interfaces show without the names of their servers
  }
  timer = window.setInterval(tick, 5000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(range, () => {
  points.value = []
  loadHistory(true)
})
watch(logAll, loadLog)

const serverOf = computed(() => {
  const names: Record<string, string> = {}
  for (const server of servers.value) {
    names[server.interface] = server.name
  }
  return names
})

function interfaceLabel(name: string): string {
  return serverOf.value[name] ? `${name} · ${serverOf.value[name]}` : name
}

const kindLabels: Record<SystemInterface['kind'], string> = {
  ethernet: 'Ethernet',
  wireguard: 'WireGuard',
  loopback: 'Loopback',
  other: 'Other',
}

// the checks, with the clock of this computer: the server can't see it
const skewText = computed(() => {
  const seconds = Math.abs(skew.value)
  if (seconds < 2) {
    return 'The clock of the server and the one of this computer agree.'
  }
  return `The clock of the server is ${seconds} s ${skew.value > 0 ? 'ahead of' : 'behind'} the one of this computer.`
})

const checks = computed<SystemCheck[]>(() => {
  const list = snapshot.value?.checks ?? []
  if (Math.abs(skew.value) <= skewLimit) {
    return list
  }
  return list.map((check) =>
    check.id === 'clock'
      ? {
          ...check,
          status: 'warning',
          title: 'The clock of the server is off',
          detail: `${skewText.value} Authenticator codes fail past ${skewLimit} seconds: check the time service of the host, or of this computer.`,
        }
      : check,
  )
})

const problems = computed(() => ({
  errors: checks.value.filter((check) => check.status === 'error').length,
  warnings: checks.value.filter((check) => check.status === 'warning').length,
}))

const checkLook: Record<CheckStatus, { icon: IconName; color: string; label: string }> = {
  ok: { icon: 'check-circle', color: 'text-emerald-600 dark:text-emerald-400', label: 'OK' },
  warning: { icon: 'alert', color: 'text-amber-600 dark:text-amber-400', label: 'Warning' },
  error: { icon: 'x-circle', color: 'text-rose-600 dark:text-rose-400', label: 'Error' },
  unknown: { icon: 'help', color: 'text-slate-400 dark:text-slate-500', label: 'Unknown' },
}

// the history
const end = computed(() => snapshot.value?.at ?? points.value[points.value.length - 1]?.at ?? Math.floor(Date.now() / 1000))
const start = computed(() => end.value - range.value)
const times = computed(() => points.value.map((point) => point.at))
const cpuSeries = computed(() => [
  { name: 'In use', values: points.value.map((point) => point.cpu) },
  { name: 'Authway Server', values: points.value.map((point) => point.own_cpu) },
])
const memorySeries = computed(() => [
  { name: 'In use', values: points.value.map((point) => point.memory) },
  { name: 'Authway Server', values: points.value.map((point) => point.own_memory) },
])

// the interfaces of the network chart: the ones of the history, the Ethernet first
const chartInterfaces = computed(() => {
  const names = new Set<string>()
  for (const point of points.value) {
    for (const name of Object.keys(point.network)) {
      names.add(name)
    }
  }
  const order = (name: string) => (name.startsWith('eth') || name.startsWith('en') ? 0 : name.startsWith('wg') ? 1 : 2)
  return [...names].sort((a, b) => order(a) - order(b) || a.localeCompare(b, undefined, { numeric: true }))
})
watch(chartInterfaces, (names) => {
  if (!names.includes(chosen.value)) {
    chosen.value = names[0] ?? ''
  }
})
const networkSeries = computed(() => [
  { name: 'Received', values: points.value.map((point) => point.network[chosen.value]?.[0] ?? 0) },
  { name: 'Sent', values: points.value.map((point) => point.network[chosen.value]?.[1] ?? 0) },
])

// the tiles
const host = computed(() => snapshot.value?.host)
const own = computed(() => snapshot.value?.authway)
const dataDisk = computed(() => snapshot.value?.disks.find((disk) => disk.name === 'data') ?? snapshot.value?.disks[0])
const memoryUsed = computed(() => (host.value ? host.value.memory_total - host.value.memory_available : 0))
const uplink = computed(
  () => snapshot.value?.interfaces.find((iface) => iface.kind === 'ethernet') ?? snapshot.value?.interfaces.find((iface) => iface.kind !== 'loopback'),
)

function share(part: number, whole: number): number {
  return whole ? (part / whole) * 100 : 0
}

function diskShare(disk: SystemDisk): number {
  return share(disk.used, disk.used + disk.available)
}

// the fill of a meter: the accent, then amber and red as it fills
function meterColor(percent: number): string {
  if (percent >= 95) {
    return 'bg-rose-500'
  }
  return percent >= 90 ? 'bg-amber-500' : 'bg-sky-600 dark:bg-sky-400'
}

function count(value: number): string {
  return value.toLocaleString()
}

const clockNow = computed(() =>
  snapshot.value ? new Date(snapshot.value.at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '',
)

const levelTone: Record<LogEntry['level'], 'red' | 'amber' | 'gray'> = { error: 'red', warn: 'amber', info: 'gray', debug: 'gray' }
const levelLabel: Record<LogEntry['level'], string> = { error: 'Error', warn: 'Warning', info: 'Info', debug: 'Debug' }

function logTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

// IPv6 in the container, for the tunnels: the addresses, the forwarding, the route out
const ipv6Text = computed(() => {
  const s = snapshot.value
  if (!s || s.ipv6_on === null) {
    return 'Unknown'
  }
  if (!s.ipv6_on) {
    return 'Off'
  }
  const forward = s.ipv6_forward === null ? 'forwarding unknown' : s.ipv6_forward ? 'forwarding on' : 'forwarding off'
  const route = s.ipv6_route === null ? '' : s.ipv6_route ? ', route out' : ', no route out'
  return `On, ${forward}${route}`
})

// the certificate of the web UI, in a row of the card of Authway Server
const certificateText = computed(() => {
  const certificate = snapshot.value?.certificate
  if (!certificate) {
    return 'None: HTTPS is off'
  }
  const until = new Date(certificate.not_after * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' })
  return certificate.self_signed ? `Self-signed, until ${until}` : `${certificate.names[0] ?? 'Yours'}, until ${until}`
})
</script>

<template>
  <div class="mx-auto max-w-7xl">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">System</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          The resources of the host and of Authway Server, the network interfaces and the disks, read every 5 seconds,
          and the checks of what goes wrong most.
        </p>
      </div>
      <p v-if="snapshot" class="text-xs text-slate-500 tabular-nums dark:text-slate-400">Read at {{ clockNow }}</p>
    </div>

    <UiNotice v-if="error" tone="error" class="mt-6">{{ error }}</UiNotice>
    <UiNotice v-if="snapshot?.simulated" class="mt-6" title="Made-up values">
      This server doesn't run on Linux: the resources, the interfaces and the disks are invented, to try the page.
    </UiNotice>

    <div class="mt-6 border-b border-slate-200 dark:border-slate-800">
      <div class="-mb-px flex gap-6 overflow-x-auto" role="tablist" aria-label="System">
        <button
          v-for="(entry, index) in tabs"
          :id="`system-tab-${entry.id}`"
          :key="entry.id"
          ref="tabButtons"
          type="button"
          role="tab"
          :aria-selected="tab === entry.id"
          :aria-controls="`system-panel-${entry.id}`"
          :tabindex="tab === entry.id ? 0 : -1"
          class="flex items-center gap-2 border-b-2 px-1 pb-3 text-sm font-medium whitespace-nowrap"
          :class="
            tab === entry.id
              ? 'border-sky-700 text-sky-800 dark:border-sky-400 dark:text-sky-300'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          "
          @click="tab = entry.id"
          @keydown="onTabKey($event, index)"
        >
          {{ entry.label }}
          <span
            v-if="tabAlert[entry.id]"
            class="h-2 w-2 rounded-full"
            :class="tabAlert[entry.id] === 'red' ? 'bg-rose-500' : 'bg-amber-500'"
            :title="tabAlert[entry.id] === 'red' ? 'An error' : 'A warning'"
          />
        </button>
      </div>
    </div>

    <div v-if="tab === 'overview'" id="system-panel-overview" role="tabpanel" aria-labelledby="system-tab-overview">
      <!-- the checks -->
      <section :class="[card, 'mt-6']" aria-labelledby="checks-title">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h2 id="checks-title" class="font-semibold">Checks</h2>
          <template v-if="snapshot">
            <UiBadge v-if="problems.errors" tone="red" dot>
              {{ problems.errors === 1 ? '1 error' : `${problems.errors} errors` }}{{
                problems.warnings ? `, ${problems.warnings === 1 ? '1 warning' : `${problems.warnings} warnings`}` : ''
              }}
            </UiBadge>
            <UiBadge v-else-if="problems.warnings" tone="amber" dot>
              {{ problems.warnings === 1 ? '1 warning' : `${problems.warnings} warnings` }}
            </UiBadge>
            <UiBadge v-else tone="green" dot>All good</UiBadge>
          </template>
        </div>
        <ul v-if="snapshot" class="divide-y divide-slate-100 dark:divide-slate-800">
          <li v-for="check in checks" :key="check.id" class="flex gap-3 px-5 py-3">
            <span :class="['mt-0.5 shrink-0', checkLook[check.status].color]">
              <AppIcon :name="checkLook[check.status].icon" />
            </span>
            <div class="min-w-0 text-sm">
              <p class="font-medium text-slate-900 dark:text-slate-100">
                <span class="sr-only">{{ checkLook[check.status].label }}: </span>{{ check.title }}
              </p>
              <p v-if="check.detail" class="mt-0.5 break-words text-slate-600 dark:text-slate-400">{{ check.detail }}</p>
              <p v-if="check.id === 'clock' && Math.abs(skew) <= skewLimit" class="mt-0.5 text-slate-600 dark:text-slate-400">
                {{ skewText }}
              </p>
              <button
                v-if="check.id === 'log' && check.status !== 'ok'"
                type="button"
                class="mt-1 inline-block font-medium text-sky-700 hover:underline dark:text-sky-400"
                @click="tab = 'log'"
              >
                See the log
              </button>
            </div>
          </li>
        </ul>
        <p v-else class="px-5 py-6 text-sm text-slate-500">Reading…</p>
      </section>

      <!-- the tiles -->
      <div v-if="host && own" class="mt-6 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <div :class="[card, 'p-4']">
          <p class="text-sm text-slate-500 dark:text-slate-400">Processors</p>
          <p class="mt-1 text-2xl font-semibold">{{ formatPercent(host.cpu) }}</p>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {{ host.processors === 1 ? '1 processor' : `${host.processors} processors` }} · load {{ host.load[0].toFixed(2) }}
          </p>
          <p class="text-xs text-slate-500 dark:text-slate-400">Authway Server {{ formatPercent(own.cpu) }}</p>
        </div>
        <div :class="[card, 'p-4']">
          <p class="text-sm text-slate-500 dark:text-slate-400">Memory</p>
          <p class="mt-1 text-2xl font-semibold">{{ formatPercent(share(memoryUsed, host.memory_total)) }}</p>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">{{ formatBytes(memoryUsed) }} of {{ formatBytes(host.memory_total) }} in use</p>
          <p class="text-xs text-slate-500 dark:text-slate-400">Authway Server {{ formatBytes(own.memory) }}</p>
        </div>
        <div v-if="dataDisk" :class="[card, 'p-4']">
          <p class="text-sm text-slate-500 dark:text-slate-400">Disk of the data</p>
          <p class="mt-1 text-2xl font-semibold">{{ formatPercent(diskShare(dataDisk)) }}</p>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">{{ formatBytes(dataDisk.used) }} of {{ formatBytes(dataDisk.total) }} in use</p>
          <p class="text-xs text-slate-500 dark:text-slate-400">{{ formatBytes(dataDisk.available) }} available</p>
        </div>
        <div v-if="uplink" :class="[card, 'p-4']">
          <p class="text-sm text-slate-500 dark:text-slate-400">Network, {{ uplink.name }}</p>
          <p class="mt-1 text-2xl font-semibold">{{ formatRate(uplink.received + uplink.sent) }}</p>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">{{ formatRate(uplink.received) }} received</p>
          <p class="text-xs text-slate-500 dark:text-slate-400">{{ formatRate(uplink.sent) }} sent</p>
        </div>
        <div :class="[card, 'p-4']">
          <p class="text-sm text-slate-500 dark:text-slate-400">Up for</p>
          <p class="mt-1 text-2xl font-semibold">{{ uptime(host.uptime) }}</p>
          <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">the host</p>
          <p class="text-xs text-slate-500 dark:text-slate-400">Authway Server {{ uptime((snapshot?.at ?? 0) - own.started) }}</p>
        </div>
      </div>
    </div>

    <!-- the history -->
    <section
      v-else-if="tab === 'history'"
      id="system-panel-history"
      class="mt-6"
      role="tabpanel"
      aria-labelledby="system-tab-history"
    >
      <div class="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 class="font-semibold">History</h2>
          <p class="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
            Kept in memory: it starts again when Authway Server restarts. Past an hour, the points are averages of a minute.
          </p>
        </div>
        <div class="inline-flex rounded-md border border-slate-300 bg-white p-0.5 shadow-sm dark:border-slate-600 dark:bg-slate-800" role="group" aria-label="Time range">
          <button
            v-for="entry in ranges"
            :key="entry.seconds"
            type="button"
            class="rounded px-3 py-1.5 text-sm font-medium whitespace-nowrap"
            :class="
              range === entry.seconds
                ? 'bg-sky-700 text-white dark:bg-sky-500 dark:text-slate-950'
                : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700'
            "
            :aria-pressed="range === entry.seconds"
            @click="range = entry.seconds"
          >
            {{ entry.label }}
          </button>
        </div>
      </div>
      <UiNotice v-if="historyError" tone="error" class="mt-4">{{ historyError }}</UiNotice>

      <div class="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div :class="[card, 'p-5']">
          <h3 class="text-sm font-semibold">Processors</h3>
          <p class="mb-3 text-xs text-slate-500 dark:text-slate-400">Share of all the processors of the host</p>
          <LineChart label="Processors" :times="times" :series="cpuSeries" :start="start" :end="end" :step="step" unit="percent" />
        </div>
        <div :class="[card, 'p-5']">
          <h3 class="text-sm font-semibold">Memory</h3>
          <p class="mb-3 text-xs text-slate-500 dark:text-slate-400">
            Of the {{ formatBytes(memoryTotal) }} of the host, without the files the kernel keeps in memory
          </p>
          <LineChart
            label="Memory"
            :times="times"
            :series="memorySeries"
            :start="start"
            :end="end"
            :step="step"
            unit="bytes"
            :max="memoryTotal || undefined"
          />
        </div>
        <div :class="[card, 'p-5 lg:col-span-2']">
          <div class="mb-3 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h3 class="text-sm font-semibold">Network</h3>
              <p class="text-xs text-slate-500 dark:text-slate-400">
                The traffic of an interface of the container. eth0 carries the tunnels and the web UI; a WireGuard
                interface, the traffic of the peers inside their tunnels.
              </p>
            </div>
            <label v-if="chartInterfaces.length" class="block">
              <span class="mb-1 block text-xs font-medium text-slate-500 dark:text-slate-400">Interface</span>
              <select
                v-model="chosen"
                class="block rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900"
              >
                <option v-for="name in chartInterfaces" :key="name" :value="name">{{ interfaceLabel(name) }}</option>
              </select>
            </label>
          </div>
          <LineChart
            :label="`Network, ${interfaceLabel(chosen)}`"
            :times="times"
            :series="networkSeries"
            :start="start"
            :end="end"
            :step="step"
            unit="rate"
          />
        </div>
      </div>
    </section>

    <!-- the interfaces -->
    <section
      v-else-if="tab === 'network'"
      id="system-panel-network"
      class="mt-6"
      role="tabpanel"
      aria-labelledby="system-tab-network"
    >
      <h2 class="font-semibold">Network interfaces</h2>
      <p class="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
        The rates of the latest 5 seconds, and the totals since the interface was made.
      </p>
      <p v-if="!snapshot" class="mt-4 text-sm text-slate-500">Reading…</p>
      <div v-else :class="[card, 'mt-4 overflow-x-auto']">
        <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" :class="th">Interface</th>
              <th scope="col" :class="th">State</th>
              <th scope="col" :class="th">Addresses</th>
              <th scope="col" :class="[th, 'text-right']">Received</th>
              <th scope="col" :class="[th, 'text-right']">Sent</th>
              <th scope="col" :class="[th, 'text-right']">Errors · drops</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="iface in snapshot.interfaces" :key="iface.name">
              <td class="px-4 py-3 whitespace-nowrap">
                <span class="font-mono font-medium">{{ iface.name }}</span>
                <p class="text-xs text-slate-500 dark:text-slate-400">
                  {{ kindLabels[iface.kind] }}<template v-if="serverOf[iface.name]"> · {{ serverOf[iface.name] }}</template>
                </p>
              </td>
              <td class="px-4 py-3 whitespace-nowrap">
                <UiBadge :tone="iface.up ? 'green' : 'red'" dot>{{ iface.up ? 'Up' : 'Down' }}</UiBadge>
                <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">MTU {{ iface.mtu }}</p>
              </td>
              <td class="px-4 py-3 font-mono text-xs">
                <p v-for="address in iface.addresses" :key="address">{{ address }}</p>
                <span v-if="!iface.addresses.length" class="text-slate-400">—</span>
              </td>
              <td class="px-4 py-3 text-right whitespace-nowrap tabular-nums">
                {{ formatRate(iface.received) }}
                <p class="text-xs text-slate-500 dark:text-slate-400">
                  {{ formatBytes(iface.received_bytes) }} · {{ count(iface.received_packets) }} packets
                </p>
              </td>
              <td class="px-4 py-3 text-right whitespace-nowrap tabular-nums">
                {{ formatRate(iface.sent) }}
                <p class="text-xs text-slate-500 dark:text-slate-400">{{ formatBytes(iface.sent_bytes) }} · {{ count(iface.sent_packets) }} packets</p>
              </td>
              <td class="px-4 py-3 text-right whitespace-nowrap tabular-nums">{{ count(iface.errors) }} · {{ count(iface.drops) }}</td>
            </tr>
            <tr v-if="!snapshot.interfaces.length">
              <td colspan="6" class="px-4 py-6 text-center text-slate-500">Can't read the interfaces.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- the disks, the host, Authway Server -->
    <div
      v-else-if="tab === 'host'"
      id="system-panel-host"
      class="mt-6"
      role="tabpanel"
      aria-labelledby="system-tab-host"
    >
      <p v-if="!(snapshot && host && own)" class="text-sm text-slate-500">Reading…</p>
      <div v-else class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <section :class="[card, 'p-5']" aria-labelledby="disks-title">
          <h2 id="disks-title" class="font-semibold">Disks</h2>
          <div v-for="disk in snapshot.disks" :key="disk.name" class="mt-4">
            <div class="flex items-baseline justify-between gap-3 text-sm">
              <p class="font-medium">
                {{ disk.name === 'data' ? 'Data folder' : 'System of the container' }}
                <span class="ml-1 font-mono text-xs font-normal text-slate-500">{{ disk.path }}</span>
              </p>
              <p class="tabular-nums">{{ formatPercent(diskShare(disk)) }}</p>
            </div>
            <div
              class="mt-2 h-2 overflow-hidden rounded-full bg-sky-100 dark:bg-sky-950"
              role="meter"
              :aria-valuenow="Math.round(diskShare(disk))"
              aria-valuemin="0"
              aria-valuemax="100"
              :aria-label="`${disk.name === 'data' ? 'Data folder' : 'System of the container'} in use`"
            >
              <div class="h-full rounded-full" :class="meterColor(diskShare(disk))" :style="{ width: `${Math.min(100, diskShare(disk))}%` }" />
            </div>
            <p class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {{ formatBytes(disk.used) }} of {{ formatBytes(disk.total) }} in use, {{ formatBytes(disk.available) }} available.
              <template v-if="disk.inodes">{{ count(disk.inodes_free) }} more files can be created.</template>
            </p>
          </div>
          <p v-if="!snapshot.disks.length" class="mt-3 text-sm text-slate-500">Can't read the disks.</p>
          <dl class="mt-5 space-y-1.5 border-t border-slate-100 pt-4 text-sm dark:border-slate-800">
            <div class="flex justify-between gap-3">
              <dt class="text-slate-500 dark:text-slate-400">Database</dt>
              <dd class="tabular-nums">{{ formatBytes(snapshot.database.size) }}</dd>
            </div>
            <div class="flex justify-between gap-3">
              <dt class="text-slate-500 dark:text-slate-400">Changes not yet in it (WAL)</dt>
              <dd class="tabular-nums">{{ formatBytes(snapshot.database.log) }}</dd>
            </div>
          </dl>
        </section>

        <section :class="[card, 'p-5']" aria-labelledby="host-title">
          <h2 id="host-title" class="font-semibold">Host</h2>
          <dl class="mt-3 space-y-1.5 text-sm">
            <div v-for="row in [
              ['Name', host.hostname || '—'],
              ['Kernel', host.kernel || '—'],
              ['System', (host.os || '—') + (host.container ? ', in a container' : '')],
              ['Time zone', host.timezone],
              ['Load', `${host.load.map((value) => value.toFixed(2)).join(' · ')} (1, 5, 15 min)`],
              ['Waiting for the disks', formatPercent(host.iowait)],
              ['Swap', host.swap_total ? `${formatBytes(host.swap_total - host.swap_free)} of ${formatBytes(host.swap_total)} in use` : 'None'],
              ['IP forwarding', snapshot.ip_forward === null ? 'Unknown' : snapshot.ip_forward ? 'On' : 'Off'],
              ['IPv6', ipv6Text],
              ['Connection tracking', snapshot.conntrack.max ? `${count(snapshot.conntrack.count)} of ${count(snapshot.conntrack.max)}` : 'Unknown'],
            ]" :key="row[0]" class="flex justify-between gap-3">
              <dt class="shrink-0 text-slate-500 dark:text-slate-400">{{ row[0] }}</dt>
              <dd class="min-w-0 text-right break-words">{{ row[1] }}</dd>
            </div>
          </dl>
        </section>

        <section :class="[card, 'p-5']" aria-labelledby="own-title">
          <h2 id="own-title" class="font-semibold">Authway Server</h2>
          <dl class="mt-3 space-y-1.5 text-sm">
            <div v-for="row in [
              ['Version', own.version],
              ['Started', dateTime(own.started)],
              ['Processors', formatPercent(own.cpu)],
              ['Memory', own.memory_limit ? `${formatBytes(own.memory)} of ${formatBytes(own.memory_limit)}` : `${formatBytes(own.memory)}, no limit`],
              ['Memory of Go', formatBytes(own.heap)],
              ['Goroutines', count(own.goroutines)],
              ['Open files', own.max_files ? `${count(own.open_files)} of ${count(own.max_files)}` : count(own.open_files)],
              ['Built with', `${own.go_version}, ${own.platform}`],
              ['Certificate', certificateText],
            ]" :key="row[0]" class="flex justify-between gap-3">
              <dt class="shrink-0 text-slate-500 dark:text-slate-400">{{ row[0] }}</dt>
              <dd class="min-w-0 text-right break-words">{{ row[1] }}</dd>
            </div>
          </dl>
        </section>
      </div>
    </div>

    <!-- the log -->
    <section
      v-else-if="tab === 'log'"
      id="system-panel-log"
      :class="[card, 'mt-6']"
      role="tabpanel"
      aria-labelledby="system-tab-log"
    >
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
        <h2 class="font-semibold">Recent log</h2>
        <div class="flex items-center gap-2">
          <div class="inline-flex rounded-md border border-slate-300 bg-white p-0.5 dark:border-slate-600 dark:bg-slate-800" role="group" aria-label="Lines">
            <button
              v-for="entry in [
                { all: false, label: 'Warnings and errors' },
                { all: true, label: 'Everything' },
              ]"
              :key="entry.label"
              type="button"
              class="rounded px-2.5 py-1 text-sm font-medium whitespace-nowrap"
              :class="
                logAll === entry.all
                  ? 'bg-sky-700 text-white dark:bg-sky-500 dark:text-slate-950'
                  : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700'
              "
              :aria-pressed="logAll === entry.all"
              @click="logAll = entry.all"
            >
              {{ entry.label }}
            </button>
          </div>
          <UiButton size="sm" icon="refresh" @click="loadLog">Refresh</UiButton>
        </div>
      </div>
      <ol class="max-h-[32rem] divide-y divide-slate-100 overflow-y-auto dark:divide-slate-800">
        <li v-for="(entry, index) in log" :key="`${entry.at}-${index}`" class="px-5 py-2.5 text-sm">
          <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
            <UiBadge :tone="levelTone[entry.level]">{{ levelLabel[entry.level] }}</UiBadge>
            <span class="text-xs text-slate-500 tabular-nums dark:text-slate-400">{{ logTime(entry.at) }}</span>
          </div>
          <p class="mt-1 break-words text-slate-900 dark:text-slate-100">{{ entry.message }}</p>
          <p v-if="entry.attrs" class="mt-0.5 font-mono text-xs break-all text-slate-500 dark:text-slate-400">{{ entry.attrs }}</p>
        </li>
        <li v-if="!log.length" class="px-5 py-6 text-center text-sm text-slate-500">
          {{ logAll ? 'Nothing logged yet.' : 'No warning and no error since Authway Server started.' }}
        </li>
      </ol>
      <p class="border-t border-slate-200 px-5 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        The latest 500 lines and the latest 200 warnings and errors, since Authway Server started. The whole log is the
        one of the container: <code class="font-mono">docker compose logs authway-server</code>
      </p>
    </section>
  </div>
</template>
