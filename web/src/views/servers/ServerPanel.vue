<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { api, type Peer, type Route, type Server, type User } from '../../api'
import AppIcon from '../../components/AppIcon.vue'
import UiBadge from '../../components/UiBadge.vue'
import UiButton from '../../components/UiButton.vue'
import UiEmpty from '../../components/UiEmpty.vue'
import UiMenu, { type MenuItem } from '../../components/UiMenu.vue'
import UiNotice from '../../components/UiNotice.vue'
import { ago, authModeLabel, dateTime, duration, errorMessage, formatBytes, lockModeLabel } from '../../format'
import { canManage, confirm, isAdmin, notify } from '../../state'
import PeerAlertsModal from './PeerAlertsModal.vue'
import PeerConfigModal from './PeerConfigModal.vue'
import PeerDrawer from './PeerDrawer.vue'
import RoutingHelpModal from './RoutingHelpModal.vue'

// servers: all of them, for the names of the ones the peers reach
const props = defineProps<{ server: Server; servers: Server[] }>()
const emit = defineEmits<{ edit: [Server]; deleted: []; changed: [] }>()

const peers = ref<Peer[]>([])
const users = ref<User[]>([])
const loaded = ref(false)
const search = ref('')
const drawerOpen = ref(false)
const editing = ref<Peer | null>(null)
const configPeer = ref<Peer | null>(null)
const alertsPeer = ref<Peer | null>(null)
const routingHelp = ref(false)

const gated = computed(() => props.server.auth_mode !== 'key')
const bound = computed(() => gated.value && props.server.device_binding)
// what the peers reach besides the networks: each other, the peers of other servers
const traffic = computed(() => {
  const names = props.server.reachable_servers
    .map((id) => props.servers.find((server) => server.id === id)?.name)
    .filter((name): name is string => !!name)
  const parts: string[] = []
  if (props.server.client_to_client) {
    parts.push('Between its peers')
  }
  if (names.length) {
    parts.push(`To the peers of ${names.join(', ')}`)
  }
  return parts.join(' · ') || 'None'
})
// a routed server on a network of the container that can't route: the System page tells more
const routingProblem = computed(() => {
  const drivers = (props.server.routes ?? []).map((route) => route.driver)
  if (drivers.includes('ipvlan')) {
    return "The container is on an ipvlan network, which can't route the tunnels. See the System page."
  }
  return ''
})
// the next hop on the router: the Docker host when the container is on its bridge
function routerHop(route: Route): string {
  if (route.host) {
    return route.host.state === 'routed' && route.host.address ? route.host.address : 'the address of the Docker host'
  }
  return route.via || 'the container'
}
// what the helper of the Docker host says of a route, amber when the networks get no answer
function hostNote(route: Route): { text: string; warning: boolean } | null {
  const host = route.host
  switch (host?.state) {
    case 'routed':
      if (host.error) {
        return { text: capitalize(host.error) + '.', warning: true }
      }
      if (host.previous) {
        return {
          text: `The address of the Docker host changed: the router still has the route via ${host.previous}. Change it, then say it's done at the top of the page.`,
          warning: true,
        }
      }
      return null
    case 'off':
      return { text: "The Docker host doesn't send it on to the container: add compose.host-routes.yaml. See the System page.", warning: true }
    case 'stopped':
      return { text: "The helper of compose.host-routes.yaml isn't running. See the System page.", warning: true }
    case 'pending':
      return { text: 'The Docker host is adding the route…', warning: false }
    case 'failed':
      return { text: `The Docker host can't route it: ${host.error}.`, warning: true }
  }
  return null
}
function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1)
}
// what a peer reaches when it's not just the networks of the server: all its traffic, only some of them
function peerNotes(peer: Peer): string[] {
  const notes: string[] = []
  if (peer.route_all) {
    notes.push('all traffic')
  }
  if (peer.access.length === 1) {
    notes.push(`only ${peer.access[0]}`)
  } else if (peer.access.length > 1) {
    notes.push(`only ${peer.access.length} networks`)
  }
  return notes
}
function accessTitle(peer: Peer): string | undefined {
  return peer.access.length ? `Reaches only ${peer.access.join(', ')}` : undefined
}
// the servers whose peers reach the peers of this one
const reachedBy = computed(() =>
  props.servers.filter((server) => server.reachable_servers.includes(props.server.id)).map((server) => server.name),
)
const endpoint = computed(() => {
  const port = props.server.public_port || props.server.listen_port
  return props.server.public_host.includes(':') ? `[${props.server.public_host}]:${port}` : `${props.server.public_host}:${port}`
})
// with a login, a peer without a user can't log in: a server that had none keeps its peers without one
const withoutUser = computed(() => (gated.value ? peers.value.filter((peer) => !peer.user_id).length : 0))
const filtered = computed(() => {
  const text = search.value.trim().toLowerCase()
  if (!text) {
    return peers.value
  }
  return peers.value.filter((peer) =>
    [peer.name, gated.value ? peer.username : '', peer.address, peer.address6, peer.endpoint].some((value) =>
      value.toLowerCase().includes(text),
    ),
  )
})

async function loadPeers() {
  try {
    peers.value = await api.peers(props.server.id)
  } catch (e) {
    if (!loaded.value) {
      notify(errorMessage(e), 'error')
    }
  } finally {
    loaded.value = true
  }
}

async function loadUsers() {
  try {
    users.value = await api.users()
  } catch {
    users.value = []
  }
}

let timer: number | undefined
onMounted(() => {
  loadPeers()
  loadUsers()
  // the state of the peers changes on its own: handshakes, logins
  timer = window.setInterval(loadPeers, 10000)
})
onBeforeUnmount(() => clearInterval(timer))

function addPeer() {
  editing.value = null
  loadUsers()
  drawerOpen.value = true
}

function editPeer(peer: Peer) {
  editing.value = peer
  loadUsers()
  drawerOpen.value = true
}

async function peerSaved(peer: Peer, created: boolean) {
  drawerOpen.value = false
  await loadPeers()
  emit('changed')
  if (created) {
    configPeer.value = peer
  }
}

async function run(action: () => Promise<unknown>, done: string) {
  try {
    await action()
    notify(done)
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
  await loadPeers()
  emit('changed')
}

async function deleteServer() {
  const ok = await confirm(
    `Delete ${props.server.name}?`,
    `Its ${props.server.peers} peers are deleted too, and their configuration files stop working. This can't be undone.`,
    'Delete server',
  )
  if (!ok) {
    return
  }
  try {
    await api.deleteServer(props.server.id)
    notify(`${props.server.name} deleted.`)
    emit('deleted')
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
}

function peerMenu(peer: Peer): MenuItem[] {
  const items: MenuItem[] = [
    { label: 'Configuration', icon: 'qr', action: () => (configPeer.value = peer) },
    { label: 'Edit', icon: 'edit', action: () => editPeer(peer) },
  ]
  if (peer.alerts || peer.blocked) {
    items.push({ label: `Alerts (${peer.alerts})`, icon: 'alert', action: () => (alertsPeer.value = peer) })
  }
  if (peer.session) {
    items.push({
      label: 'Log out',
      icon: 'logout',
      action: () => run(() => api.logoutPeer(peer.id), `${peer.name} is logged out.`),
    })
  }
  if (bound.value && peer.device) {
    items.push({
      label: peer.device.state === 'enrolled' ? 'Replace the device' : 'Allow a device',
      icon: 'device',
      action: async () => {
        const ok = await confirm(
          `Let a new device enroll for ${peer.name}?`,
          (peer.device?.state === 'enrolled'
            ? `${peer.device.name || 'The device enrolled'} is forgotten and the session ends. `
            : '') +
            'The next device that logs in with the configuration file and the password of the user is enrolled. Do it after a reinstall or for a new computer.',
          'Allow a new device',
          false,
        )
        if (ok) {
          await run(() => api.allowDevice(peer.id), `A new device can enroll for ${peer.name}.`)
        }
      },
    })
    if (peer.device.state !== 'closed') {
      items.push({
        label: 'Revoke the device',
        icon: 'close',
        danger: true,
        action: async () => {
          const ok = await confirm(
            `Revoke the device of ${peer.name}?`,
            'The session ends and nobody logs in for this peer until you allow a new device.',
            'Revoke',
          )
          if (ok) {
            await run(() => api.revokeDevice(peer.id), `The device of ${peer.name} is revoked.`)
          }
        },
      })
    }
  }
  items.push(
    {
      label: 'New keys',
      icon: 'key',
      action: async () => {
        const ok = await confirm(
          `New keys for ${peer.name}?`,
          'The current configuration file, and every copy of it, stops working. Give the new file to the user.' +
            (bound.value ? ' The device enrolled is forgotten: the one that logs in with the new file is enrolled.' : ''),
          'Make new keys',
        )
        if (ok) {
          await run(() => api.newPeerKeys(peer.id), `${peer.name} has new keys.`)
          configPeer.value = peers.value.find((entry) => entry.id === peer.id) ?? null
        }
      },
    },
    {
      label: 'Delete',
      icon: 'trash',
      danger: true,
      action: async () => {
        const ok = await confirm(`Delete ${peer.name}?`, 'Its configuration file stops working.', 'Delete peer')
        if (ok) {
          await run(() => api.deletePeer(peer.id), `${peer.name} deleted.`)
        }
      },
    },
  )
  return items
}

const serverMenu = computed<MenuItem[]>(() => [
  { label: 'Edit', icon: 'edit', action: () => emit('edit', props.server) },
  { label: 'Delete', icon: 'trash', danger: true, action: deleteServer },
])

// the details of an enrolled device, on hover
function deviceTitle(peer: Peer): string {
  const device = peer.device
  if (!device) {
    return ''
  }
  const lines = [`Enrolled ${dateTime(device.enrolled_at)}`, `Last login ${dateTime(device.last_used_at)} from ${device.last_from || 'an unknown IP'}`]
  if (device.kind && device.kind !== 'software') {
    lines.push(`Key in the ${device.kind === 'tpm' ? 'TPM' : 'Secure Enclave'}`)
  }
  if (props.server.machine_id) {
    lines.push(device.machine_id ? 'Computer recorded' : 'Computer recorded at the next login')
  }
  if (device.wireguard_key === 'device') {
    lines.push(`Own WireGuard key since ${dateTime(device.wireguard_key_at)}`)
  }
  return lines.join('\n')
}

async function copyKey() {
  try {
    await navigator.clipboard.writeText(props.server.public_key)
    notify('Public key copied.')
  } catch {
    notify("The browser doesn't allow copying here.", 'error')
  }
}
</script>

<template>
  <div class="space-y-8">
    <section class="rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div class="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-lg font-semibold">{{ server.name }}</h2>
            <UiBadge :tone="server.enabled ? 'green' : 'gray'" dot>{{ server.enabled ? 'Enabled' : 'Disabled' }}</UiBadge>
            <UiBadge :tone="gated ? 'sky' : 'gray'">
              <AppIcon :name="gated ? 'lock' : 'key'" :size="14" />{{ authModeLabel(server.auth_mode) }}
            </UiBadge>
          </div>
          <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {{ server.connected }} of {{ server.peers }} peers connected<template v-if="gated">
              · {{ server.sessions }} logged in</template
            >
          </p>
        </div>
        <div class="flex items-center gap-2">
          <UiButton v-if="isAdmin()" icon="edit" size="sm" @click="emit('edit', server)">Edit</UiButton>
          <UiMenu v-if="isAdmin()" :items="serverMenu" :label="`Actions of ${server.name}`" />
        </div>
      </div>
      <dl class="grid gap-x-8 gap-y-4 px-5 py-5 text-sm break-words sm:grid-cols-2 xl:grid-cols-4">
        <div>
          <dt class="text-slate-500 dark:text-slate-400">Endpoint of the peers</dt>
          <dd class="mt-0.5 font-mono break-all">{{ endpoint }}</dd>
        </div>
        <div>
          <dt class="text-slate-500 dark:text-slate-400">Tunnel network</dt>
          <dd class="mt-0.5 font-mono">{{ server.network }} <span class="text-slate-500">(server {{ server.address }})</span></dd>
          <dd v-if="server.network6" class="mt-0.5 font-mono break-words">
            {{ server.network6 }} <span class="text-slate-500">(server {{ server.address6 }})</span>
          </dd>
          <dd v-else class="mt-0.5 text-slate-500 dark:text-slate-400">IPv4 only</dd>
        </div>
        <div>
          <dt class="text-slate-500 dark:text-slate-400">Networks the peers reach</dt>
          <dd class="mt-0.5 font-mono">{{ server.networks.length ? server.networks.join(', ') : 'None' }}</dd>
        </div>
        <div>
          <dt class="flex items-center gap-1 text-slate-500 dark:text-slate-400">
            What the networks see
            <button
              type="button"
              class="rounded-full p-0.5 hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-2 focus-visible:outline-sky-600 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="How NAT and routed work"
              title="How NAT and routed work"
              @click="routingHelp = true"
            >
              <AppIcon name="help" :size="16" />
            </button>
          </dt>
          <dd v-if="!server.routed" class="mt-0.5">NAT: the address of the container</dd>
          <template v-else>
            <dd class="mt-0.5">
              Routed: the address of each peer<template v-if="server.inbound"> · the networks start connections</template>
            </dd>
            <template v-for="route in server.routes ?? []" :key="route.tunnel">
              <dd class="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Route on the router:
                <span class="font-mono break-words text-slate-700 dark:text-slate-300">{{ route.tunnel }} via {{ routerHop(route) }}</span>
              </dd>
              <dd v-if="route.host?.state === 'routed'" class="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                The Docker host sends it on to the container, <span class="font-mono">{{ route.via }}</span>
              </dd>
              <dd
                v-if="hostNote(route)"
                class="mt-0.5 text-xs"
                :class="hostNote(route)?.warning ? 'text-amber-700 dark:text-amber-400' : 'text-slate-500 dark:text-slate-400'"
              >
                {{ hostNote(route)?.text }}
              </dd>
            </template>
            <dd v-if="routingProblem" class="mt-1 text-xs text-amber-700 dark:text-amber-400">{{ routingProblem }}</dd>
          </template>
        </div>
        <div>
          <dt class="text-slate-500 dark:text-slate-400">DNS servers</dt>
          <dd class="mt-0.5 font-mono">{{ server.dns.length ? server.dns.join(', ') : 'None' }}</dd>
        </div>
        <div v-if="gated">
          <dt class="text-slate-500 dark:text-slate-400">Login page</dt>
          <dd class="mt-0.5 font-mono">{{ server.login_url }}</dd>
        </div>
        <div v-if="gated">
          <dt class="text-slate-500 dark:text-slate-400">Session length</dt>
          <dd class="mt-0.5">{{ duration(server.session_timeout) }}</dd>
        </div>
        <div v-if="gated">
          <dt class="text-slate-500 dark:text-slate-400">Copied configurations</dt>
          <dd class="mt-0.5">
            Lock {{ lockModeLabel(server.lock_endpoint).toLowerCase() }}<template v-if="server.detect_copies">
              · detected{{ server.block_copies ? ' and blocked' : '' }}</template
            >
          </dd>
        </div>
        <div v-if="gated">
          <dt class="text-slate-500 dark:text-slate-400">Device binding</dt>
          <dd class="mt-0.5">
            <template v-if="bound">Only the enrolled device{{ server.machine_id ? ', on its computer' : '' }}</template>
            <template v-else>Off: any device with the file and the password</template>
          </dd>
        </div>
        <div>
          <dt class="text-slate-500 dark:text-slate-400">Traffic between peers</dt>
          <dd class="mt-0.5">
            {{ traffic }}
            <p v-if="reachedBy.length" class="text-xs text-slate-500 dark:text-slate-400">
              The peers of {{ reachedBy.join(', ') }} reach these peers
            </p>
          </dd>
        </div>
        <div v-if="server.fallback_endpoints.length">
          <dt class="text-slate-500 dark:text-slate-400">Fallback addresses</dt>
          <dd class="mt-0.5 font-mono break-all">{{ server.fallback_endpoints.join(', ') }}</dd>
        </div>
        <div>
          <dt class="text-slate-500 dark:text-slate-400">Interface · listen port</dt>
          <dd class="mt-0.5 font-mono">{{ server.interface }} · {{ server.listen_port }}/udp</dd>
        </div>
        <div class="min-w-0 sm:col-span-2 xl:col-span-1">
          <dt class="text-slate-500 dark:text-slate-400">Public key</dt>
          <dd class="mt-0.5 flex min-w-0 items-center gap-1.5">
            <span class="min-w-0 truncate font-mono" :title="server.public_key">{{ server.public_key }}</span>
            <button
              type="button"
              class="rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:hover:bg-slate-800"
              aria-label="Copy the public key"
              @click="copyKey"
            >
              <AppIcon name="copy" :size="16" />
            </button>
          </dd>
        </div>
      </dl>
    </section>

    <section>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h2 class="text-lg font-semibold">Peers</h2>
        <div class="flex flex-wrap items-center gap-3">
          <input
            v-if="peers.length"
            v-model="search"
            type="search"
            placeholder="Search peers"
            aria-label="Search peers"
            class="w-56 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900"
          />
          <UiButton v-if="canManage()" variant="primary" icon="plus" @click="addPeer">Add peer</UiButton>
        </div>
      </div>

      <UiNotice v-if="withoutUser && canManage()" tone="warning" class="mt-4">
        {{ withoutUser === 1 ? "1 peer has no user, so it can't log in." : `${withoutUser} peers have no user, so they can't log in.` }}
        Choose a user with Edit, in the menu of the peer.
      </UiNotice>
      <UiEmpty
        v-if="loaded && !peers.length"
        class="mt-4"
        icon="users"
        title="No peer yet"
        :text="
          gated
            ? 'Each peer belongs to a user, who logs in before the traffic of the peer passes.'
            : 'Each peer gets a configuration file for the WireGuard apps.'
        "
      />

      <div
        v-else-if="peers.length"
        class="mt-4 relative overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900"
      >
        <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800/50 dark:text-slate-400">
            <tr>
              <th scope="col" class="px-4 py-3">Peer</th>
              <th scope="col" class="px-4 py-3">Address</th>
              <th scope="col" class="px-4 py-3">Status</th>
              <th v-if="bound" scope="col" class="px-4 py-3">Device</th>
              <th scope="col" class="px-4 py-3">Last handshake</th>
              <th scope="col" class="px-4 py-3">Traffic</th>
              <th scope="col" class="px-4 py-3"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr v-for="peer in filtered" :key="peer.id" :class="{ 'opacity-60': !peer.enabled }">
              <td class="px-4 py-3">
                <p class="font-medium">{{ peer.name }}</p>
                <p v-if="gated" class="text-slate-500 dark:text-slate-400" :title="accessTitle(peer)">
                  <span :class="{ 'text-amber-700 dark:text-amber-400': !peer.username }">{{ peer.username || 'No user' }}</span>
                  <span v-for="note in peerNotes(peer)" :key="note" class="ml-1">· {{ note }}</span>
                </p>
                <p v-else-if="peerNotes(peer).length" class="text-slate-500 dark:text-slate-400" :title="accessTitle(peer)">
                  {{ capitalize(peerNotes(peer).join(' · ')) }}
                </p>
              </td>
              <td class="px-4 py-3 font-mono whitespace-nowrap">
                {{ peer.address }}
                <p v-if="peer.address6" class="text-xs text-slate-500 dark:text-slate-400">{{ peer.address6 }}</p>
              </td>
              <td class="px-4 py-3">
                <div class="flex flex-wrap gap-1.5">
                  <UiBadge v-if="!peer.enabled" tone="gray">Disabled</UiBadge>
                  <UiBadge v-else :tone="peer.connected ? 'green' : 'gray'" dot>
                    {{ peer.connected ? 'Connected' : 'Offline' }}
                  </UiBadge>
                  <template v-if="gated && peer.enabled">
                    <UiBadge v-if="peer.blocked" tone="red">Blocked</UiBadge>
                    <UiBadge
                      v-else-if="peer.session?.paused_at"
                      tone="amber"
                      :title="`Logged in from ${peer.session.endpoint}, now sending from another IP`"
                    >
                      Paused
                    </UiBadge>
                    <UiBadge v-else-if="peer.session" tone="sky" :title="`Until ${dateTime(peer.session.expires_at)}`">
                      Logged in
                    </UiBadge>
                    <UiBadge v-else-if="peer.connected" tone="amber">Waiting for login</UiBadge>
                  </template>
                  <button v-if="peer.alerts" type="button" class="rounded-full" @click="alertsPeer = peer">
                    <UiBadge tone="red"><AppIcon name="alert" :size="13" />{{ peer.alerts }}</UiBadge>
                  </button>
                </div>
              </td>
              <td v-if="bound" class="px-4 py-3">
                <template v-if="peer.device?.state === 'enrolled'">
                  <p class="flex items-center gap-1.5 font-medium" :title="deviceTitle(peer)">
                    <AppIcon name="device" :size="15" class="shrink-0 text-slate-500" />
                    <span class="truncate">{{ peer.device.name || 'Device without a name' }}</span>
                    <AppIcon v-if="peer.device.wireguard_key === 'device'" name="key" :size="14" class="shrink-0 text-emerald-600" />
                    <span v-if="peer.device.wireguard_key === 'device'" class="sr-only">, with its own WireGuard key</span>
                  </p>
                  <p class="text-xs text-slate-500 dark:text-slate-400">
                    {{ peer.device.wireguard_key === 'device' ? 'Own key: the file no longer connects' : 'Connects with the file' }}
                  </p>
                </template>
                <template v-else-if="peer.device?.state === 'waiting'">
                  <UiBadge tone="amber">Waiting</UiBadge>
                  <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Until {{ dateTime(peer.device.enrollment_until) }}</p>
                </template>
                <template v-else>
                  <UiBadge tone="gray">None</UiBadge>
                  <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Allow a device to log in</p>
                </template>
              </td>
              <td class="px-4 py-3 whitespace-nowrap">
                <template v-if="peer.last_handshake || !peer.last_seen">
                  <p>{{ ago(peer.last_handshake) }}</p>
                  <p v-if="peer.endpoint" class="font-mono text-xs text-slate-500 dark:text-slate-400">{{ peer.endpoint }}</p>
                </template>
                <!-- WireGuard forgets the handshakes when the container starts again: the history doesn't -->
                <template v-else>
                  <p :title="`Last seen ${dateTime(peer.last_seen)}, in the connection history`">Seen {{ ago(peer.last_seen) }}</p>
                  <p v-if="peer.last_endpoint" class="font-mono text-xs text-slate-500 dark:text-slate-400">{{ peer.last_endpoint }}</p>
                </template>
              </td>
              <td class="px-4 py-3 whitespace-nowrap text-slate-600 dark:text-slate-300">
                ↓ {{ formatBytes(peer.received) }} · ↑ {{ formatBytes(peer.sent) }}
              </td>
              <td class="px-4 py-3 text-right">
                <UiMenu v-if="canManage()" :items="peerMenu(peer)" :label="`Actions of ${peer.name}`" />
              </td>
            </tr>
            <tr v-if="!filtered.length">
              <td :colspan="bound ? 7 : 6" class="px-4 py-6 text-center text-slate-500">No peer matches "{{ search }}".</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <PeerDrawer
      :open="drawerOpen"
      :server="server"
      :peer="editing"
      :peers="peers"
      :users="users"
      @close="drawerOpen = false"
      @saved="peerSaved"
    />
    <PeerConfigModal :peer="configPeer" :server="server" @close="configPeer = null" />
    <PeerAlertsModal :peer="alertsPeer" @close="alertsPeer = null" @cleared="loadPeers" />
    <RoutingHelpModal :open="routingHelp" :routed="server.routed" @close="routingHelp = false" />
  </div>
</template>
