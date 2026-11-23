<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, ApiError, type AuthMode, type Server, type ServerInput, type ServerSuggestion } from '../../api'
import AppIcon from '../../components/AppIcon.vue'
import ConflictNotice from '../../components/ConflictNotice.vue'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiListInput from '../../components/UiListInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { useEditGuard } from '../../conflict'
import { authModes, duration, errorMessage, fieldMessage, lockOff, lockOn, routingModes } from '../../format'
import { isPublicTunnel, routerRoutes } from '../../routing'
import { notify } from '../../state'
import RoutingHelpModal from './RoutingHelpModal.vue'

// servers: all of them, for the ones the peers reach
const props = defineProps<{ open: boolean; server: Server | null; servers: Server[] }>()
const emit = defineEmits<{ close: []; saved: [Server] }>()

const form = ref<ServerInput>(blank())
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)
const advanced = ref(false)
const loading = ref(false)
// why the tunnels can't carry IPv6, as the server says it: then no IPv6 network is proposed
const ipv6Off = ref('')
const suggesting = ref(false)
// the explanation of NAT and routed, over the drawer
const routingHelp = ref(false)

const timeouts = [3600, 2 * 3600, 4 * 3600, 8 * 3600, 12 * 3600, 24 * 3600, 3 * 86400, 7 * 86400]
const timeoutOptions = computed(() => {
  const values = timeouts.includes(form.value.session_timeout) ? timeouts : [...timeouts, form.value.session_timeout].sort((a, b) => a - b)
  return values.map((value) => ({ value, label: duration(value) }))
})
const gated = computed(() => form.value.auth_mode !== 'key')
// what the configuration files of the peers carry: a change needs new files on the devices
const filesChange = computed(() => {
  const s = props.server
  if (!s) {
    return false
  }
  const clean = (list: string[]) => list.map((value) => value.trim()).filter(Boolean).join(',')
  return (
    s.public_host !== form.value.public_host.trim() ||
    Number(form.value.public_port || 0) !== s.public_port ||
    (Number(form.value.public_port || 0) === 0 && Number(form.value.listen_port) !== s.listen_port) ||
    clean(form.value.networks) !== s.networks.join(',') ||
    clean(form.value.dns) !== s.dns.join(',') ||
    clean(form.value.fallback_endpoints) !== s.fallback_endpoints.join(',') ||
    Number(form.value.mtu || 0) !== s.mtu ||
    Number(form.value.keepalive) !== s.keepalive ||
    (s.auth_mode === 'key') !== (form.value.auth_mode === 'key') ||
    form.value.network6.trim() !== s.network6
  )
})
const network6Help = computed(() =>
  ipv6Off.value
    ? `IPv6 isn't available to Authway Server: ${ipv6Off.value}.`
    : 'Optional. Leave empty for IPv4 only. Each peer gets the matching IPv6 address (10.8.0.5 becomes …::5). IPv6 traffic leaves through Authway Server\'s own address, like IPv4.',
)
// the IPv6 network of a server with peers changes: they keep working with their files, over IPv4
const ipv6Changes = computed(() => {
  const s = props.server
  const now = form.value.network6.trim()
  if (!s || s.peers === 0 || now === s.network6) {
    return ''
  }
  if (!now) {
    return 'Peers will lose their IPv6 address. Their existing configuration files still work over IPv4.'
  }
  return 'Peers will get an IPv6 address matching their IPv4 one. Existing configuration files keep working over IPv4; download them again to use IPv6.'
})

async function suggestNetwork6() {
  if (!props.server) {
    return
  }
  suggesting.value = true
  try {
    const suggestion = await api.serverDefaults(props.server.id)
    ipv6Off.value = suggestion.ipv6_off ?? ''
    if (suggestion.network6) {
      form.value.network6 = suggestion.network6
    }
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    suggesting.value = false
  }
}

// the values the server proposes, without what only tells why
function proposed(suggestion: ServerSuggestion): ServerInput {
  const { ipv6_off: off, ...input } = suggestion
  ipv6Off.value = off ?? ''
  return input
}
// the login mode of the peers that are logged in changes: they log in again
const modeChanges = computed(() => props.server !== null && props.server.auth_mode !== form.value.auth_mode && props.server.sessions > 0)
// the login turned on: the peers added without a user can't log in until they get one
const withoutUser = computed(() => (props.server?.auth_mode === 'key' && gated.value ? props.server.peers_without_user : 0))
// device binding turned on: the peers logged in log in again, from their device
const bindingStarts = computed(
  () => props.server !== null && gated.value && form.value.device_binding && !props.server.device_binding && props.server.sessions > 0,
)
// routed now: the answers of the networks need the route on their router
const routedStarts = computed(() => form.value.routed && !props.server?.routed)
// the routes the routers need, where the other routed servers tell the address of Authway Server in the network: for
// the warning below and the drawing of the help
const routes = computed(() => routerRoutes(form.value.network, form.value.networks, props.servers))
const startRoutes = computed(() => (routedStarts.value && routes.value.known.length > 0 ? routes.value : null))
// what the server shows after saving: the networks whose route isn't known yet, and the IPv6 tunnel
const laterRoutes = computed(() => {
  const later = [...(startRoutes.value?.unknown ?? [])]
  if (form.value.network6.trim()) {
    later.push(form.value.network6.trim())
  }
  return later
})
// the tunnel networks that the helper of the Docker host routes only when its AUTHWAY_ROUTE_PUBLIC lists them
const publicTunnels = computed(() =>
  [form.value.network.trim(), form.value.network6.trim()].filter((cidr) => cidr !== '' && isPublicTunnel(cidr)),
)
// NAT again: the connections opened while routed lose their answers, and the networks no longer reach the peers
const routedEnds = computed(() => props.server !== null && props.server.routed && !form.value.routed)
const inboundEnds = computed(() => routedEnds.value && props.server?.inbound === true)
const others = computed(() => props.servers.filter((server) => server.id !== props.server?.id))
// the peers of this server and of the servers checked or unchecked route other networks: new files
const reachChanges = computed(() => {
  const before = [...(props.server?.reachable_servers ?? [])].sort().join(',')
  return before !== [...form.value.reachable_servers].sort().join(',')
})

function toggleReach(id: number, on: boolean) {
  const list = form.value.reachable_servers.filter((value) => value !== id)
  form.value.reachable_servers = on ? [...list, id] : list
}
// the lock to the public IP of the login, as a switch: off, the session follows the device
const locked = computed({
  get: () => form.value.lock_endpoint === 'strict',
  set: (on: boolean) => {
    form.value.lock_endpoint = on ? 'strict' : 'roaming'
  },
})

// the fields of the form from a server, the servers it reaches in order: their order doesn't matter
function formOf(s: Server): ServerInput {
  return {
    name: s.name,
    enabled: s.enabled,
    public_host: s.public_host,
    listen_port: s.listen_port,
    public_port: s.public_port,
    network: s.network,
    network6: s.network6,
    networks: [...s.networks],
    dns: [...s.dns],
    mtu: s.mtu,
    keepalive: s.keepalive,
    auth_mode: s.auth_mode,
    session_timeout: s.session_timeout,
    lock_endpoint: s.lock_endpoint,
    detect_copies: s.detect_copies,
    block_copies: s.block_copies,
    redirect: s.redirect,
    fallback_endpoints: [...s.fallback_endpoints],
    device_binding: s.device_binding,
    machine_id: s.machine_id,
    client_to_client: s.client_to_client,
    reachable_servers: [...s.reachable_servers].sort((a, b) => a - b),
    routed: s.routed,
    inbound: s.inbound,
  }
}

// another administrator saving this server meanwhile
const guard = useEditGuard(formOf, {
  name: 'Name',
  enabled: 'Enabled',
  public_host: 'Public address',
  listen_port: 'UDP port',
  public_port: 'Public port',
  network: 'VPN network',
  network6: 'IPv6 tunnel network',
  networks: 'Networks peers can reach',
  dns: 'DNS servers of the peers',
  mtu: 'MTU',
  keepalive: 'Peer keepalive',
  auth_mode: 'Login',
  session_timeout: 'Session length',
  lock_endpoint: 'Lock session to login IP',
  detect_copies: 'Detect shared configurations',
  block_copies: 'Block the peer',
  redirect: 'Redirect to the login page',
  fallback_endpoints: 'Fallback addresses',
  device_binding: 'Device binding',
  machine_id: 'Also check the computer',
  client_to_client: 'Peers can reach each other',
  reachable_servers: 'Servers peers can reach',
  routed: 'NAT or routed',
  inbound: 'Networks can connect to peers',
  version: 'Version',
})
const conflict = guard.conflict

function useTheirs() {
  Object.assign(form.value, guard.useTheirs())
}

function blank(): ServerInput {
  return {
    name: '',
    enabled: true,
    public_host: '',
    listen_port: 51820,
    public_port: 0,
    network: '',
    network6: '',
    networks: [],
    dns: [],
    mtu: 0,
    keepalive: 25,
    auth_mode: 'password',
    session_timeout: 8 * 3600,
    lock_endpoint: 'strict',
    detect_copies: true,
    block_copies: false,
    redirect: true,
    fallback_endpoints: [],
    device_binding: false,
    machine_id: false,
    client_to_client: false,
    reachable_servers: [],
    routed: false,
    inbound: false,
  }
}

watch(
  () => props.open,
  async (open) => {
    if (!open) {
      return
    }
    errors.value = {}
    error.value = ''
    advanced.value = false
    ipv6Off.value = ''
    guard.start(props.server)
    if (props.server) {
      form.value = formOf(props.server)
      return
    }
    form.value = blank()
    loading.value = true
    try {
      form.value = { ...blank(), ...proposed(await api.serverDefaults()) }
    } catch (e) {
      error.value = errorMessage(e)
    } finally {
      loading.value = false
    }
  },
)

function number(value: string | number): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.trunc(parsed) : -1
}

async function save() {
  busy.value = true
  errors.value = {}
  error.value = ''
  let again = false
  const input: ServerInput = {
    ...form.value,
    listen_port: number(form.value.listen_port),
    public_port: form.value.public_port === ('' as unknown) ? 0 : number(form.value.public_port),
    mtu: form.value.mtu === ('' as unknown) ? 0 : number(form.value.mtu),
    keepalive: number(form.value.keepalive),
    network6: form.value.network6.trim(),
    networks: form.value.networks.map((value) => value.trim()).filter(Boolean),
    dns: form.value.dns.map((value) => value.trim()).filter(Boolean),
    fallback_endpoints: form.value.fallback_endpoints.map((value) => value.trim()).filter(Boolean),
    block_copies: form.value.detect_copies && form.value.block_copies,
    device_binding: gated.value && form.value.device_binding,
    machine_id: gated.value && form.value.device_binding && form.value.machine_id,
    // the servers deleted meanwhile
    reachable_servers: form.value.reachable_servers
      .filter((id) => others.value.some((server) => server.id === id))
      .sort((a, b) => a - b),
    inbound: form.value.routed && form.value.inbound,
  }
  try {
    const server = props.server
      ? await api.updateServer(props.server.id, { ...input, version: guard.version.value })
      : await api.createServer(input)
    notify(props.server ? `${server.name} saved.` : `${server.name} added.`)
    emit('saved', server)
  } catch (e) {
    const merged = guard.refused(e, input)
    if (merged) {
      form.value = merged.values
      again = merged.again
      return
    }
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = e.fields
      if (['public_port', 'mtu', 'keepalive'].some((field) => field in e.fields)) {
        advanced.value = true
      }
    }
    error.value = errorMessage(e)
  } finally {
    busy.value = false
    // only what the form doesn't show changed meanwhile: saved again with the new version
    if (again) {
      save()
    }
  }
}

function setMode(mode: AuthMode) {
  form.value.auth_mode = mode
}
</script>

<template>
  <UiDrawer :open="open" :title="server ? `Edit ${server.name}` : 'Add server'" @close="emit('close')">
    <form id="server-form" class="space-y-8" novalidate @submit.prevent="save">
      <ConflictNotice :conflict="conflict" noun="server" @theirs="useTheirs" />
      <section class="space-y-5">
        <UiInput v-model="form.name" label="Name" :error="fieldMessage(errors.name)" helper="Letters, digits, spaces, dots and dashes, up to 32 characters. Used to name the configuration files." />
        <UiToggle v-model="form.enabled" label="Enabled" description="A disabled server keeps its peers, but no one can connect." />
      </section>

      <section class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Connection</h3>
        <UiInput
          v-model="form.public_host"
          label="Public address"
          placeholder="vpn.example.com"
          :error="fieldMessage(errors.public_host)"
          helper="The hostname or IP address peers connect to from the internet."
        />
        <UiInput
          v-model="form.listen_port"
          label="UDP port"
          type="number"
          :error="fieldMessage(errors.listen_port)"
          helper="Also publish this port in Docker, for example 51820:51820/udp."
        />
        <UiListInput
          v-model="form.fallback_endpoints"
          label="Fallback addresses"
          placeholder="vpn2.example.com:51820"
          add-label="Add fallback address"
          :error="fieldMessage(errors.fallback_endpoints)"
          helper="Up to 4 other addresses for this server, such as the IP of a second internet line. The Authway app tries them if the public address doesn't respond; WireGuard apps ignore them. Without a port, the public address's port is used."
        />
      </section>

      <section class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Networks</h3>
        <UiInput
          v-model="form.network"
          label="VPN network"
          mono
          placeholder="10.8.0.0/24"
          :error="fieldMessage(errors.network)"
          helper="The server uses the first address; peers get the following ones."
        />
        <div>
          <UiInput
            v-model="form.network6"
            label="IPv6 VPN network"
            mono
            optional
            placeholder="fd12:3456:789a:1::/64"
            :error="fieldMessage(errors.network6)"
            :helper="network6Help"
          />
          <button
            v-if="!form.network6.trim() && !ipv6Off"
            type="button"
            class="mt-2 text-sm font-medium text-sky-700 hover:text-sky-900 disabled:opacity-60 dark:text-sky-400"
            :disabled="suggesting"
            @click="suggestNetwork6"
          >
            Suggest an IPv6 network
          </button>
        </div>
        <UiListInput
          v-model="form.networks"
          label="Networks peers can reach"
          placeholder="192.168.1.0/24"
          add-label="Add network"
          :error="fieldMessage(errors.networks)"
          helper="Peers that use split tunneling send only these networks through the VPN. Peers that send all their traffic through the VPN can reach everything. IPv6 networks need an IPv6 VPN network."
        />
        <UiNotice v-if="ipv6Changes" tone="info">{{ ipv6Changes }}</UiNotice>
        <fieldset class="space-y-2.5">
          <legend class="mb-2 flex items-center gap-1 text-sm font-medium">
            How your networks see peers
            <button
              type="button"
              class="rounded-full p-0.5 text-slate-500 hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-2 focus-visible:outline-sky-600 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="How NAT and routed modes work"
              title="How NAT and routed modes work"
              @click="routingHelp = true"
            >
              <AppIcon name="help" :size="18" />
            </button>
          </legend>
          <label
            v-for="mode in routingModes"
            :key="mode.label"
            class="flex cursor-pointer gap-3 rounded-lg border p-3.5"
            :class="
              form.routed === mode.value
                ? 'border-sky-600 bg-sky-50/60 ring-1 ring-sky-600 dark:border-sky-400 dark:bg-sky-500/10 dark:ring-sky-400'
                : 'border-slate-200 hover:border-slate-300 dark:border-slate-700'
            "
          >
            <input
              type="radio"
              name="routed"
              class="mt-0.5 accent-sky-700"
              :checked="form.routed === mode.value"
              @change="form.routed = mode.value"
            />
            <span>
              <span class="block text-sm font-medium">{{ mode.label }}</span>
              <span class="block text-sm text-slate-500 dark:text-slate-400">{{ mode.description }}</span>
            </span>
          </label>
          <p v-if="fieldMessage(errors.routed)" class="text-xs text-red-700 dark:text-red-400">{{ fieldMessage(errors.routed) }}</p>
        </fieldset>
        <UiToggle
          v-if="form.routed"
          v-model="form.inbound"
          label="Allow your networks to connect to peers"
          :description="
            gated
              ? 'Devices on the networks above can open connections to logged-in peers. Each device\'s own firewall still applies.'
              : 'Devices on the networks above can open connections to any peer on this server. Each device\'s own firewall still applies.'
          "
        />
        <UiNotice v-if="startRoutes" tone="warning">
          <p>Add these routes to your routers. Until you do, those networks can't reply to peers.</p>
          <ul class="mt-1 list-disc space-y-0.5 pl-5">
            <li v-for="route in startRoutes.known" :key="route.network">
              <span class="font-mono">{{ route.tunnel }} via {{ route.via }}</span>, on the router for
              <span class="font-mono">{{ route.network }}</span>
            </li>
          </ul>
          <p v-if="laterRoutes.length > 0" class="mt-1">
            After you save, the server's panel lists the remaining routes to add, for
            <span class="font-mono">{{ laterRoutes.join(', ') }}</span>.
          </p>
        </UiNotice>
        <UiNotice v-else-if="routedStarts" tone="warning">
          Your networks can't reply to peers until their router has a route back to the VPN network. After you save, the
          server's panel shows the route to add.
        </UiNotice>
        <UiNotice v-if="form.routed && publicTunnels.length > 0" tone="warning">
          <span class="font-mono">{{ publicTunnels.join(', ') }}</span>
          {{ publicTunnels.length > 1 ? "aren't private networks" : "isn't a private network" }}. If you route through the
          Docker host (compose.host-routes.yaml), add {{ publicTunnels.length > 1 ? 'them' : 'it' }} to AUTHWAY_ROUTE_PUBLIC in
          the Docker host's .env file. Private IPv4 networks and unique local IPv6 networks (fd00::/8) work without this.
        </UiNotice>
        <UiNotice v-if="routedEnds" tone="info">
          Connections that peers opened in routed mode may drop once; their apps reconnect through NAT.
          <template v-if="inboundEnds">Your networks can no longer open connections to peers.</template>
          You can remove the route from your router.
        </UiNotice>
        <UiListInput
          v-model="form.dns"
          label="DNS servers for peers"
          placeholder="192.168.1.1"
          add-label="Add DNS server"
          :error="fieldMessage(errors.dns)"
          helper="Peers with names in their access rules use Authway Server instead, which asks these servers."
        />
      </section>

      <section class="space-y-4">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Login</h3>
        <fieldset class="space-y-2.5">
          <legend class="sr-only">How peers log in</legend>
          <label
            v-for="mode in authModes"
            :key="mode.value"
            class="flex cursor-pointer gap-3 rounded-lg border p-3.5"
            :class="
              form.auth_mode === mode.value
                ? 'border-sky-600 bg-sky-50/60 ring-1 ring-sky-600 dark:border-sky-400 dark:bg-sky-500/10 dark:ring-sky-400'
                : 'border-slate-200 hover:border-slate-300 dark:border-slate-700'
            "
          >
            <input
              type="radio"
              name="auth_mode"
              class="mt-0.5 accent-sky-700"
              :checked="form.auth_mode === mode.value"
              @change="setMode(mode.value)"
            />
            <span>
              <span class="block text-sm font-medium">{{ mode.label }}</span>
              <span class="block text-sm text-slate-500 dark:text-slate-400">{{ mode.description }}</span>
            </span>
          </label>
        </fieldset>
        <UiSelect
          v-if="gated"
          v-model="form.session_timeout"
          label="Session length"
          :options="timeoutOptions"
          :error="fieldMessage(errors.session_timeout)"
          helper="When it ends, the user must log in again. A session also ends after 5 minutes without traffic."
        />
        <UiNotice v-if="modeChanges" tone="warning">Peers that are logged in now will be logged out and need to log in again.</UiNotice>
        <UiNotice v-if="withoutUser" tone="warning">
          {{ withoutUser === 1 ? '1 peer on this server has no user' : `${withoutUser} peers on this server have no user` }}. With
          a login required, they can only reach the login page and can't log in. After saving, assign a user to each one
          (Edit, in the peer's menu).
        </UiNotice>
      </section>

      <section v-if="gated" class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Protection against shared configurations</h3>
        <UiToggle v-model="locked" label="Lock each session to the IP it logged in from" :description="locked ? lockOn : lockOff" />
        <p v-if="fieldMessage(errors.lock_endpoint)" class="text-xs text-red-700 dark:text-red-400">
          {{ fieldMessage(errors.lock_endpoint) }}
        </p>
        <UiToggle
          v-model="form.detect_copies"
          label="Detect two devices using the same configuration"
          description="If a peer keeps switching between two public IPs, two devices are probably using it. The session ends and an alert is recorded. Two devices behind the same NAT can't be told apart."
        />
        <UiToggle
          v-if="form.detect_copies"
          v-model="form.block_copies"
          label="Block the peer when this happens"
          description="The peer stays blocked until an administrator clears its alerts or gives it new keys. If this is off, the user can simply log in again."
        />
        <UiToggle
          v-model="form.redirect"
          label="Redirect to the login page"
          description="Before login, every website name points to this server, and any http:// address opens the login page. No other traffic gets through."
        />
      </section>

      <section v-if="gated" class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Device binding</h3>
        <UiToggle
          v-model="form.device_binding"
          label="Only allow logins from the enrolled device"
          description="The first device that logs in with a peer is enrolled. After that, only that device can log in, using the Authway app. A copied configuration file won't work anywhere else, even with the right password. Logging in from a browser or the WireGuard apps isn't possible."
        />
        <UiToggle
          v-if="form.device_binding"
          v-model="form.machine_id"
          label="Also check the computer"
          description="The Authway app also sends a fingerprint of the computer's hardware, so a device key copied to another computer can't log in."
        />
        <UiNotice v-if="bindingStarts" tone="warning">
          Peers that are logged in now will be logged out. Their next login enrolls the device they use.
        </UiNotice>
      </section>

      <section class="space-y-4">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Traffic between peers</h3>
        <UiToggle
          v-model="form.client_to_client"
          label="Peers on this server can reach each other"
          :description="gated ? 'Both peers must be logged in.' : 'All connections between peers on this server are allowed.'"
        />
        <fieldset v-if="others.length" class="space-y-2">
          <legend class="text-sm font-medium">Peers on this server can also reach peers on</legend>
          <label
            v-for="other in others"
            :key="other.id"
            class="flex cursor-pointer items-center gap-3 rounded-lg border border-slate-200 px-3.5 py-2.5 hover:border-slate-300 dark:border-slate-700"
          >
            <input
              type="checkbox"
              class="size-4 accent-sky-700"
              :checked="form.reachable_servers.includes(other.id)"
              @change="toggleReach(other.id, ($event.target as HTMLInputElement).checked)"
            />
            <span class="min-w-0 flex-1 text-sm">
              {{ other.name }}
              <span class="ml-1 font-mono text-xs text-slate-500 dark:text-slate-400">{{ other.network }}</span>
            </span>
            <span v-if="!other.enabled" class="text-xs text-slate-500">Disabled</span>
          </label>
          <p class="text-xs text-slate-500 dark:text-slate-400">
            One way only: peers on the selected servers can reply, but can't start connections to this server. To allow
            the other direction, select this server in their settings.
          </p>
          <p v-if="fieldMessage(errors.reachable_servers)" class="text-xs text-red-700 dark:text-red-400">
            {{ fieldMessage(errors.reachable_servers) }}
          </p>
        </fieldset>
        <UiNotice v-if="reachChanges" tone="info">
          Split-tunnel peers on this server and on the servers you selected or cleared need a new configuration file, because
          it lists the networks of linked servers.
        </UiNotice>
      </section>

      <section>
        <button
          type="button"
          class="text-sm font-medium text-sky-700 hover:text-sky-900 dark:text-sky-400"
          :aria-expanded="advanced"
          @click="advanced = !advanced"
        >
          {{ advanced ? 'Hide' : 'Show' }} advanced settings
        </button>
        <div v-if="advanced" class="mt-5 space-y-5">
          <UiInput
            v-model="form.public_port"
            label="Public port"
            type="number"
            optional
            :error="fieldMessage(errors.public_port)"
            helper="Set this if Docker or a router exposes the UDP port under a different number. 0 means the same as the UDP port."
          />
          <UiInput
            v-model="form.mtu"
            label="MTU"
            type="number"
            optional
            :error="fieldMessage(errors.mtu)"
            helper="0 uses WireGuard's default of 1420. Allowed range: 1280 to 1500."
          />
          <UiInput
            v-model="form.keepalive"
            label="Peer keepalive (seconds)"
            type="number"
            :error="fieldMessage(errors.keepalive)"
            helper="Keeps the tunnel open through NAT and keeps sessions alive. 0 turns it off."
          />
        </div>
      </section>

      <UiNotice v-if="filesChange" tone="info">
        This changes the peers' configuration files, so download them again for each device. If only the networks changed,
        peers that send all their traffic through the VPN keep working with their old file.
      </UiNotice>
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <RoutingHelpModal
      :open="routingHelp"
      :routed="form.routed"
      :route="routes.known[0] ?? null"
      @close="routingHelp = false"
    />
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="server-form" variant="primary" :loading="busy" :disabled="loading">
        {{ server ? 'Save' : 'Add server' }}
      </UiButton>
    </template>
  </UiDrawer>
</template>
