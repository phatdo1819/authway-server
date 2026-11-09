<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, ApiError, type AuthMode, type Server, type ServerInput, type ServerSuggestion } from '../../api'
import AppIcon from '../../components/AppIcon.vue'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiListInput from '../../components/UiListInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { authModes, duration, errorMessage, fieldMessage, lockModes, routingModes } from '../../format'
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
    ? `The container has no IPv6 for the tunnels: ${ipv6Off.value}.`
    : 'Optional: empty for IPv4 only. Each peer gets the address in the same place as its IPv4 one, 10.8.0.5 is …::5. The server forwards IPv6 as IPv4, with the address of its container.',
)
// the IPv6 network of a server with peers changes: they keep working with their files, over IPv4
const ipv6Changes = computed(() => {
  const s = props.server
  const now = form.value.network6.trim()
  if (!s || s.peers === 0 || now === s.network6) {
    return ''
  }
  if (!now) {
    return 'The peers lose their IPv6 address. Their configuration files still connect, over IPv4.'
  }
  return 'The peers get an IPv6 address from their IPv4 one. Their configuration files of before keep working over IPv4: download them again for IPv6.'
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
const lockOptions = lockModes.map((mode) => ({ value: mode.value, label: mode.label }))
const lockHelp = computed(() => lockModes.find((mode) => mode.value === form.value.lock_endpoint)?.description ?? '')

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
    if (props.server) {
      const s = props.server
      form.value = {
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
        reachable_servers: [...s.reachable_servers],
        routed: s.routed,
        inbound: s.inbound,
      }
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
    reachable_servers: form.value.reachable_servers.filter((id) => others.value.some((server) => server.id === id)),
    inbound: form.value.routed && form.value.inbound,
  }
  try {
    const server = props.server ? await api.updateServer(props.server.id, input) : await api.createServer(input)
    notify(props.server ? `${server.name} saved.` : `${server.name} added.`)
    emit('saved', server)
  } catch (e) {
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = e.fields
      if (['public_port', 'mtu', 'keepalive'].some((field) => field in e.fields)) {
        advanced.value = true
      }
    }
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

function setMode(mode: AuthMode) {
  form.value.auth_mode = mode
}
</script>

<template>
  <UiDrawer :open="open" :title="server ? `Edit ${server.name}` : 'Add server'" @close="emit('close')">
    <form id="server-form" class="space-y-8" novalidate @submit.prevent="save">
      <section class="space-y-5">
        <UiInput v-model="form.name" label="Name" :error="fieldMessage(errors.name)" helper="Letters, digits, spaces, dots, dashes; up to 32. It names the configuration files." />
        <UiToggle v-model="form.enabled" label="Enabled" description="A disabled server keeps its peers, but nobody connects." />
      </section>

      <section class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Connection</h3>
        <UiInput
          v-model="form.public_host"
          label="Public address"
          placeholder="vpn.example.com"
          :error="fieldMessage(errors.public_host)"
          helper="The name or IP the peers connect to, from the internet."
        />
        <UiInput
          v-model="form.listen_port"
          label="UDP port"
          type="number"
          :error="fieldMessage(errors.listen_port)"
          helper="Publish it in Docker too, for example 51820:51820/udp."
        />
        <UiListInput
          v-model="form.fallback_endpoints"
          label="Fallback addresses"
          placeholder="vpn2.example.com:51820"
          add-label="Add fallback address"
          :error="fieldMessage(errors.fallback_endpoints)"
          helper="Other addresses of this server, for example the IP of a second internet line, up to 4. Authway tries them when the public address doesn't answer; the WireGuard apps ignore them. Without a port, the one of the public address."
        />
      </section>

      <section class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Networks</h3>
        <UiInput
          v-model="form.network"
          label="Tunnel network"
          mono
          placeholder="10.8.0.0/24"
          :error="fieldMessage(errors.network)"
          helper="The server takes the first address, the peers the next ones."
        />
        <div>
          <UiInput
            v-model="form.network6"
            label="IPv6 tunnel network"
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
          label="Networks the peers reach"
          placeholder="192.168.1.0/24"
          add-label="Add network"
          :error="fieldMessage(errors.networks)"
          helper="The peers that don't send all their traffic through the tunnel route these networks to it. The peers that send all of it reach everything. IPv6 networks need the IPv6 tunnel network."
        />
        <UiNotice v-if="ipv6Changes" tone="info">{{ ipv6Changes }}</UiNotice>
        <fieldset class="space-y-2.5">
          <legend class="mb-2 flex items-center gap-1 text-sm font-medium">
            What the networks see of the peers
            <button
              type="button"
              class="rounded-full p-0.5 text-slate-500 hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-2 focus-visible:outline-sky-600 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="How NAT and routed work"
              title="How NAT and routed work"
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
          label="The networks start connections to the peers"
          :description="
            gated
              ? 'From the networks above, to the peers logged in only. The firewall of each device still decides.'
              : 'From the networks above, to every peer of this server. The firewall of each device still decides.'
          "
        />
        <UiNotice v-if="routedStarts" tone="warning">
          Until the router of the networks has a route to the tunnel networks, through the Docker host or the container,
          the networks don't answer the peers. After saving, the server shows the route to add.
        </UiNotice>
        <UiNotice v-if="routedEnds" tone="info">
          The connections the peers opened while routed can drop once: their apps connect again, through NAT.
          <template v-if="inboundEnds">The networks no longer start connections to the peers.</template>
          The route on the router is no longer needed.
        </UiNotice>
        <UiListInput
          v-model="form.dns"
          label="DNS servers of the peers"
          placeholder="192.168.1.1"
          add-label="Add DNS server"
          :error="fieldMessage(errors.dns)"
        />
      </section>

      <section class="space-y-4">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Login</h3>
        <fieldset class="space-y-2.5">
          <legend class="sr-only">Login of the peers</legend>
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
          helper="After it, the user logs in again. A session also ends after 5 minutes without a handshake."
        />
        <UiNotice v-if="modeChanges" tone="warning">The peers logged in now are logged out: they log in again under the new mode.</UiNotice>
        <UiNotice v-if="withoutUser" tone="warning">
          {{ withoutUser === 1 ? '1 peer of this server has no user' : `${withoutUser} peers of this server have no user` }}: with a
          login they reach only the login page, and can't log in. After saving, choose the user of each one with Edit, in the
          menu of the peer.
        </UiNotice>
      </section>

      <section v-if="gated" class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Copied configurations</h3>
        <UiSelect
          v-model="form.lock_endpoint"
          label="Lock the session to the public IP of the login"
          :options="lockOptions"
          :error="fieldMessage(errors.lock_endpoint)"
          :helper="lockHelp"
        />
        <UiToggle
          v-model="form.detect_copies"
          label="Detect two devices with the same configuration"
          description="The public IP of a peer that keeps switching between two networks means two devices: the session ends and an alert is recorded. Two devices behind the same NAT can't be told apart."
        />
        <UiToggle
          v-if="form.detect_copies"
          v-model="form.block_copies"
          label="Block the peer when it happens"
          description="Until an administrator clears its alerts or gives it new keys. Without it, the user can log in again."
        />
        <UiToggle
          v-model="form.redirect"
          label="Lead to the login page"
          description="Before the login, any name resolves to this server and any plain http:// address opens the login page. Nothing is forwarded."
        />
      </section>

      <section v-if="gated" class="space-y-5">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Device binding</h3>
        <UiToggle
          v-model="form.device_binding"
          label="Log in only from the enrolled device"
          description="The first device that logs in for a peer is enrolled: from then on only that device logs in, with the Authway app. A copy of the configuration file doesn't log in anywhere else, even with the password. The browser and the WireGuard apps can't log in."
        />
        <UiToggle
          v-if="form.device_binding"
          v-model="form.machine_id"
          label="Check the computer too"
          description="Authway also sends a fingerprint of the hardware of the computer: the key of the device, copied to another computer, doesn't log in."
        />
        <UiNotice v-if="bindingStarts" tone="warning">
          The peers logged in now are logged out: they log in again from their device, which is enrolled then.
        </UiNotice>
      </section>

      <section class="space-y-4">
        <h3 class="text-sm font-semibold tracking-wide text-slate-500 uppercase dark:text-slate-400">Traffic between peers</h3>
        <UiToggle
          v-model="form.client_to_client"
          label="The peers of this server reach each other"
          :description="gated ? 'Both peers must be logged in.' : 'Every connection between two peers of this server passes.'"
        />
        <fieldset v-if="others.length" class="space-y-2">
          <legend class="text-sm font-medium">The peers of this server reach the peers of</legend>
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
            One way: the peers of the servers checked answer, but don't start connections here. For the other way, check
            this server in their settings.
          </p>
          <p v-if="fieldMessage(errors.reachable_servers)" class="text-xs text-red-700 dark:text-red-400">
            {{ fieldMessage(errors.reachable_servers) }}
          </p>
        </fieldset>
        <UiNotice v-if="reachChanges" tone="info">
          The peers that don't send all their traffic through the tunnel, of this server and of the servers checked or
          unchecked, need their configuration file again: it routes the networks of the linked servers.
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
            helper="When Docker or a router publishes the UDP port under another number. 0: the UDP port."
          />
          <UiInput
            v-model="form.mtu"
            label="MTU"
            type="number"
            optional
            :error="fieldMessage(errors.mtu)"
            helper="0: 1420, the default of WireGuard. From 1280 to 1500."
          />
          <UiInput
            v-model="form.keepalive"
            label="Keepalive of the peers (seconds)"
            type="number"
            :error="fieldMessage(errors.keepalive)"
            helper="Keeps the tunnel open through NAT, and the sessions alive. 0 turns it off."
          />
        </div>
      </section>

      <UiNotice v-if="filesChange" tone="info">
        This changes the configuration files of the peers: download them again for the devices. The peers that send all
        their traffic through the tunnel keep working with the old file when only the networks change.
      </UiNotice>
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <RoutingHelpModal :open="routingHelp" :routed="form.routed" @close="routingHelp = false" />
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="server-form" variant="primary" :loading="busy" :disabled="loading">
        {{ server ? 'Save' : 'Add server' }}
      </UiButton>
    </template>
  </UiDrawer>
</template>
