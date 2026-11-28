<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import {
  address6Of,
  addressProblem,
  emptyRow,
  isName,
  nextFreeAddress,
  rowProblem,
  rowsOf,
  ruleTarget,
  rulesOf,
  type AccessRow,
} from '../../addresses'
import { api, ApiError, type Peer, type PeerInput, type Server, type User } from '../../api'
import ConflictNotice from '../../components/ConflictNotice.vue'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { useEditGuard } from '../../conflict'
import { errorMessage, fieldMessage } from '../../format'
import { notify } from '../../state'
import AccessRules from './AccessRules.vue'

const props = defineProps<{ open: boolean; server: Server; peer: Peer | null; peers: Peer[]; users: User[] }>()
const emit = defineEmits<{ close: []; saved: [Peer, boolean] }>()

const form = ref<PeerInput>({ name: '', enabled: true, user_id: 0, route_all: false, address: '', device_approval: false })
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)
// the access rules: all the networks of the server, or only some, inside them, and names. A server without networks
// takes only names, none when the list is empty. A row each: the address, network or name, its traffic and ports
const limited = ref(false)
const rows = ref<AccessRow[]>([])
const hasNetworks = computed(() => props.server.networks.length > 0)
// the list applies: only some of the networks, or the names of a server without networks
const listed = computed(() => limited.value || !hasNetworks.value)
const serverNetworks = computed(() => props.server.networks.join(', '))
const accessModes = [
  { value: false, label: "All of the server's networks" },
  { value: true, label: 'Only some of them' },
]
const typedNames = computed(() => listed.value && rows.value.some((row) => isName(row.target)))
const routeAllHelp = computed(
  () =>
    `The device's internet traffic also goes out through this server. If off, only traffic for ${hasNetworks.value ? "the server's networks" : 'the sites below'} uses the VPN.`,
)
const accessHelp = computed(() => {
  if (!hasNetworks.value) {
    if (form.value.route_all) {
      return 'Since all its traffic goes through the VPN, it already reaches every site on the internet.'
    }
    return "Sites on the internet, such as app.example.com, or *.example.com for every name under example.com (not example.com itself). Their traffic goes through the VPN, so they see the server's public address, and the peer uses Authway Server as its DNS server. To allow only some traffic to a site, choose TCP, UDP or both, and the ports, such as 443. Leave the list empty for none."
  }
  let help = `Addresses or networks inside ${serverNetworks.value}, or names. A single address means just that one device. A name such as files.corp.lan, or *.corp.lan for every name under corp.lan (not corp.lan itself), covers the addresses that DNS gives for it.`
  if (!form.value.route_all) {
    help += " A name on the internet, such as app.example.com, also goes through the VPN, so the site sees the server's public address."
  }
  help += typedNames.value ? ' With a name, the peer uses Authway Server as its DNS server.' : " The peer still uses the server's DNS servers."
  help +=
    ' To allow only some traffic, choose TCP, UDP, both or ping instead of all traffic, and the ports: one such as 3389, several such as 80, 443, or a range such as 8000-8090. Empty ports are all of them.'
  return form.value.route_all ? `${help} Since all its traffic goes through the VPN, it can also reach the internet, but no other private networks.` : help
})
const accessError = computed(() => {
  if (errors.value.access !== 'invalid') {
    return fieldMessage(errors.value.access)
  }
  return hasNetworks.value
    ? 'Enter addresses, networks, or names such as files.corp.lan or *.corp.lan.'
    : 'Enter names such as app.example.com or *.example.com.'
})
// the rules of the rows, as the server keeps them, without the blank rows
const typedAccess = computed(() => (listed.value ? rulesOf(rows.value) : []))
// *.corp.lan covers the names under corp.lan, not corp.lan itself (in Active Directory, the domain's own name gives
// every domain controller): the wildcards typed without their own name, as the server compares names
const wildcardsAlone = computed(() => {
  const typed = typedAccess.value.map((entry) => ruleTarget(entry).replace(/\.$/, '').toLowerCase())
  const parents = typed.filter((entry) => entry.startsWith('*.') && isName(entry)).map((entry) => entry.slice(2))
  // a name alone needs two labels: *.lan's own name couldn't be added anyway
  return [...new Set(parents)].filter((parent) => parent.includes('.') && !typed.includes(parent))
})
function listOf(items: string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}` : items[0]
}
const wildcardHint = computed(() => {
  const parents = wildcardsAlone.value
  if (parents.length === 0) {
    return ''
  }
  if (parents.length === 1) {
    return `*.${parents[0]} doesn't include ${parents[0]} itself. Add ${parents[0]} too if the peer needs it.`
  }
  return `${listOf(parents.map((parent) => `*.${parent}`))} don't include ${listOf(parents)} themselves. Add them too if the peer needs them.`
})
// the ports don't change the file: the firewall of the server filters them
const accessChanges = computed(
  () => (props.peer?.access ?? []).map(ruleTarget).join(',') !== typedAccess.value.map(ruleTarget).join(','),
)
// names change the DNS server of the file, whatever traffic goes through the VPN
const namesChange = computed(() => (props.peer?.access ?? []).some(isName) !== typedNames.value)

const gated = computed(() => props.server.auth_mode !== 'key')
// device binding: the peer's new device waits for an administrator, or enrolls at its first login
const bound = computed(() => gated.value && props.server.device_binding)
// another administrator saving this peer meanwhile
const guard = useEditGuard(
  (peer: Peer) => ({
    name: peer.name,
    enabled: peer.enabled,
    user_id: peer.user_id,
    route_all: peer.route_all,
    access: [...peer.access],
    device_approval: peer.device_approval,
  }),
  {
    name: 'Name',
    enabled: 'Enabled',
    user_id: 'User',
    route_all: 'All traffic through the VPN',
    access: 'Networks it can reach',
    device_approval: 'New devices need approval',
  },
)
const conflict = guard.conflict
// the fields of the form, as the server has them
function typed() {
  return {
    name: form.value.name,
    enabled: form.value.enabled,
    user_id: gated.value ? Number(form.value.user_id) : (props.peer?.user_id ?? 0),
    route_all: form.value.route_all,
    access: typedAccess.value,
    device_approval: form.value.device_approval ?? false,
  }
}
function fill(values: Partial<ReturnType<typeof typed>>) {
  const { access: list, ...rest } = values
  Object.assign(form.value, rest)
  if (list) {
    limited.value = list.length > 0
    rows.value = list.length ? rowsOf(list) : [emptyRow()]
  }
}
function useTheirs() {
  fill(guard.useTheirs())
}
// a user has one peer on a server: the others are taken
const userOptions = computed(() => {
  const taken = new Set(props.peers.filter((peer) => peer.id !== props.peer?.id).map((peer) => peer.user_id))
  const options = props.users
    .filter((user) => !taken.has(user.id))
    .map((user) => ({
      value: user.id,
      label: `${user.username}${user.full_name ? ` (${user.full_name})` : ''}${user.disabled ? ' — disabled' : ''}`,
    }))
  return [{ value: 0, label: 'Choose a user' }, ...options]
})
// checked while typed: the address of another peer, of the server, out of the network
const addressError = computed(() => (props.peer ? '' : addressProblem(form.value.address ?? '', props.server.network, props.peers)))
const networkFull = computed(
  () => !props.peer && !(form.value.address ?? '').trim() && !nextFreeAddress(props.server.network, props.peers.map((peer) => peer.address)),
)
// the routes of the file: all the traffic, or the networks it reaches. With names, it routes all the networks of the
// server whatever its rules, and asks Authway Server for DNS: only whether it has names changes it
const changesFile = computed(
  () =>
    props.peer !== null &&
    (props.peer.route_all !== form.value.route_all ||
      namesChange.value ||
      (!form.value.route_all && !typedNames.value && accessChanges.value)),
)
// on a server with an IPv6 network, the IPv6 address that comes with the IPv4 one typed
const addressHelp = "The next free address is filled in. It can't be changed after the peer is added, because it's in the configuration file."
const address6Line = computed(() => {
  const address6 = addressError.value ? '' : address6Of(form.value.address ?? '', props.server.network, props.server.network6)
  return address6 ? `IPv6 address: ${address6}` : ''
})

watch(
  () => props.open,
  (open) => {
    if (!open) {
      return
    }
    errors.value = {}
    error.value = ''
    const peer = props.peer
    guard.start(peer)
    form.value = peer
      ? { name: peer.name, enabled: peer.enabled, user_id: peer.user_id, route_all: peer.route_all, device_approval: peer.device_approval }
      : {
          name: '',
          enabled: true,
          user_id: 0,
          route_all: false,
          address: nextFreeAddress(props.server.network, props.peers.map((peer) => peer.address)),
          // the server's choice for its new peers
          device_approval: props.server.device_approval,
        }
    limited.value = (peer?.access.length ?? 0) > 0
    rows.value = peer?.access.length ? rowsOf(peer.access) : [emptyRow()]
  },
)

// a new address: the answer of the server about the old one no longer holds
watch(
  () => form.value.address,
  () => delete errors.value.address,
)

watch(
  () => form.value.user_id,
  (id, old) => {
    // a new peer is named after its user, until the name is typed
    if (props.peer || !id) {
      return
    }
    const user = props.users.find((entry) => entry.id === id)
    const previous = props.users.find((entry) => entry.id === old)
    if (user && (!form.value.name || form.value.name === previous?.username)) {
      form.value.name = user.username
    }
  },
)

async function save() {
  // the ports of a rule, or a rule without its address
  if (addressError.value || (listed.value && rows.value.some((row) => rowProblem(row) !== ''))) {
    error.value = 'Check the fields marked in red.'
    return
  }
  busy.value = true
  errors.value = {}
  error.value = ''
  let again = false
  try {
    // without a login the user isn't asked: a peer keeps the one it had, for when the login comes back
    const input = {
      ...form.value,
      user_id: gated.value ? Number(form.value.user_id) : (props.peer?.user_id ?? 0),
      // only some, with nothing typed: the server says it's required, never all by mistake. Without networks, an
      // empty list is no names
      access: hasNetworks.value ? (limited.value ? (typedAccess.value.length ? typedAccess.value : ['']) : []) : typedAccess.value,
      version: guard.version.value,
    }
    const peer = props.peer ? await api.updatePeer(props.peer.id, input) : await api.createPeer(props.server.id, input)
    notify(props.peer ? `${peer.name} saved.` : `${peer.name} added.`)
    emit('saved', peer, !props.peer)
  } catch (e) {
    const merged = guard.refused(e, typed())
    if (merged) {
      fill(merged.values)
      again = merged.again
      return
    }
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = e.fields
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
</script>

<template>
  <UiDrawer :open="open" :title="peer ? `Edit ${peer.name}` : `Add peer to ${server.name}`" @close="emit('close')">
    <form id="peer-form" class="space-y-6" novalidate @submit.prevent="save">
      <ConflictNotice :conflict="conflict" noun="peer" @theirs="useTheirs" />
      <UiSelect
        v-if="gated"
        v-model="form.user_id"
        label="User"
        :options="userOptions"
        :error="fieldMessage(errors.user_id)"
        help="The user logs in with their password before this peer's traffic gets through."
      />
      <UiNotice v-if="gated && users.length === 0" tone="warning">
        There are no users yet. Add one in <RouterLink to="/users" class="font-medium underline">Users</RouterLink> first.
      </UiNotice>
      <UiInput
        v-model="form.name"
        label="Name"
        placeholder="Alice's laptop"
        :error="fieldMessage(errors.name)"
        help="Usually the device, for example: Alice's laptop."
      />
      <UiToggle v-model="form.route_all" label="Send all traffic through the VPN" :help="routeAllHelp" />
      <fieldset v-if="server.networks.length" class="space-y-2.5">
        <legend class="mb-2 text-sm font-medium">Networks it reaches</legend>
        <label
          v-for="mode in accessModes"
          :key="mode.label"
          class="flex cursor-pointer gap-3 rounded-lg border p-3.5"
          :class="
            limited === mode.value
              ? 'border-sky-600 bg-sky-50/60 ring-1 ring-sky-600 dark:border-sky-400 dark:bg-sky-500/10 dark:ring-sky-400'
              : 'border-slate-200 hover:border-slate-300 dark:border-slate-700'
          "
        >
          <input type="radio" name="access" class="mt-0.5 accent-sky-700" :checked="limited === mode.value" @change="limited = mode.value" />
          <span>
            <span class="block text-sm font-medium">{{ mode.label }}</span>
            <span v-if="!mode.value" class="block font-mono text-sm break-words text-slate-500 dark:text-slate-400">{{ serverNetworks }}</span>
            <span v-else class="block text-sm text-slate-500 dark:text-slate-400">The firewall of the server lets nothing else through.</span>
          </span>
        </label>
        <AccessRules
          v-if="limited"
          v-model="rows"
          label="Addresses, networks and names"
          placeholder="192.168.1.10 or files.corp.lan"
          add-label="Add address, network or name"
          :error="accessError"
          :help="accessHelp"
        />
      </fieldset>
      <AccessRules
        v-else
        v-model="rows"
        label="Sites it reaches by name"
        placeholder="app.example.com"
        add-label="Add name"
        :error="accessError"
        :help="accessHelp"
      />
      <UiNotice v-if="wildcardHint" tone="info">{{ wildcardHint }}</UiNotice>
      <UiNotice v-if="changesFile" tone="info">
        This changes the configuration file. The Authway app gets the new settings at its next login. For the
        WireGuard apps, download the file again.
      </UiNotice>
      <UiToggle
        v-if="bound"
        :model-value="form.device_approval ?? false"
        label="New devices need approval"
        help="The first device that logs in waits until an administrator approves it here, so a copied file and password can't enroll another computer. Off, the first device that logs in is enrolled at once."
        @update:model-value="form.device_approval = $event"
      />
      <UiToggle v-model="form.enabled" label="Enabled" help="A disabled peer keeps its keys but can't connect." />
      <UiInput
        v-if="!peer"
        v-model="form.address as string"
        label="VPN address"
        mono
        :placeholder="`Next free address in ${server.network}`"
        :error="addressError || fieldMessage(errors.address || (networkFull ? 'network_full' : ''))"
        :helper="address6Line"
        :help="addressHelp"
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="peer-form" variant="primary" :loading="busy">{{ peer ? 'Save' : 'Add peer' }}</UiButton>
    </template>
  </UiDrawer>
</template>
