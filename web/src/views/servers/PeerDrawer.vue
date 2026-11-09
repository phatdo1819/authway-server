<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { address6Of, addressProblem, nextFreeAddress } from '../../addresses'
import { api, ApiError, type Peer, type PeerInput, type Server, type User } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { errorMessage, fieldMessage } from '../../format'
import { notify } from '../../state'

const props = defineProps<{ open: boolean; server: Server; peer: Peer | null; peers: Peer[]; users: User[] }>()
const emit = defineEmits<{ close: []; saved: [Peer, boolean] }>()

const form = ref<PeerInput>({ name: '', enabled: true, user_id: 0, route_all: false, address: '' })
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)

const gated = computed(() => props.server.auth_mode !== 'key')
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
const changesFile = computed(() => props.peer !== null && props.peer.route_all !== form.value.route_all)
// on a server with an IPv6 network, the IPv6 address that comes with the IPv4 one typed
const addressHelp = computed(() => {
  const help = "The next free address is filled in. It can't change once the peer is added: its configuration file has it."
  const address6 = addressError.value ? '' : address6Of(form.value.address ?? '', props.server.network, props.server.network6)
  return address6 ? `Its IPv6 address: ${address6}. ${help}` : help
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
    form.value = peer
      ? { name: peer.name, enabled: peer.enabled, user_id: peer.user_id, route_all: peer.route_all }
      : {
          name: '',
          enabled: true,
          user_id: 0,
          route_all: false,
          address: nextFreeAddress(props.server.network, props.peers.map((peer) => peer.address)),
        }
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
  if (addressError.value) {
    error.value = 'Check the fields in red.'
    return
  }
  busy.value = true
  errors.value = {}
  error.value = ''
  try {
    // without a login the user isn't asked: a peer keeps the one it had, for when the login comes back
    const input = { ...form.value, user_id: gated.value ? Number(form.value.user_id) : (props.peer?.user_id ?? 0) }
    const peer = props.peer ? await api.updatePeer(props.peer.id, input) : await api.createPeer(props.server.id, input)
    notify(props.peer ? `${peer.name} saved.` : `${peer.name} added.`)
    emit('saved', peer, !props.peer)
  } catch (e) {
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = e.fields
    }
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UiDrawer :open="open" :title="peer ? `Edit ${peer.name}` : `Add peer to ${server.name}`" @close="emit('close')">
    <form id="peer-form" class="space-y-6" novalidate @submit.prevent="save">
      <UiSelect
        v-if="gated"
        v-model="form.user_id"
        label="User"
        :options="userOptions"
        :error="fieldMessage(errors.user_id)"
        helper="The user logs in with their password before the traffic of this peer passes."
      />
      <UiNotice v-if="gated && users.length === 0" tone="warning">
        There is no user yet: add one in <RouterLink to="/users" class="font-medium underline">Users</RouterLink> first.
      </UiNotice>
      <UiInput v-model="form.name" label="Name" :error="fieldMessage(errors.name)" helper="For example the device: Alice laptop." />
      <UiToggle
        v-model="form.route_all"
        label="Send all the traffic through the tunnel"
        description="The internet traffic of the device goes out from this server too. Otherwise only the networks of the server do."
      />
      <UiNotice v-if="changesFile" tone="info">
        This changes the configuration file: download it again for the device.
      </UiNotice>
      <UiToggle v-model="form.enabled" label="Enabled" description="A disabled peer keeps its keys but can't connect." />
      <UiInput
        v-if="!peer"
        v-model="form.address as string"
        label="Address in the tunnel"
        mono
        :placeholder="`The next free one in ${server.network}`"
        :error="addressError || fieldMessage(errors.address || (networkFull ? 'network_full' : ''))"
        :helper="addressHelp"
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="peer-form" variant="primary" :loading="busy">{{ peer ? 'Save' : 'Add peer' }}</UiButton>
    </template>
  </UiDrawer>
</template>
