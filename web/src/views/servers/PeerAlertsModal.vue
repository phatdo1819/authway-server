<script setup lang="ts">
import { ref, watch } from 'vue'

import { api, type Alert, type Peer } from '../../api'
import UiBadge from '../../components/UiBadge.vue'
import UiButton from '../../components/UiButton.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import { alertKind, dateTime, errorMessage } from '../../format'
import { canManage, notify } from '../../state'

const props = defineProps<{ peer: Peer | null }>()
const emit = defineEmits<{ close: []; cleared: [] }>()

const alerts = ref<Alert[]>([])
const busy = ref(false)

watch(
  () => props.peer,
  async (peer) => {
    alerts.value = []
    if (!peer) {
      return
    }
    try {
      alerts.value = await api.peerAlerts(peer.id)
    } catch (e) {
      notify(errorMessage(e), 'error')
    }
  },
)

async function clear() {
  if (!props.peer) {
    return
  }
  busy.value = true
  try {
    await api.clearPeerAlerts(props.peer.id)
    notify(props.peer.blocked ? `${props.peer.name} is unblocked.` : 'Alerts cleared.')
    emit('cleared')
    emit('close')
  } catch (e) {
    notify(errorMessage(e), 'error')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UiModal :open="peer !== null" :title="`Alerts of ${peer?.name ?? ''}`" wide @close="emit('close')">
    <div class="space-y-4">
      <UiNotice v-if="peer?.blocked" tone="error" title="This peer is blocked">
        Its configuration looked used by two devices at once. If the user shared or lost it, give the peer
        <strong>New keys</strong> and the user the new file. Otherwise clear the alerts to unblock it.
      </UiNotice>
      <ul class="divide-y divide-slate-200 dark:divide-slate-700">
        <li v-for="alert in alerts" :key="alert.id" class="py-3">
          <div class="flex flex-wrap items-center gap-2">
            <UiBadge :tone="alert.kind === 'copy' ? 'red' : 'amber'">{{ alertKind(alert.kind) }}</UiBadge>
            <span class="text-slate-500">{{ dateTime(alert.at) }}</span>
          </div>
          <p class="mt-1">
            <template v-if="alert.username">User {{ alert.username }}, from</template><template v-else>From</template>
            <span class="font-mono"> {{ alert.addresses.join(', ') || 'an unknown IP' }}</span>
          </p>
        </li>
        <li v-if="!alerts.length" class="py-3 text-slate-500">No alert.</li>
      </ul>
    </div>
    <template #footer>
      <UiButton @click="emit('close')">Close</UiButton>
      <UiButton v-if="canManage()" variant="primary" :loading="busy" @click="clear">
        {{ peer?.blocked ? 'Clear alerts and unblock' : 'Clear alerts' }}
      </UiButton>
    </template>
  </UiModal>
</template>
