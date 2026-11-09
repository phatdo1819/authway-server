<script setup lang="ts">
import { ref, watch } from 'vue'

import { api, type Peer, type Server } from '../../api'
import QrCode from '../../components/QrCode.vue'
import UiButton from '../../components/UiButton.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import { errorMessage } from '../../format'
import { download, notify } from '../../state'

// the configuration file of a peer, with its QR code for the phones
const props = defineProps<{ peer: Peer | null; server: Server }>()
const emit = defineEmits<{ close: [] }>()

const file = ref<{ name: string; text: string } | null>(null)
const showQr = ref(false)

watch(
  () => props.peer,
  async (peer) => {
    file.value = null
    showQr.value = false
    if (!peer) {
      return
    }
    try {
      file.value = await api.peerConfig(peer.id)
    } catch (e) {
      notify(errorMessage(e), 'error')
      emit('close')
    }
  },
)

function save() {
  if (file.value) {
    download(file.value.name, file.value.text)
  }
}
</script>

<template>
  <UiModal :open="peer !== null" :title="`Configuration of ${peer?.name ?? ''}`" wide @close="emit('close')">
    <div class="space-y-4">
      <UiNotice tone="warning">
        The file and the QR code hold the private key of the peer: whoever has them can connect as this peer. Give them
        only to its user.
      </UiNotice>
      <p v-if="server.auth_mode !== 'key'">
        After connecting, the user logs in with Authway, or on
        <span class="font-mono">{{ server.login_url }}</span> in a browser.
      </p>
      <div v-if="showQr && file" class="space-y-2 text-center">
        <QrCode :text="file.text" :label="`QR code of the configuration of ${peer?.name}`" />
        <p class="text-xs text-slate-500">Scan it with the WireGuard app of the phone: Add a tunnel, then Scan from QR code.</p>
      </div>
    </div>
    <template #footer>
      <UiButton @click="emit('close')">Close</UiButton>
      <UiButton icon="qr" :disabled="!file" @click="showQr = !showQr">{{ showQr ? 'Hide' : 'Show' }} QR code</UiButton>
      <UiButton variant="primary" icon="download" :disabled="!file" @click="save">Download</UiButton>
    </template>
  </UiModal>
</template>
