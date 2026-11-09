<script setup lang="ts">
import type { TotpSetup, User } from '../../api'
import QrCode from '../../components/QrCode.vue'
import UiButton from '../../components/UiButton.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'

defineProps<{ data: { user: User; setup: TotpSetup } | null }>()
const emit = defineEmits<{ close: [] }>()

function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim()
}
</script>

<template>
  <UiModal :open="data !== null" :title="`Authenticator of ${data?.user.username ?? ''}`" @close="emit('close')">
    <div v-if="data" class="space-y-4">
      <p>The user scans this code with an authenticator app, such as Google Authenticator, Microsoft Authenticator or 2FAS.</p>
      <QrCode :text="data.setup.uri" :label="`QR code of the authenticator of ${data.user.username}`" />
      <div>
        <p class="text-xs text-slate-500">Or types this key in the app:</p>
        <p class="mt-1 font-mono text-sm break-all select-all">{{ grouped(data.setup.secret) }}</p>
      </div>
      <UiNotice tone="warning">This code is shown only now. To see a new one later, set up the authenticator again.</UiNotice>
    </div>
    <template #footer>
      <UiButton variant="primary" @click="emit('close')">Done</UiButton>
    </template>
  </UiModal>
</template>
