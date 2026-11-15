<script setup lang="ts">
import { ref, watch } from 'vue'

import { api, ApiError, type TotpSetup, type User } from '../../api'
import QrCode from '../../components/QrCode.vue'
import UiButton from '../../components/UiButton.vue'
import UiInput from '../../components/UiInput.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import { errorMessage, fieldMessage } from '../../format'

const props = defineProps<{ data: { user: User; setup: TotpSetup } | null }>()
// checked: a code of the app worked, the key counts as in use
const emit = defineEmits<{ close: []; checked: [] }>()

function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim()
}

// the check of a code, optional: it shows the user scanned the right QR code
const code = ref('')
const codeError = ref('')
const checking = ref(false)
const checked = ref(false)

watch(
  () => props.data,
  () => {
    code.value = ''
    codeError.value = ''
    checked.value = false
  },
)

async function check() {
  const typed = code.value.replace(/\s+/g, '')
  if (!/^[0-9]{6}$/.test(typed)) {
    codeError.value = 'Enter the 6-digit code shown in the app.'
    return
  }
  if (!props.data) {
    return
  }
  checking.value = true
  codeError.value = ''
  try {
    await api.checkTotp(props.data.user.id, typed)
    checked.value = true
    emit('checked')
  } catch (e) {
    const field = e instanceof ApiError ? e.fields.code : undefined
    codeError.value = field ? fieldMessage(field) : errorMessage(e)
  } finally {
    checking.value = false
  }
}
</script>

<template>
  <UiModal :open="data !== null" :title="`Authenticator of ${data?.user.username ?? ''}`" @close="emit('close')">
    <div v-if="data" class="space-y-5">
      <ol class="list-decimal space-y-1 pl-5">
        <li>The user scans this QR code with an authenticator app, such as Google Authenticator, Microsoft Authenticator or 2FAS.</li>
        <li>Optional: enter the code the app shows to make sure it worked. Their first VPN login with a code confirms it too.</li>
      </ol>
      <QrCode :text="data.setup.uri" :label="`Authenticator QR code for ${data.user.username}`" />
      <div>
        <p class="text-xs text-slate-500 dark:text-slate-400">Or enter this key in the app manually:</p>
        <p class="mt-1 font-mono text-sm break-all select-all">{{ grouped(data.setup.secret) }}</p>
      </div>
      <UiNotice v-if="checked" tone="info">It works. The app shows the right codes, and the authenticator is now marked as in use.</UiNotice>
      <form v-else class="flex items-end gap-2" @submit.prevent="check">
        <div class="flex-1">
          <UiInput v-model="code" label="Code from the app" autocomplete="one-time-code" placeholder="123456" mono :error="codeError" />
        </div>
        <UiButton type="submit" :loading="checking">Check</UiButton>
      </form>
      <UiNotice tone="warning">This QR code is only shown once. If it's lost, create a new one from the Users list.</UiNotice>
    </div>
    <template #footer>
      <UiButton variant="primary" @click="emit('close')">Done</UiButton>
    </template>
  </UiModal>
</template>
