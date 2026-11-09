<script setup lang="ts">
import { ref } from 'vue'

import { api, ApiError, type TotpSetup } from '../../api'
import QrCode from '../../components/QrCode.vue'
import UiButton from '../../components/UiButton.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import { errorMessage, fieldMessage } from '../../format'
import { session } from '../../state'

// the authenticator of the administrator logged in: the password first, so a session left open alone can't put
// another authenticator on the account; saved when its first code is right
const emit = defineEmits<{ done: []; cancel: [] }>()
defineProps<{ cancellable?: boolean }>()

const password = ref('')
const passwordError = ref('')
const setup = ref<TotpSetup | null>(null)
const code = ref('')
const error = ref('')
const codeError = ref('')
const busy = ref(false)

async function start() {
  error.value = passwordError.value = codeError.value = ''
  code.value = ''
  if (!password.value) {
    passwordError.value = 'Type your password.'
    return
  }
  busy.value = true
  try {
    setup.value = await api.startTotp(password.value)
    password.value = ''
  } catch (e) {
    if (e instanceof ApiError && e.code === 'validation') {
      passwordError.value = fieldMessage(e.fields.password)
    } else {
      error.value = errorMessage(e)
    }
  } finally {
    busy.value = false
  }
}

function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim()
}

async function confirm() {
  error.value = codeError.value = ''
  if (!/^\d{6}$/.test(code.value.trim())) {
    codeError.value = 'Type the 6 digits of the app.'
    return
  }
  busy.value = true
  try {
    await api.confirmTotp(code.value.trim())
    emit('done')
  } catch (e) {
    if (e instanceof ApiError && e.code === 'validation') {
      codeError.value = fieldMessage(e.fields.code)
    } else if (e instanceof ApiError && e.code === 'setup_expired') {
      // the password again, for a new secret
      setup.value = null
      error.value = errorMessage(e)
    } else {
      error.value = errorMessage(e)
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="space-y-4 text-sm">
    <form v-if="!setup" class="space-y-4" novalidate @submit.prevent="start">
      <p class="text-slate-600 dark:text-slate-300">Type your password to set up an authenticator app.</p>
      <UiInput v-model="password" label="Your password" type="password" autocomplete="current-password" :error="passwordError" />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
      <div class="flex justify-end gap-3">
        <UiButton v-if="cancellable" @click="emit('cancel')">Cancel</UiButton>
        <UiButton type="submit" variant="primary" :loading="busy">Continue</UiButton>
      </div>
    </form>
    <template v-else>
      <ol class="list-decimal space-y-1 pl-5 text-slate-600 dark:text-slate-300">
        <li>Scan this code with an authenticator app, such as Google Authenticator, Microsoft Authenticator or 2FAS.</li>
        <li>Type the code that the app shows.</li>
      </ol>
      <QrCode :text="setup.uri" :label="`QR code of the authenticator of ${session.me?.username ?? ''}`" />
      <div>
        <p class="text-xs text-slate-500">Or type this key in the app:</p>
        <p class="mt-1 font-mono text-sm break-all select-all">{{ grouped(setup.secret) }}</p>
      </div>
      <form class="space-y-4" novalidate @submit.prevent="confirm">
        <UiInput v-model="code" label="Code of the app" autocomplete="one-time-code" placeholder="123456" mono :error="codeError" />
        <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
        <div class="flex justify-end gap-3">
          <UiButton v-if="cancellable" @click="emit('cancel')">Cancel</UiButton>
          <UiButton type="submit" variant="primary" :loading="busy">Turn on</UiButton>
        </div>
      </form>
    </template>
  </div>
</template>
