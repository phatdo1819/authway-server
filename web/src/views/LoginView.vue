<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, ApiError } from '../api'
import UiButton from '../components/UiButton.vue'
import UiInput from '../components/UiInput.vue'
import UiNotice from '../components/UiNotice.vue'
import { errorMessage } from '../format'
import { checkSession } from '../state'

const router = useRouter()
const route = useRoute()
const username = ref('')
const password = ref('')
const code = ref('')
// the password is right, the account has an authenticator: the second step asks a code
const needsCode = ref(false)
const error = ref('')
const busy = ref(false)

async function submit() {
  if (!username.value || !password.value) {
    error.value = 'Enter your username and password.'
    return
  }
  if (needsCode.value && !/^\d{6}$/.test(code.value.trim())) {
    error.value = 'Type the 6 digits of your authenticator app.'
    return
  }
  busy.value = true
  error.value = ''
  try {
    const result = await api.login(username.value, password.value, needsCode.value ? code.value.trim() : '')
    password.value = code.value = ''
    await checkSession(true)
    if (result.setup) {
      router.replace({ name: 'setup' })
      return
    }
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') && !route.query.next.startsWith('//') ? route.query.next : '/servers'
    router.replace(next)
  } catch (e) {
    if (e instanceof ApiError && e.code === 'otp_required') {
      needsCode.value = true
      await nextTick()
      document.getElementById('login-code')?.querySelector('input')?.focus()
      return
    }
    code.value = ''
    if (e instanceof ApiError && e.code === 'invalid_credentials') {
      // back to the first step: the password was wrong
      needsCode.value = false
      password.value = ''
    }
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

function back() {
  needsCode.value = false
  password.value = code.value = error.value = ''
}
</script>

<template>
  <main class="flex min-h-screen items-center justify-center px-4 py-12">
    <div class="w-full max-w-sm">
      <div class="mb-8 flex flex-col items-center text-center">
        <img src="/icon.svg" alt="" width="56" height="56" />
        <h1 class="mt-4 text-2xl font-semibold tracking-tight">Authway Server</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">WireGuard with login</p>
      </div>
      <form
        class="space-y-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900"
        novalidate
        @submit.prevent="submit"
      >
        <UiNotice v-if="route.query.restored && !needsCode" tone="info">
          The configuration is restored. Log in with an administrator of the backup.
        </UiNotice>
        <template v-if="!needsCode">
          <UiInput v-model="username" label="Username" autocomplete="username" />
          <UiInput v-model="password" label="Password" type="password" autocomplete="current-password" />
        </template>
        <template v-else>
          <p class="text-sm text-slate-600 dark:text-slate-300">
            Open the authenticator app of <span class="font-medium">{{ username }}</span> and type its code.
          </p>
          <div id="login-code">
            <UiInput v-model="code" label="Authenticator code" autocomplete="one-time-code" placeholder="123456" mono />
          </div>
        </template>
        <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
        <UiButton type="submit" variant="primary" :loading="busy" class="w-full">{{ needsCode ? 'Verify' : 'Log in' }}</UiButton>
        <button
          v-if="needsCode"
          type="button"
          class="w-full text-center text-sm text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
          @click="back"
        >
          Use another account
        </button>
      </form>
    </div>
  </main>
</template>
