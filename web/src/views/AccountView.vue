<script setup lang="ts">
import { computed, ref } from 'vue'

import { api, ApiError } from '../api'
import UiBadge from '../components/UiBadge.vue'
import UiButton from '../components/UiButton.vue'
import UiInput from '../components/UiInput.vue'
import UiModal from '../components/UiModal.vue'
import { errorMessage, roleLabel, roles } from '../format'
import { checkSession, notify, session } from '../state'
import AuthenticatorSetup from './account/AuthenticatorSetup.vue'
import ChangePasswordForm from './account/ChangePasswordForm.vue'

const section = 'rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900'

const enrolling = ref(false)
const removing = ref(false)
const removePassword = ref('')
const removeError = ref('')
const removeBusy = ref(false)

const roleText = computed(() => roles.find((role) => role.value === session.me?.role)?.description ?? '')
const initials = computed(() => {
  const name = (session.me?.full_name || session.me?.username || '?').trim()
  const words = name.split(/\s+/).filter(Boolean)
  return (words.length > 1 ? words[0][0] + words[words.length - 1][0] : name.slice(0, 2)).toUpperCase()
})

async function enrolled() {
  enrolling.value = false
  await checkSession(true)
  notify('Authenticator turned on. Your other sessions of the web UI are logged out.')
}

function openRemove() {
  removePassword.value = ''
  removeError.value = ''
  removing.value = true
}

async function removeTotp() {
  removeError.value = ''
  removeBusy.value = true
  try {
    await api.removeMyTotp(removePassword.value)
    removing.value = false
    removePassword.value = ''
    await checkSession(true)
    notify('Authenticator removed: the next logins ask only for the password.')
  } catch (e) {
    removeError.value = e instanceof ApiError && e.code === 'validation' ? 'Wrong password.' : errorMessage(e)
  } finally {
    removeBusy.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-3xl space-y-8">
    <div>
      <h1 class="text-2xl font-semibold tracking-tight">Your account</h1>
      <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">How you log in to this web UI.</p>
    </div>

    <section :class="section">
      <div class="flex flex-wrap items-center gap-4">
        <span
          class="flex size-14 shrink-0 items-center justify-center rounded-full bg-sky-100 text-lg font-semibold text-sky-800 dark:bg-sky-500/15 dark:text-sky-300"
          aria-hidden="true"
        >
          {{ initials }}
        </span>
        <div class="min-w-0 flex-1">
          <p class="truncate text-lg font-semibold">{{ session.me?.full_name || session.me?.username }}</p>
          <p v-if="session.me?.full_name" class="truncate text-sm text-slate-500 dark:text-slate-400">{{ session.me.username }}</p>
        </div>
        <UiBadge tone="sky">{{ roleLabel(session.me?.role ?? 'viewer') }}</UiBadge>
      </div>
      <p class="mt-4 text-sm text-slate-600 dark:text-slate-300">{{ roleText }}</p>
      <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Another Administrator changes your role, in Administrators.</p>
    </section>

    <section :class="section">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <h2 class="text-base font-semibold">Authenticator app</h2>
          <UiBadge :tone="session.me?.totp ? 'green' : 'gray'" dot>{{ session.me?.totp ? 'On' : 'Off' }}</UiBadge>
        </div>
        <div v-if="!enrolling" class="flex gap-2">
          <UiButton size="sm" icon="shield" @click="enrolling = true">{{ session.me?.totp ? 'Replace' : 'Set up' }}</UiButton>
          <UiButton v-if="session.me?.totp && !session.me.require_admin_mfa" size="sm" variant="danger" @click="openRemove">
            Remove
          </UiButton>
        </div>
      </div>
      <p class="mt-2 text-sm text-slate-600 dark:text-slate-300">
        <template v-if="session.me?.totp">The login asks for a code of the app after the password.</template>
        <template v-else>The login asks only for the password. With an app, a stolen password isn't enough.</template>
      </p>
      <p v-if="session.me?.totp && session.me.require_admin_mfa" class="mt-1 text-xs text-slate-500 dark:text-slate-400">
        The settings require an authenticator of every administrator: yours can be replaced, not removed.
      </p>
      <div v-if="enrolling" class="mt-4 rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <AuthenticatorSetup cancellable @done="enrolled" @cancel="enrolling = false" />
      </div>
    </section>

    <section :class="section">
      <h2 class="text-base font-semibold">Password</h2>
      <div class="mt-4">
        <ChangePasswordForm @done="notify('Password changed. The other sessions of the web UI are logged out.')" />
      </div>
    </section>

    <section :class="[section, 'text-sm']">
      <h2 class="text-base font-semibold">Locked out?</h2>
      <p class="mt-2 text-slate-600 dark:text-slate-300">
        Another Administrator can give you a new password or remove your authenticator, in Administrators. Or, on the Docker
        host:
      </p>
      <pre class="mt-2 overflow-x-auto rounded-md bg-slate-100 p-3 font-mono text-xs dark:bg-slate-800">docker exec authway-server authway-server reset-admin-password {{ session.me?.username }}
docker exec authway-server authway-server reset-admin-mfa {{ session.me?.username }}</pre>
    </section>

    <UiModal :open="removing" title="Remove your authenticator?" @close="removing = false">
      <form id="remove-totp" class="space-y-4" novalidate @submit.prevent="removeTotp">
        <p class="text-sm">The next logins ask only for the password. Type it to go on.</p>
        <UiInput v-model="removePassword" label="Your password" type="password" autocomplete="current-password" :error="removeError" />
      </form>
      <template #footer>
        <UiButton @click="removing = false">Cancel</UiButton>
        <UiButton type="submit" form="remove-totp" variant="danger" :loading="removeBusy">Remove</UiButton>
      </template>
    </UiModal>
  </div>
</template>
