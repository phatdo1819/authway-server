<script setup lang="ts">
import { useRouter } from 'vue-router'

import { api } from '../api'
import { checkSession, notify, session } from '../state'
import AuthenticatorSetup from './account/AuthenticatorSetup.vue'
import ChangePasswordForm from './account/ChangePasswordForm.vue'

// what the server asks before the rest of the web UI: a new password, then an authenticator
const router = useRouter()

async function next(message: string) {
  notify(message)
  await checkSession(true)
  if (!session.me?.setup) {
    router.replace('/servers')
  }
}

async function logout() {
  try {
    await api.logout()
  } catch {
    // the session ends anyway when the browser closes
  }
  session.me = null
  router.replace({ name: 'login' })
}
</script>

<template>
  <main class="flex min-h-screen items-center justify-center px-4 py-12">
    <div class="w-full max-w-md">
      <div class="mb-6 flex flex-col items-center text-center">
        <img src="/icon.svg" alt="" width="48" height="48" />
        <h1 class="mt-4 text-2xl font-semibold tracking-tight">
          {{ session.me?.setup === 'mfa' ? 'Set up your authenticator' : 'Choose your password' }}
        </h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          <template v-if="session.me?.setup === 'mfa'">
            Every administrator logs in with a code of an authenticator app too: set yours up to go on.
          </template>
          <template v-else>
            The current password of <span class="font-medium">{{ session.me?.username }}</span> was given to you: choose one that only you know.
          </template>
        </p>
      </div>
      <section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <AuthenticatorSetup v-if="session.me?.setup === 'mfa'" @done="next('Authenticator set up. The next logins ask for its code.')" />
        <ChangePasswordForm v-else @done="next('Password changed.')" />
      </section>
      <button
        type="button"
        class="mt-4 w-full text-center text-sm text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
        @click="logout"
      >
        Log out
      </button>
    </div>
  </main>
</template>
