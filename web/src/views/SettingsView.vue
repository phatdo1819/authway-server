<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { api, ApiError, type PasswordPolicy } from '../api'
import UiButton from '../components/UiButton.vue'
import UiInput from '../components/UiInput.vue'
import UiNotice from '../components/UiNotice.vue'
import UiToggle from '../components/UiToggle.vue'
import { adminMinPassword, errorMessage, fieldMessage, policyText } from '../format'
import { confirm, isAdmin, notify, session } from '../state'
import BackupSection from './settings/BackupSection.vue'

const section = 'rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900'
const canEdit = computed(isAdmin)

const publicHost = ref('')
const hostError = ref('')
const savingHost = ref(false)

const policy = ref<PasswordPolicy>({ min_length: 10, require_lower: true, require_upper: true, require_digit: true, require_symbol: false })
const minLength = ref<string | number>(10)
const policyError = ref('')
const savingPolicy = ref(false)

const requireMfa = ref(false)
const mfaError = ref('')
const savingMfa = ref(false)

const enrollHours = ref<string | number>(72)
const enrollError = ref('')
const savingEnroll = ref(false)

const historyDays = ref<string | number>(90)
const savedDays = ref(90)
const historyError = ref('')
const savingHistory = ref(false)

const lengthHelper = computed(
  () => `From 8 to 64. The administrators need at least ${adminMinPassword}, whatever this says.`,
)

onMounted(async () => {
  try {
    const settings = await api.settings()
    publicHost.value = settings.public_host
    policy.value = { ...settings.password_policy }
    minLength.value = settings.password_policy.min_length
    requireMfa.value = settings.require_admin_mfa
    enrollHours.value = settings.enroll_hours
    historyDays.value = savedDays.value = settings.history_days
  } catch (e) {
    notify(errorMessage(e), 'error')
  }
})

async function saveHistory() {
  historyError.value = ''
  const days = Number(historyDays.value)
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    historyError.value = 'Use from 1 to 3650 days (10 years).'
    return
  }
  // fewer days delete the older rows at once: there is no way back
  const unit = days === 1 ? 'day' : 'days'
  if (
    days < savedDays.value &&
    !(await confirm(
      `Keep only ${days} ${unit}?`,
      `The logins, the connections, the events and the alerts older than ${days} ${unit} are deleted within a few seconds, and can't come back.`,
      'Delete the older history',
    ))
  ) {
    return
  }
  savingHistory.value = true
  try {
    historyDays.value = savedDays.value = (await api.saveSettings({ history_days: days })).history_days
    notify('Settings saved.')
  } catch (e) {
    historyError.value = e instanceof ApiError && e.fields.history_days ? 'Use from 1 to 3650 days (10 years).' : errorMessage(e)
  } finally {
    savingHistory.value = false
  }
}

async function saveEnroll() {
  savingEnroll.value = true
  enrollError.value = ''
  try {
    enrollHours.value = (await api.saveSettings({ enroll_hours: Number(enrollHours.value) })).enroll_hours
    notify('Settings saved. They apply to the enrollments opened from now on.')
  } catch (e) {
    enrollError.value = e instanceof ApiError && e.fields.enroll_hours ? 'Use from 1 to 720 hours (30 days).' : errorMessage(e)
  } finally {
    savingEnroll.value = false
  }
}

async function saveHost() {
  savingHost.value = true
  hostError.value = ''
  try {
    publicHost.value = (await api.saveSettings({ public_host: publicHost.value })).public_host
    notify('Settings saved.')
  } catch (e) {
    hostError.value = e instanceof ApiError ? fieldMessage(e.fields.public_host) || errorMessage(e) : errorMessage(e)
  } finally {
    savingHost.value = false
  }
}

async function savePolicy() {
  savingPolicy.value = true
  policyError.value = ''
  try {
    const saved = await api.saveSettings({ password_policy: { ...policy.value, min_length: Number(minLength.value) } })
    policy.value = { ...saved.password_policy }
    minLength.value = saved.password_policy.min_length
    if (session.me) {
      session.me.password_policy = saved.password_policy
    }
    notify('Password policy saved. It applies to the passwords chosen from now on.')
  } catch (e) {
    policyError.value = e instanceof ApiError && e.fields.min_length ? 'Use a length from 8 to 64.' : errorMessage(e)
  } finally {
    savingPolicy.value = false
  }
}

async function saveMfa() {
  mfaError.value = ''
  if (requireMfa.value) {
    const ok = await confirm(
      'Require an authenticator of every administrator?',
      'The administrators without one set it up at their next request, before anything else.',
      'Require',
      false,
    )
    if (!ok) {
      return
    }
  }
  savingMfa.value = true
  try {
    const saved = await api.saveSettings({ require_admin_mfa: requireMfa.value })
    requireMfa.value = saved.require_admin_mfa
    if (session.me) {
      session.me.require_admin_mfa = saved.require_admin_mfa
    }
    notify('Settings saved.')
  } catch (e) {
    mfaError.value = e instanceof ApiError && e.fields.require_admin_mfa ? fieldMessage(e.fields.require_admin_mfa) : errorMessage(e)
  } finally {
    savingMfa.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-3xl space-y-8">
    <div>
      <h1 class="text-2xl font-semibold tracking-tight">Settings</h1>
      <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
        <template v-if="!canEdit">Only an Administrator changes the settings of the server.</template>
        Your password and your authenticator app are in
        <RouterLink :to="{ name: 'account' }" class="font-medium text-sky-700 hover:underline dark:text-sky-400">Your account</RouterLink>.
      </p>
    </div>

    <section :class="section">
      <h2 class="text-base font-semibold">New servers</h2>
      <form class="mt-4 space-y-4" novalidate @submit.prevent="saveHost">
        <UiInput
          v-model="publicHost"
          label="Public address of this host"
          placeholder="vpn.example.com"
          :error="hostError"
          :disabled="!canEdit"
          helper="The address that new servers propose to their peers. The servers keep their own: edit them to change it."
        />
        <div v-if="canEdit" class="flex justify-end">
          <UiButton type="submit" variant="primary" :loading="savingHost">Save</UiButton>
        </div>
      </form>
    </section>

    <section :class="section">
      <h2 class="text-base font-semibold">Device binding</h2>
      <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
        On the servers that ask for it, a new peer, a peer with new keys or another user enrolls the first device that logs
        in, during this time. After it, nobody logs in until an administrator allows a device.
      </p>
      <form class="mt-4 space-y-4" novalidate @submit.prevent="saveEnroll">
        <div class="max-w-48">
          <UiInput v-model="enrollHours" label="Enrollment time (hours)" type="number" :error="enrollError" :disabled="!canEdit" />
        </div>
        <p class="-mt-2 text-xs text-slate-500 dark:text-slate-400">From 1 to 720 (30 days). 72 by default.</p>
        <div v-if="canEdit" class="flex justify-end">
          <UiButton type="submit" variant="primary" :loading="savingEnroll">Save</UiButton>
        </div>
      </form>
    </section>

    <section :class="section">
      <h2 class="text-base font-semibold">History</h2>
      <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
        How long Activity keeps the logins, the connections, the events and the alerts. The older ones are deleted every
        hour. The backups don't have the history.
      </p>
      <form class="mt-4 space-y-4" novalidate @submit.prevent="saveHistory">
        <div class="max-w-48">
          <UiInput v-model="historyDays" label="Keep the history (days)" type="number" :error="historyError" :disabled="!canEdit" />
        </div>
        <p class="-mt-2 text-xs text-slate-500 dark:text-slate-400">From 1 to 3650 (10 years). 90 by default.</p>
        <div v-if="canEdit" class="flex justify-end">
          <UiButton type="submit" variant="primary" :loading="savingHistory">Save</UiButton>
        </div>
      </form>
    </section>

    <section :class="section">
      <h2 class="text-base font-semibold">Password policy</h2>
      <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
        For the passwords that the users and the administrators get from now on. The current ones keep working until they
        change.
      </p>
      <form class="mt-4 space-y-4" novalidate @submit.prevent="savePolicy">
        <div class="max-w-48">
          <UiInput v-model="minLength" label="Minimum length" type="number" :disabled="!canEdit" />
        </div>
        <p class="-mt-2 text-xs text-slate-500 dark:text-slate-400">{{ lengthHelper }}</p>
        <UiToggle v-model="policy.require_lower" label="A lowercase letter" :disabled="!canEdit" />
        <UiToggle v-model="policy.require_upper" label="An uppercase letter" :disabled="!canEdit" />
        <UiToggle v-model="policy.require_digit" label="A digit" :disabled="!canEdit" />
        <UiToggle v-model="policy.require_symbol" label="A symbol or a space" :disabled="!canEdit" />
        <p class="text-sm text-slate-600 dark:text-slate-300">
          Users: {{ policyText({ ...policy, min_length: Number(minLength) || policy.min_length }) }}
        </p>
        <UiNotice v-if="policyError" tone="error">{{ policyError }}</UiNotice>
        <div v-if="canEdit" class="flex justify-end">
          <UiButton type="submit" variant="primary" :loading="savingPolicy">Save</UiButton>
        </div>
      </form>
    </section>

    <section :class="section">
      <h2 class="text-base font-semibold">Login of the administrators</h2>
      <form class="mt-4 space-y-4" novalidate @submit.prevent="saveMfa">
        <UiToggle
          v-model="requireMfa"
          label="Require an authenticator app"
          :disabled="!canEdit"
          description="Every administrator logs in with a code of an authenticator app too. The ones without one set it up before anything else, and nobody can remove theirs."
        />
        <UiNotice v-if="mfaError" tone="error">{{ mfaError }}</UiNotice>
        <div v-if="canEdit" class="flex justify-end">
          <UiButton type="submit" variant="primary" :loading="savingMfa">Save</UiButton>
        </div>
      </form>
    </section>

    <BackupSection v-if="canEdit" />
  </div>
</template>
