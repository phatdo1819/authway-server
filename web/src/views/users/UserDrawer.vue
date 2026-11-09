<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, ApiError, type User, type UserInput } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiToggle from '../../components/UiToggle.vue'
import { errorMessage, fieldMessage, generatePassword, policyText } from '../../format'
import { notify, session } from '../../state'

const props = defineProps<{ open: boolean; user: User | null }>()
const emit = defineEmits<{ close: []; saved: [User] }>()

const form = ref<UserInput>({ username: '', full_name: '', password: '', disabled: false })
const confirmPassword = ref('')
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)
// a password made here, shown so that it can be given to the user
const generated = ref('')
const policy = computed(() => policyText(session.me?.password_policy))

function generate() {
  generated.value = generatePassword(session.me?.password_policy)
  form.value.password = confirmPassword.value = generated.value
}

async function copyGenerated() {
  try {
    await navigator.clipboard.writeText(generated.value)
    notify('Password copied.')
  } catch {
    notify('Select the password and copy it.', 'error')
  }
}

watch(
  () => props.open,
  (open) => {
    if (!open) {
      return
    }
    errors.value = {}
    error.value = ''
    confirmPassword.value = ''
    generated.value = ''
    const user = props.user
    form.value = user
      ? { username: user.username, full_name: user.full_name, password: '', disabled: user.disabled }
      : { username: '', full_name: '', password: '', disabled: false }
  },
)

async function save() {
  errors.value = {}
  error.value = ''
  if (form.value.password !== confirmPassword.value) {
    errors.value = { confirm: 'mismatch' }
    return
  }
  busy.value = true
  try {
    const user = props.user ? await api.updateUser(props.user.id, form.value) : await api.createUser(form.value)
    notify(props.user ? `${user.username} saved.` : `${user.username} added.`)
    emit('saved', user)
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
  <UiDrawer :open="open" :title="user ? `Edit ${user.username}` : 'Add user'" @close="emit('close')">
    <form id="user-form" class="space-y-6" novalidate @submit.prevent="save">
      <UiInput
        v-model="form.username"
        label="Username"
        autocomplete="off"
        :error="fieldMessage(errors.username)"
        helper="Letters, digits and . _ @ -. The user types it on the login page."
      />
      <UiInput v-model="form.full_name" label="Full name" optional :error="fieldMessage(errors.full_name)" />
      <UiInput
        v-model="form.password"
        :label="user ? 'New password' : 'Password'"
        type="password"
        autocomplete="new-password"
        :optional="Boolean(user)"
        :error="fieldMessage(errors.password)"
        :helper="user ? `Leave it empty to keep the current one. A new password logs the user out. ${policy}` : policy"
      />
      <UiInput
        v-model="confirmPassword"
        label="Type the password again"
        type="password"
        autocomplete="new-password"
        :error="errors.confirm ? 'The two passwords differ.' : ''"
      />
      <div class="space-y-2">
        <UiButton size="sm" icon="key" @click="generate">Generate a password</UiButton>
        <div v-if="generated" class="flex items-center gap-2 rounded-md bg-slate-100 px-3 py-2 dark:bg-slate-800">
          <span class="min-w-0 flex-1 font-mono text-sm break-all select-all">{{ generated }}</span>
          <UiButton size="sm" icon="copy" @click="copyGenerated">Copy</UiButton>
        </div>
        <p v-if="generated" class="text-xs text-slate-500 dark:text-slate-400">
          Give it to the user before saving: it isn't shown again.
        </p>
      </div>
      <UiToggle
        v-model="form.disabled"
        label="Disabled"
        description="The user can't log in, and is logged out now. The peers stay."
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="user-form" variant="primary" :loading="busy">{{ user ? 'Save' : 'Add user' }}</UiButton>
    </template>
  </UiDrawer>
</template>
