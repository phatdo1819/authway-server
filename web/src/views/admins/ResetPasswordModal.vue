<script setup lang="ts">
import { ref, watch } from 'vue'

import { api, ApiError, type AdminAccount } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiInput from '../../components/UiInput.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import { errorMessage, fieldMessage, generatePassword, policyText } from '../../format'
import { notify, session } from '../../state'

const props = defineProps<{ admin: AdminAccount | null }>()
const emit = defineEmits<{ close: []; saved: [] }>()

const password = ref('')
const error = ref('')
const busy = ref(false)

watch(
  () => props.admin,
  (admin) => {
    if (admin) {
      error.value = ''
      password.value = generatePassword(session.me?.password_policy, true)
    }
  },
)

async function copy() {
  try {
    await navigator.clipboard.writeText(password.value)
    notify('Password copied.')
  } catch {
    notify('Select the password and copy it.', 'error')
  }
}

async function save() {
  if (!props.admin) {
    return
  }
  error.value = ''
  busy.value = true
  try {
    await api.resetAdminPassword(props.admin.id, password.value)
    notify(`New password of ${props.admin.username} saved: they choose their own at the next login.`)
    emit('saved')
  } catch (e) {
    error.value = e instanceof ApiError && e.code === 'validation' ? fieldMessage(e.fields.password) : errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UiModal :open="admin !== null" :title="`New password for ${admin?.username ?? ''}`" @close="emit('close')">
    <form id="reset-password" class="space-y-4 text-sm" novalidate @submit.prevent="save">
      <p>
        Give this password to {{ admin?.username }}: the web UI asks for a new one at the next login. Their sessions end now.
      </p>
      <UiInput v-model="password" label="New password" autocomplete="off" mono :helper="policyText(session.me?.password_policy, true)" />
      <div class="flex gap-2">
        <UiButton size="sm" icon="refresh" @click="password = generatePassword(session.me?.password_policy, true)">Another one</UiButton>
        <UiButton size="sm" icon="copy" @click="copy">Copy</UiButton>
      </div>
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="reset-password" variant="primary" :loading="busy">Save password</UiButton>
    </template>
  </UiModal>
</template>
