<script setup lang="ts">
import { computed, ref } from 'vue'

import { api, ApiError } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import { errorMessage, fieldMessage, policyText } from '../../format'
import { session } from '../../state'

const emit = defineEmits<{ done: [] }>()

const current = ref('')
const password = ref('')
const again = ref('')
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)
const helper = computed(() => policyText(session.me?.password_policy, true))

async function save() {
  errors.value = {}
  error.value = ''
  if (password.value !== again.value) {
    errors.value = { again: 'The two passwords differ.' }
    return
  }
  busy.value = true
  try {
    await api.changePassword(current.value, password.value)
    current.value = password.value = again.value = ''
    emit('done')
  } catch (e) {
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = Object.fromEntries(Object.entries(e.fields).map(([field, code]) => [field, fieldMessage(code)]))
      if (e.fields.password === 'too_short') {
        errors.value.password = helper.value
      }
    } else {
      error.value = errorMessage(e)
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <form class="space-y-4" novalidate @submit.prevent="save">
    <UiInput v-model="current" label="Current password" type="password" autocomplete="current-password" :error="errors.current" />
    <UiInput v-model="password" label="New password" type="password" autocomplete="new-password" :error="errors.password" :helper="helper" />
    <UiInput v-model="again" label="Type it again" type="password" autocomplete="new-password" :error="errors.again" />
    <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    <div class="flex justify-end">
      <UiButton type="submit" variant="primary" :loading="busy">Change password</UiButton>
    </div>
  </form>
</template>
