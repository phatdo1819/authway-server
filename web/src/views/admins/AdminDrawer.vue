<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, ApiError, type AdminAccount, type AdminInput, type Role } from '../../api'
import ConflictNotice from '../../components/ConflictNotice.vue'
import UiButton from '../../components/UiButton.vue'
import UiDrawer from '../../components/UiDrawer.vue'
import UiInput from '../../components/UiInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { useEditGuard } from '../../conflict'
import { errorMessage, fieldMessage, generatePassword, policyText, roles } from '../../format'
import { notify, session } from '../../state'

const props = defineProps<{ open: boolean; admin: AdminAccount | null }>()
const emit = defineEmits<{ close: []; saved: [] }>()

const form = ref<AdminInput>({ username: '', full_name: '', role: 'operator', disabled: false, password: '' })
const errors = ref<Record<string, string>>({})
const error = ref('')
const busy = ref(false)
const own = computed(() => props.admin !== null && props.admin.id === session.me?.id)
const roleDescription = computed(() => roles.find((role) => role.value === form.value.role)?.description ?? '')
// another administrator saving this account meanwhile
const guard = useEditGuard((admin: AdminAccount) => ({ full_name: admin.full_name, role: admin.role, disabled: admin.disabled }), {
  full_name: 'Full name',
  role: 'Role',
  disabled: 'Disabled',
})
const conflict = guard.conflict

watch(
  () => props.open,
  (open) => {
    if (!open) {
      return
    }
    errors.value = {}
    error.value = ''
    const admin = props.admin
    guard.start(admin)
    form.value = admin
      ? { username: admin.username, full_name: admin.full_name, role: admin.role, disabled: admin.disabled }
      : { username: '', full_name: '', role: 'operator', disabled: false, password: generatePassword(session.me?.password_policy, true) }
  },
)

function regenerate() {
  form.value.password = generatePassword(session.me?.password_policy, true)
}

async function copyPassword() {
  try {
    await navigator.clipboard.writeText(form.value.password ?? '')
    notify('Password copied.')
  } catch {
    notify('Select the password and copy it.', 'error')
  }
}

async function save() {
  errors.value = {}
  error.value = ''
  busy.value = true
  let again = false
  try {
    if (props.admin) {
      await api.updateAdmin(props.admin.id, { ...form.value, password: undefined, version: guard.version.value })
      notify(`${form.value.username} saved.`)
    } else {
      await api.createAdmin(form.value)
      notify(`${form.value.username} added. Give them the password: they choose their own at the first login.`)
    }
    emit('saved')
  } catch (e) {
    const { full_name, role, disabled } = form.value
    const merged = guard.refused(e, { full_name, role, disabled })
    if (merged) {
      Object.assign(form.value, merged.values)
      again = merged.again
      return
    }
    if (e instanceof ApiError && e.code === 'validation') {
      errors.value = e.fields
    }
    error.value = errorMessage(e)
  } finally {
    busy.value = false
    // only what the form doesn't show changed meanwhile: saved again with the new version
    if (again) {
      save()
    }
  }
}

function useTheirs() {
  Object.assign(form.value, guard.useTheirs())
}

const roleOptions = roles.map((role) => ({ value: role.value, label: role.label })) as { value: Role; label: string }[]
</script>

<template>
  <UiDrawer :open="open" :title="admin ? `Edit ${admin.username}` : 'Add administrator'" @close="emit('close')">
    <form id="admin-form" class="space-y-6" novalidate @submit.prevent="save">
      <ConflictNotice :conflict="conflict" noun="administrator" @theirs="useTheirs" />
      <UiInput
        v-model="form.username"
        label="Username"
        autocomplete="off"
        :disabled="Boolean(admin)"
        :error="fieldMessage(errors.username)"
        :helper="admin ? 'The username stays: add another administrator for another name.' : 'Letters, digits and . _ @ -.'"
      />
      <UiInput v-model="form.full_name" label="Full name" optional :error="fieldMessage(errors.full_name)" />
      <div>
        <UiSelect v-model="form.role" label="Role" :options="roleOptions" :disabled="own" :error="fieldMessage(errors.role)" />
        <p class="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
          {{ own ? 'You can\'t change your own role.' : roleDescription }}
        </p>
      </div>
      <div v-if="!admin">
        <UiInput
          v-model="form.password!"
          label="First password"
          autocomplete="off"
          mono
          :error="fieldMessage(errors.password)"
          :helper="`Give it to them: they choose their own at the first login. ${policyText(session.me?.password_policy, true)}`"
        />
        <div class="mt-2 flex gap-2">
          <UiButton size="sm" icon="refresh" @click="regenerate">New password</UiButton>
          <UiButton size="sm" icon="copy" @click="copyPassword">Copy</UiButton>
        </div>
      </div>
      <UiToggle
        v-if="admin && !own"
        v-model="form.disabled"
        label="Disabled"
        description="The administrator can't log in, and is logged out now."
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="emit('close')">Cancel</UiButton>
      <UiButton type="submit" form="admin-form" variant="primary" :loading="busy">{{ admin ? 'Save' : 'Add administrator' }}</UiButton>
    </template>
  </UiDrawer>
</template>
