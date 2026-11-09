<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api, ApiError, type BackupSummary } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiInput from '../../components/UiInput.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import { dateTime, errorMessage, fieldMessage } from '../../format'
import { download, notify, session } from '../../state'

// A backup has the whole configuration, its keys too; a restore replaces it. For an Administrator only: the server
// checks the role, and the password of the administrator, for both.
const router = useRouter()
const section = 'rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900'
// see internal/backup: a larger file isn't a backup
const maxSize = 8 * 1024 * 1024
const minPassphrase = 12

type Errors = { file?: string; passphrase?: string; again?: string; password?: string; other?: string }

const busy = ref(false)

// the download
const backingUp = ref(false)
const passphrase = ref('')
const passphraseAgain = ref('')
const password = ref('')
const backupErrors = ref<Errors>({})

function openBackup() {
  passphrase.value = passphraseAgain.value = password.value = ''
  backupErrors.value = {}
  backingUp.value = true
}

async function makeBackup() {
  const errors: Errors = {}
  if ([...passphrase.value].length < minPassphrase) {
    errors.passphrase = `At least ${minPassphrase} characters.`
  } else if (passphrase.value !== passphraseAgain.value) {
    errors.again = 'The two passphrases differ.'
  }
  if (!password.value) {
    errors.password = 'Type your password.'
  }
  backupErrors.value = errors
  if (Object.keys(errors).length) {
    return
  }
  busy.value = true
  try {
    const file = await api.backup(password.value, passphrase.value)
    download(file.name, file.text, 'application/json')
    backingUp.value = false
    passphrase.value = passphraseAgain.value = password.value = ''
    notify('Backup downloaded. Keep the passphrase apart from the file.')
  } catch (e) {
    backupErrors.value = apiErrors(e)
  } finally {
    busy.value = false
  }
}

// the restore: the file and its passphrase first, to see what the backup has; then the password replaces everything
const restoring = ref(false)
const fileText = ref('')
const restorePassphrase = ref('')
const restorePassword = ref('')
const summary = ref<BackupSummary | null>(null)
const restoreErrors = ref<Errors>({})

function openRestore() {
  fileText.value = restorePassphrase.value = restorePassword.value = ''
  summary.value = null
  restoreErrors.value = {}
  restoring.value = true
}

function closeRestore() {
  restoring.value = false
  fileText.value = restorePassphrase.value = restorePassword.value = ''
  summary.value = null
}

async function chooseFile(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  fileText.value = ''
  restoreErrors.value = {}
  if (!file) {
    return
  }
  if (file.size > maxSize) {
    restoreErrors.value = { file: "This file is too large to be a backup of Authway Server." }
    return
  }
  try {
    fileText.value = await file.text()
  } catch {
    restoreErrors.value = { file: "This file can't be read." }
  }
}

function backupMessage(code: string, detail: string): string {
  switch (code) {
    case 'required':
      return 'Choose the file of a backup.'
    case 'not_backup':
      return "This file isn't a backup of Authway Server."
    case 'newer_version':
      return 'This backup comes from a newer version of Authway Server: update this one first.'
    case 'invalid_content':
      return `This backup can't be restored: ${detail || 'its content isn’t valid'}.`
  }
  return fieldMessage(code)
}

function apiErrors(e: unknown): Errors {
  if (!(e instanceof ApiError) || e.code !== 'validation') {
    return { other: errorMessage(e) }
  }
  const errors: Errors = {}
  if (e.fields.backup) {
    errors.file = backupMessage(e.fields.backup, e.detail)
  }
  if (e.fields.passphrase) {
    errors.passphrase = e.fields.passphrase === 'wrong' ? 'Wrong passphrase, or the file is damaged.' : fieldMessage(e.fields.passphrase)
  }
  if (e.fields.password) {
    errors.password = fieldMessage(e.fields.password)
  }
  return errors
}

async function check() {
  const errors: Errors = {}
  if (!fileText.value) {
    errors.file = restoreErrors.value.file ?? 'Choose the file of a backup.'
  }
  if (!restorePassphrase.value) {
    errors.passphrase = 'Type the passphrase of the backup.'
  }
  restoreErrors.value = errors
  if (Object.keys(errors).length) {
    return
  }
  busy.value = true
  try {
    summary.value = await api.checkBackup(restorePassphrase.value, fileText.value)
  } catch (e) {
    restoreErrors.value = apiErrors(e)
  } finally {
    busy.value = false
  }
}

async function restore() {
  if (!restorePassword.value) {
    restoreErrors.value = { password: 'Type your password.' }
    return
  }
  restoreErrors.value = {}
  busy.value = true
  try {
    await api.restore(restorePassword.value, restorePassphrase.value, fileText.value)
    closeRestore()
    // every session of the web UI ended: the administrators are the ones of the backup
    session.me = null
    await router.replace({ name: 'login', query: { restored: '1' } })
  } catch (e) {
    restoreErrors.value = apiErrors(e)
    if (restoreErrors.value.file || restoreErrors.value.passphrase) {
      // the file changed since the check: back to the first step
      summary.value = null
    }
  } finally {
    busy.value = false
  }
}

const loginAs = computed(() => {
  const names = summary.value?.admin_usernames ?? []
  return names.length > 1 ? names.slice(0, -1).join(', ') + ' or ' + names[names.length - 1] : (names[0] ?? '')
})

function count(n: number, thing: string): string {
  return `${n} ${thing}${n === 1 ? '' : 's'}`
}
</script>

<template>
  <section :class="section">
    <h2 class="text-base font-semibold">Backup and restore</h2>
    <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
      A backup has the whole configuration: the servers and their keys, the peers, the users with their passwords and
      authenticators, the administrators and these settings. Not the history, the events or the alerts. A passphrase that
      you choose encrypts it.
    </p>
    <div class="mt-4 flex flex-wrap gap-2">
      <UiButton icon="download" @click="openBackup">Download a backup</UiButton>
      <UiButton icon="upload" @click="openRestore">Restore a backup</UiButton>
    </div>
  </section>

  <UiModal :open="backingUp" title="Download a backup" @close="backingUp = false">
    <form id="make-backup" class="space-y-4" novalidate @submit.prevent="makeBackup">
      <p class="text-sm text-slate-600 dark:text-slate-300">
        The file has the keys of every tunnel and the password hashes: the passphrase encrypts it. Without the passphrase
        nobody can restore it, you neither. Keep it apart from the file, in a password manager.
      </p>
      <UiInput
        v-model="passphrase"
        label="Passphrase"
        type="password"
        autocomplete="new-password"
        :helper="`At least ${minPassphrase} characters.`"
        :error="backupErrors.passphrase"
      />
      <UiInput v-model="passphraseAgain" label="Passphrase again" type="password" autocomplete="new-password" :error="backupErrors.again" />
      <UiInput v-model="password" label="Your password" type="password" autocomplete="current-password" :error="backupErrors.password" />
      <UiNotice v-if="backupErrors.other" tone="error">{{ backupErrors.other }}</UiNotice>
    </form>
    <template #footer>
      <UiButton @click="backingUp = false">Cancel</UiButton>
      <UiButton type="submit" form="make-backup" variant="primary" icon="download" :loading="busy">Download</UiButton>
    </template>
  </UiModal>

  <UiModal :open="restoring" title="Restore a backup" @close="closeRestore">
    <form v-show="!summary" id="check-backup" class="space-y-4" novalidate @submit.prevent="check">
      <p class="text-sm text-slate-600 dark:text-slate-300">
        Choose the file and type its passphrase: the next step shows what the backup has, before anything changes.
      </p>
      <div>
        <label for="backup-file" class="mb-1.5 block text-sm font-medium text-slate-800 dark:text-slate-200">File of the backup</label>
        <input
          id="backup-file"
          type="file"
          accept=".json,application/json"
          :aria-invalid="Boolean(restoreErrors.file)"
          class="block w-full text-sm text-slate-600 file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-2 file:text-sm file:font-medium file:text-slate-800 hover:file:bg-slate-200 dark:text-slate-300 dark:file:bg-slate-800 dark:file:text-slate-200 dark:hover:file:bg-slate-700"
          @change="chooseFile"
        />
        <p v-if="restoreErrors.file" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ restoreErrors.file }}</p>
      </div>
      <UiInput v-model="restorePassphrase" label="Passphrase of the backup" type="password" autocomplete="off" :error="restoreErrors.passphrase" />
      <UiNotice v-if="restoreErrors.other" tone="error">{{ restoreErrors.other }}</UiNotice>
    </form>

    <form v-if="summary" id="restore-backup" class="space-y-4" novalidate @submit.prevent="restore">
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
        <dt class="text-slate-500 dark:text-slate-400">Made</dt>
        <dd>{{ dateTime(summary.created_at) }}, by {{ summary.made_by }}</dd>
        <dt class="text-slate-500 dark:text-slate-400">Content</dt>
        <dd>
          {{ count(summary.servers, 'server') }}, {{ count(summary.peers, 'peer') }}, {{ count(summary.users, 'user') }},
          {{ count(summary.administrators, 'administrator') }}
        </dd>
      </dl>
      <UiNotice tone="warning" title="Everything here is replaced">
        The servers, the peers, the users, the administrators and the settings become the ones of the backup. The open VPN
        sessions end, the alerts go, and every administrator is logged out. The history and the events stay.
      </UiNotice>
      <UiNotice v-if="!summary.includes_you" tone="warning">
        Your account isn't in this backup: after the restore, log in as {{ loginAs }}.
      </UiNotice>
      <p v-else class="text-sm text-slate-600 dark:text-slate-300">
        After the restore, log in again as <span class="font-medium">{{ session.me?.username }}</span>, with the password
        and the authenticator that the backup has.
      </p>
      <UiInput v-model="restorePassword" label="Your password" type="password" autocomplete="current-password" :error="restoreErrors.password" />
      <UiNotice v-if="restoreErrors.file || restoreErrors.other" tone="error">{{ restoreErrors.file || restoreErrors.other }}</UiNotice>
    </form>

    <template #footer>
      <UiButton @click="closeRestore">Cancel</UiButton>
      <UiButton v-if="!summary" type="submit" form="check-backup" variant="primary" :loading="busy">Check</UiButton>
      <template v-else>
        <UiButton :disabled="busy" @click="summary = null">Back</UiButton>
        <UiButton type="submit" form="restore-backup" variant="danger" icon="upload" :loading="busy">Restore</UiButton>
      </template>
    </template>
  </UiModal>
</template>
