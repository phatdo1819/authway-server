<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, ApiError, type ImportResult, type ImportRow } from '../../api'
import UiBadge from '../../components/UiBadge.vue'
import UiButton from '../../components/UiButton.vue'
import UiModal from '../../components/UiModal.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiToggle from '../../components/UiToggle.vue'
import { errorMessage, fieldMessage } from '../../format'
import { confirm, download } from '../../state'

// Users from a CSV file, as Add user makes them: the file is checked, every row shown with the user it adds or
// what's wrong, then imported whole. The passwords the server made are given once, at the end.
const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: []; imported: [] }>()

const step = ref<'file' | 'check' | 'done'>('file')
const text = ref('')
const fileName = ref('')
const error = ref('')
const busy = ref(false)
const checked = ref<ImportResult | null>(null)
const result = ref<ImportResult | null>(null)
// the users already there: skipped, or a reason to stop
const skip = ref(false)
// rows refused only because their user is already there: skipping them would let the rest in
const taken = computed(() => (checked.value?.rows ?? []).filter((row) => row.errors?.username === 'taken').length)
const input = ref<HTMLInputElement | null>(null)

const columns = [
  { name: 'username', text: 'Letters, digits and . _ @ -, as in Add user.' },
  { name: 'full_name', text: 'Optional.' },
  { name: 'password', text: 'Optional: without one, a password that follows the policy is made, and shown once after the import.' },
]

// what a file-wide error means, with the name of the column when there is one
const csvMessages: Record<string, (detail: string) => string> = {
  too_large: () => 'The file is larger than 512 KB: split it.',
  not_utf8: () => 'Save the file as CSV UTF-8, then choose it again.',
  empty: () => 'The file is empty.',
  invalid: (detail) => `This isn't a CSV file the import can read${detail ? `: ${detail}` : ''}.`,
  unknown_column: (detail) => `Unknown column "${detail}". The columns are username, full_name and password.`,
  duplicate_column: (detail) => `The column "${detail}" appears twice.`,
  no_username: () => 'The first line, the header, needs a username column.',
  too_many_rows: () => 'At most 500 rows in one file: split it.',
  no_rows: () => 'The file has a header, but no row under it.',
}

const columnNames: Record<string, string> = {
  username: 'Username',
  full_name: 'Full name',
  password: 'Password',
  row: 'Row',
}

watch(
  () => props.open,
  (open) => {
    if (!open) {
      return
    }
    step.value = 'file'
    text.value = ''
    fileName.value = ''
    error.value = ''
    checked.value = null
    result.value = null
    skip.value = false
  },
)

// on the rows checked, the choice checks the file again
watch(skip, () => {
  if (step.value === 'check') {
    check()
  }
})

function users(count: number): string {
  return `${count} ${count === 1 ? 'user' : 'users'}`
}

function template() {
  const rows = ['username,full_name,password', 'alice,Alice Martin,', 'bob,Bob Smith,']
  download('authway-users.csv', rows.join('\r\n') + '\r\n', 'text/csv')
}

async function choose(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) {
    return
  }
  error.value = ''
  if (file.size > 512 * 1024) {
    error.value = csvMessages.too_large('')
    return
  }
  fileName.value = file.name
  text.value = await file.text()
  ;(event.target as HTMLInputElement).value = ''
  await check()
}

function fileError(e: unknown): string {
  if (e instanceof ApiError && e.code === 'validation' && e.fields.csv) {
    return csvMessages[e.fields.csv]?.(e.detail) ?? fieldMessage(e.fields.csv)
  }
  return errorMessage(e)
}

async function check() {
  if (!text.value.trim()) {
    error.value = 'Choose a file, or paste its rows.'
    return
  }
  busy.value = true
  error.value = ''
  try {
    checked.value = await api.importCheck(text.value, skip.value)
    step.value = 'check'
  } catch (e) {
    error.value = fileError(e)
  } finally {
    busy.value = false
  }
}

async function runImport() {
  busy.value = true
  error.value = ''
  try {
    const answer = await api.importFile(text.value, skip.value)
    if (!answer.imported) {
      // a user added by another administrator since the check: the rows say which
      checked.value = answer
      error.value = 'Something changed since the check: nothing is imported. See the rows below.'
      return
    }
    result.value = answer
    step.value = 'done'
    emit('imported')
  } catch (e) {
    error.value = fileError(e)
  } finally {
    busy.value = false
  }
}

function passwordsFile() {
  const rows = ['username,password', ...(result.value?.passwords ?? []).map((entry) => `${entry.username},${entry.password}`)]
  download('authway-passwords.csv', rows.join('\r\n') + '\r\n', 'text/csv')
}

function errorsOf(row: ImportRow): string[] {
  return Object.entries(row.errors ?? {}).map(([column, code]) => `${columnNames[column] ?? column}: ${fieldMessage(code)}`)
}

async function close() {
  if (step.value === 'done' && result.value?.passwords?.length) {
    // the passwords made are gone once closed
    const ok = await confirm(
      'Close without the passwords?',
      "The passwords made for the new users aren't shown again. Download them first, unless you already did.",
      'Close',
    )
    if (!ok) {
      return
    }
  }
  emit('close')
}
</script>

<template>
  <UiModal :open="open" title="Import users" wide @close="close">
    <!-- the file -->
    <div v-if="step === 'file'" class="space-y-4">
      <p>
        From a CSV file, made with a spreadsheet: each row adds a user, as Add user does. The first line names the
        columns, in any order. Nothing is added before you see each row. Then give each user a peer on its server.
      </p>
      <dl class="divide-y divide-slate-200 rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        <div v-for="column in columns" :key="column.name" class="grid gap-1 px-3 py-2 sm:grid-cols-[7rem_1fr]">
          <dt class="font-mono text-sm font-medium text-slate-900 dark:text-slate-100">{{ column.name }}</dt>
          <dd>{{ column.text }}</dd>
        </div>
      </dl>
      <div class="flex flex-wrap items-center gap-3">
        <UiButton icon="upload" variant="primary" :loading="busy" @click="input?.click()">Choose a CSV file</UiButton>
        <UiButton icon="download" variant="ghost" @click="template">Download a template</UiButton>
        <span v-if="fileName" class="text-slate-500 dark:text-slate-400">{{ fileName }}</span>
        <input ref="input" type="file" accept=".csv,text/csv,text/plain" class="hidden" @change="choose" />
      </div>
      <details class="text-sm">
        <summary class="cursor-pointer font-medium">Or paste the rows</summary>
        <textarea
          v-model="text"
          rows="7"
          spellcheck="false"
          aria-label="The rows of the file"
          placeholder="username,full_name,password&#10;alice,Alice Martin,"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/25 dark:border-slate-600 dark:bg-slate-900"
        />
        <UiButton class="mt-2" size="sm" :loading="busy" @click="check">Check</UiButton>
      </details>
      <p class="text-xs text-slate-500 dark:text-slate-400">
        Excel: <em>File › Save As › CSV UTF-8</em>. Commas, semicolons and tabs all work. At most 500 rows.
      </p>
      <UiToggle
        v-model="skip"
        label="Skip the users that already exist"
        description="Their rows are skipped, and nothing about them changes, their password neither. Without it, they stop the import."
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
    </div>

    <!-- the rows checked -->
    <div v-else-if="step === 'check' && checked" class="space-y-4">
      <UiNotice v-if="checked.invalid" tone="error">
        {{ checked.invalid }} {{ checked.invalid === 1 ? 'row needs' : 'rows need' }} a change: nothing is imported until
        the file is right. Change it in the spreadsheet, then choose it again.
        <template v-if="taken && !skip">
          {{ taken === checked.invalid ? 'All of them are' : `${taken} of them are` }} users that already exist:
          <button type="button" class="font-medium underline" @click="skip = true">skip them</button>.
        </template>
      </UiNotice>
      <UiNotice v-else-if="!checked.users" tone="warning">Nothing to add: every user of the file already exists.</UiNotice>
      <UiNotice v-else tone="info">
        Ready: {{ users(checked.users) }}, enabled.
        <template v-if="checked.skipped">
          {{ users(checked.skipped) }} already there {{ checked.skipped === 1 ? 'is' : 'are' }} skipped.
        </template>
      </UiNotice>
      <UiToggle v-model="skip" label="Skip the users that already exist" />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
      <div class="max-h-96 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
          <thead class="sticky top-0 bg-slate-50 text-left text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-800 dark:text-slate-400">
            <tr>
              <th scope="col" class="px-3 py-2">Line</th>
              <th scope="col" class="px-3 py-2">User</th>
              <th scope="col" class="px-3 py-2">Password</th>
              <th scope="col" class="px-3 py-2">Check</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
            <tr
              v-for="row in checked.rows"
              :key="row.line"
              :class="{ 'bg-rose-50/70 dark:bg-rose-500/10': row.errors, 'text-slate-400 dark:text-slate-500': row.skipped }"
            >
              <td class="px-3 py-2 text-slate-500 tabular-nums">{{ row.line }}</td>
              <td class="px-3 py-2">
                <span class="font-medium">{{ row.username || '—' }}</span>
                <p v-if="row.full_name" class="text-slate-500 dark:text-slate-400">{{ row.full_name }}</p>
              </td>
              <td class="px-3 py-2" :class="{ 'text-slate-600 dark:text-slate-300': !row.skipped }">
                {{ row.skipped ? '—' : row.password === 'given' ? 'From the file' : 'Made at the import' }}
              </td>
              <td class="px-3 py-2">
                <ul v-if="row.errors" class="space-y-0.5 text-rose-700 dark:text-rose-300">
                  <li v-for="message in errorsOf(row)" :key="message">{{ message }}</li>
                </ul>
                <template v-else-if="row.skipped">
                  <UiBadge tone="gray">Skipped</UiBadge>
                  <p class="mt-0.5 text-xs">Already exists: not changed</p>
                </template>
                <UiBadge v-else tone="green">OK</UiBadge>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- imported -->
    <div v-else-if="step === 'done' && result" class="space-y-4">
      <UiNotice tone="info">
        Added {{ users(result.users) }}<template v-if="result.skipped">, skipped {{ result.skipped }} already there</template>.
        Give each new user a peer: in WireGuard servers, Add peer, then choose the user.
      </UiNotice>
      <template v-if="result.passwords?.length">
        <UiNotice tone="warning" title="The passwords made are shown only now">
          Download them, and give each user their own, apart from the configuration file.
        </UiNotice>
        <div class="max-h-64 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
            <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
              <tr v-for="entry in result.passwords" :key="entry.username">
                <td class="px-3 py-1.5 font-medium">{{ entry.username }}</td>
                <td class="px-3 py-1.5 font-mono select-all">{{ entry.password }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <UiButton icon="download" @click="passwordsFile">Download the passwords</UiButton>
      </template>
    </div>

    <template #footer>
      <template v-if="step === 'check'">
        <UiButton @click="step = 'file'">Back</UiButton>
        <UiButton variant="primary" :loading="busy" :disabled="Boolean(checked?.invalid) || !checked?.users" @click="runImport">
          Import {{ users(checked?.users ?? 0) }}
        </UiButton>
      </template>
      <UiButton v-else-if="step === 'done'" variant="primary" @click="close">Done</UiButton>
      <UiButton v-else @click="close">Cancel</UiButton>
    </template>
  </UiModal>
</template>
