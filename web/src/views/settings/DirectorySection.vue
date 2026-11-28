<script setup lang="ts">
import { computed, inject, onMounted, ref } from 'vue'

import { api, ApiError, type DirectorySettings, type DirectorySkip, type DirectoryTest, type DirectoryView } from '../../api'
import UiButton from '../../components/UiButton.vue'
import UiHelp from '../../components/UiHelp.vue'
import UiInput from '../../components/UiInput.vue'
import UiListInput from '../../components/UiListInput.vue'
import UiNotice from '../../components/UiNotice.vue'
import UiSelect from '../../components/UiSelect.vue'
import UiToggle from '../../components/UiToggle.vue'
import { ago, dateTime, day, errorMessage, fieldMessage, sentence } from '../../format'
import { confirm, notify } from '../../state'

const section = 'rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900'

const view = ref<DirectoryView | null>(null)
const form = ref<DirectorySettings>(empty())
const minutes = ref<string | number>(15)
const password = ref('')
const errors = ref<Record<string, string>>({})
const error = ref('')
const saving = ref(false)
const testing = ref(false)
const syncing = ref(false)
const test = ref<DirectoryTest | null>(null)
const confirming = ref(false)
// the warning at the top of the pages follows the syncs
const refreshStatus = inject<() => void>('refreshStatus', () => {})

const securities = [
  { value: 'ldaps' as const, label: 'LDAPS (port 636)' },
  { value: 'starttls' as const, label: 'StartTLS (port 389)' },
]
const usernames = [
  { value: 'sAMAccountName' as const, label: 'Logon name (alice)' },
  { value: 'userPrincipalName' as const, label: 'User principal name (alice@example.com)' },
]

function empty(): DirectorySettings {
  return {
    enabled: false, servers: [''], security: 'ldaps', ca_certificates: '', bind_user: '', base_dn: '', group: '',
    username_attribute: 'sAMAccountName', sync_minutes: 15, link_local_users: false,
  }
}

function load(saved: DirectoryView) {
  view.value = saved
  const { bind_password_set: _set, status: _status, ...settings } = saved
  form.value = { ...settings, servers: settings.servers.length ? [...settings.servers] : [''] }
  minutes.value = settings.sync_minutes
  password.value = ''
}

onMounted(async () => {
  try {
    load(await api.directory())
  } catch (e) {
    error.value = errorMessage(e)
  }
})

// what the form sends: an empty password keeps the one saved
function input(): DirectorySettings {
  return {
    ...form.value,
    servers: form.value.servers.map((server) => server.trim()).filter(Boolean),
    sync_minutes: Number(minutes.value),
    bind_password: password.value,
  }
}

function serverMessage(code: string | undefined): string {
  switch (code) {
    case 'invalid':
      return 'Enter host names or IP addresses, with :port only for a non-standard port. No ldaps:// prefix.'
    case 'duplicate':
      return 'A domain controller is listed twice.'
    case 'too_many':
      return 'Up to 4 domain controllers.'
  }
  return fieldMessage(code)
}

function message(field: string): string {
  const code = errors.value[field]
  switch (field) {
    case 'servers':
      return serverMessage(code)
    case 'base_dn':
    case 'group':
      return code === 'invalid' ? 'Enter a distinguished name, like CN=VPN Users,OU=Groups,DC=example,DC=com.' : fieldMessage(code)
    case 'ca_certificates':
      return code === 'invalid' ? 'Paste one or more certificates in PEM format, each starting with -----BEGIN CERTIFICATE-----.' : ''
    case 'sync_minutes':
      return code === 'invalid' ? 'Enter 5 to 1440 minutes (a day).' : fieldMessage(code)
  }
  return fieldMessage(code)
}

function refused(e: unknown) {
  if (e instanceof ApiError && e.code === 'validation') {
    errors.value = e.fields
  }
  error.value = errorMessage(e)
}

async function save() {
  errors.value = {}
  error.value = ''
  saving.value = true
  try {
    const turnedOn = form.value.enabled && !view.value?.enabled
    load(await api.saveDirectory(input()))
    notify(turnedOn ? 'Settings saved. The first sync starts now.' : 'Settings saved.')
  } catch (e) {
    refused(e)
  } finally {
    saving.value = false
  }
}

async function runTest() {
  errors.value = {}
  error.value = ''
  test.value = null
  testing.value = true
  try {
    test.value = await api.testDirectory(input())
  } catch (e) {
    refused(e)
  } finally {
    testing.value = false
  }
}

async function syncNow() {
  syncing.value = true
  try {
    const status = await api.syncDirectory()
    if (view.value) {
      view.value.status = status
    }
    if (status.error) {
      notify("The sync didn't finish. See the error below.", 'error')
    } else if (status.held.length) {
      notify('The sync is waiting for you. See below.', 'error')
    } else {
      notify('Synced.')
    }
    refreshStatus()
  } catch (e) {
    notify(errorMessage(e), 'error')
  } finally {
    syncing.value = false
  }
}

const status = computed(() => view.value?.status)

// a few names of a long list, and how many others
function some(names: string[], count = 20): string {
  return names.length > count ? `${names.slice(0, count).join(', ')} and ${names.length - count} more` : names.join(', ')
}

// a sync held too many users at once: an Administrator confirms that many, after checking them
async function disableHeld() {
  const held = status.value?.held ?? []
  if (
    !held.length ||
    !(await confirm(
      `Disable ${plural(held.length, 'user')}?`,
      `${some(held)}. They'll be disabled here and logged out. Do this only if they really left the group or were disabled in Active Directory.`,
      'Disable them',
    ))
  ) {
    return
  }
  confirming.value = true
  try {
    const result = await api.syncDirectory(held.length)
    if (view.value) {
      view.value.status = result
    }
    if (result.error) {
      notify("The sync didn't finish. See the error below.", 'error')
    } else if (result.held.length) {
      notify('More users would be disabled now. Check the list again.', 'error')
    } else {
      notify(`Synced. ${plural(result.disabled, 'user')} disabled.`)
    }
    refreshStatus()
  } catch (e) {
    notify(errorMessage(e), 'error')
  } finally {
    confirming.value = false
  }
}

// the password of the service account: expired, or within the 14 days of the warnings
const passwordState = computed(() => {
  const expires = status.value?.password_expires ?? 0
  if (!expires) {
    return ''
  }
  const left = expires * 1000 - Date.now()
  return left <= 0 ? 'expired' : left <= 14 * 86400 * 1000 ? 'soon' : 'fine'
})

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

const summary = computed(() => {
  const s = status.value
  if (!s?.at) {
    return ''
  }
  const changes = [
    s.added && `${s.added} added`,
    s.updated && `${s.updated} updated`,
    s.disabled && `${s.disabled} disabled`,
  ].filter(Boolean)
  return `The group has ${plural(s.members, 'member')}. ${changes.length ? changes.join(', ') + '.' : 'No changes.'}`
})

function reason(skip: DirectorySkip): string {
  switch (skip.reason) {
    case 'invalid_username':
      return 'Usernames here can only use letters, digits and the characters . _ @ -'
    case 'local_user':
      return 'A local user already has this username. Turn on "Take over local users" to link them.'
    case 'other_account':
      return 'Another Active Directory account used to have this username. Delete that user here to add this one.'
    case 'taken':
      return 'Renamed in Active Directory to a username another user already has here.'
  }
  return skip.reason
}
</script>

<template>
  <section :class="section">
    <div class="flex items-center gap-1.5">
      <h2 class="text-base font-semibold">Active Directory</h2>
      <UiHelp
        label="Active Directory"
        text="Add VPN users from an Active Directory group. Active Directory checks their password at every VPN login. Their authenticator codes, peers and devices stay in Authway Server, as for other users. Administrators of this web UI stay local."
      />
    </div>

    <form class="mt-4 space-y-5" novalidate @submit.prevent="save">
      <UiToggle
        v-model="form.enabled"
        label="Sync users from Active Directory"
        help="Members of the group become users here, and changes follow at each sync. Members who are disabled or leave the group are disabled here and logged out."
      />
      <UiListInput
        v-model="form.servers"
        label="Domain controllers"
        placeholder="dc1.example.com"
        add-label="Add a domain controller"
        :error="message('servers')"
        help="Tried in order. Add :port only if it isn't the standard one."
      />
      <UiSelect
        v-model="form.security"
        label="Connection"
        :options="securities"
        :error="message('security')"
        help="Both are encrypted. Passwords are never sent in clear text."
      />
      <div>
        <div class="mb-1.5 flex items-center gap-1.5">
          <label for="directory-ca" class="block text-sm font-medium text-slate-800 dark:text-slate-200">
            CA certificate <span class="font-normal text-slate-500 dark:text-slate-400">(optional)</span>
          </label>
          <UiHelp
            label="CA certificate"
            text="Only needed if your domain controllers use certificates from your own certificate authority, such as Active Directory Certificate Services. Paste the CA certificate in PEM format."
          />
        </div>
        <textarea
          id="directory-ca"
          v-model="form.ca_certificates"
          rows="4"
          spellcheck="false"
          placeholder="-----BEGIN CERTIFICATE-----"
          class="w-full rounded-md border bg-white px-3 py-2 font-mono text-xs shadow-sm outline-none focus:ring-2 dark:bg-slate-900"
          :class="
            errors.ca_certificates
              ? 'border-rose-500 focus:ring-rose-500/30'
              : 'border-slate-300 focus:border-sky-600 focus:ring-sky-600/25 dark:border-slate-600'
          "
        />
        <p v-if="errors.ca_certificates" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ message('ca_certificates') }}</p>
      </div>
      <UiInput
        v-model="form.bind_user"
        label="Service account"
        placeholder="svc-authway@example.com"
        autocomplete="off"
        :error="message('bind_user')"
        help="An account that can read the directory, as user@domain or its full DN. It needs no other permissions."
      />
      <UiInput
        v-model="password"
        label="Service account password"
        type="password"
        autocomplete="new-password"
        :placeholder="view?.bind_password_set ? 'Saved. Leave empty to keep it.' : ''"
        :error="message('bind_password')"
      />
      <UiInput
        v-model="form.base_dn"
        label="Search base"
        placeholder="DC=example,DC=com"
        mono
        :error="message('base_dn')"
        help="Where to look for users. Usually your whole domain."
      />
      <UiInput
        v-model="form.group"
        label="VPN users group"
        placeholder="CN=VPN Users,OU=Groups,DC=example,DC=com"
        mono
        :error="message('group')"
        help="The group's full distinguished name. Members of groups inside it count too. Don't use a primary group such as Domain Users, because Active Directory doesn't list its members this way."
      />
      <UiSelect
        v-model="form.username_attribute"
        label="Username"
        :options="usernames"
        :error="message('username_attribute')"
        help="What users enter on the VPN login page. EXAMPLE\alice works too, and so does alice@example.com with the logon name, or alice alone with the user principal name."
      />
      <div class="max-w-48">
        <UiInput
          v-model="minutes"
          label="Sync every (minutes)"
          type="number"
          :error="message('sync_minutes')"
          help="From 5 to 1440. 15 by default. Logins always ask Active Directory directly, so a disabled account can't log in even before the next sync."
        />
      </div>
      <UiToggle
        v-model="form.link_local_users"
        label="Take over local users with the same username"
        help="A local user whose username matches a group member becomes that member's user. Their peers and authenticator stay, their password comes from Active Directory from then on, and they're logged out once."
      />
      <UiNotice v-if="error" tone="error">{{ error }}</UiNotice>
      <UiNotice v-if="test && test.error" tone="error" title="Couldn't read the group">{{ sentence(test.error) }}.</UiNotice>
      <UiNotice v-else-if="test" tone="info" title="Connected">
        The group has {{ plural(test.members, 'member') }}<template v-if="test.disabled">, {{ test.disabled }} of them
        disabled</template><template v-if="test.sample.length">, including {{ test.sample.join(', ') }}</template>.
        Nothing was changed.
      </UiNotice>
      <div class="flex flex-wrap justify-end gap-2">
        <UiButton icon="refresh" :loading="testing" @click="runTest">Test connection</UiButton>
        <UiButton type="submit" variant="primary" :loading="saving">Save</UiButton>
      </div>
    </form>

    <div v-if="view?.enabled" class="mt-6 space-y-3 border-t border-slate-200 pt-6 dark:border-slate-800">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="text-sm">
          <p class="font-medium">Last sync</p>
          <p v-if="!status?.at" class="text-slate-500 dark:text-slate-400">Not synced yet. The first sync starts within a minute.</p>
          <p v-else class="text-slate-600 dark:text-slate-300">{{ ago(status.at) }}. {{ summary }}</p>
        </div>
        <UiButton size="sm" icon="refresh" :loading="syncing" @click="syncNow">Sync now</UiButton>
      </div>
      <UiNotice v-if="status?.error" tone="error" title="The latest sync failed">
        <p class="break-words whitespace-pre-line">{{ sentence(status.error) }}.</p>
        <p class="mt-1">
          <template v-if="status.failures > 1">It has failed {{ status.failures }} times in a row, since {{ dateTime(status.failing_since) }}. </template>
          Users already added keep their access, and the next sync tries again within 5 minutes.
        </p>
      </UiNotice>
      <UiNotice v-if="status?.held.length" tone="warning" title="This sync is waiting for you">
        <p>
          It would disable {{ plural(status.held.length, 'user') }} at once, so it disabled no one:
          <span class="font-mono">{{ some(status.held, 50) }}</span>.
        </p>
        <p class="mt-1">
          A group or a permission changed by mistake is more likely than that many people leaving together. Logins already
          ask Active Directory, so these users can't log in if their account is really gone. If the list is right, confirm
          it.
        </p>
        <div class="mt-3">
          <UiButton size="sm" variant="danger" :loading="confirming" @click="disableHeld">
            Disable {{ plural(status.held.length, 'user') }}
          </UiButton>
        </div>
      </UiNotice>
      <p v-if="passwordState" class="text-sm" :class="passwordState === 'fine' ? 'text-slate-600 dark:text-slate-300' : 'font-medium text-amber-800 dark:text-amber-300'">
        The service account's password {{ passwordState === 'expired' ? 'expired' : 'expires' }} on {{ day(status?.password_expires ?? 0) }}.
        <template v-if="passwordState !== 'fine'">Set a new one in Active Directory, then here.</template>
      </p>
      <div v-if="status?.unanswered.length" class="text-sm">
        <p class="font-medium text-amber-800 dark:text-amber-300">Didn't answer at the latest sync</p>
        <ul class="mt-1 space-y-1 font-mono text-xs break-words text-slate-600 dark:text-slate-300">
          <li v-for="line in status.unanswered" :key="line">{{ line }}</li>
        </ul>
        <p class="mt-1 text-slate-500 dark:text-slate-400">The next domain controller in the list answered instead. Logins skip one that doesn't answer until it does again.</p>
      </div>
      <div v-if="status?.skipped.length" class="text-sm">
        <p class="font-medium">Members not added</p>
        <ul class="mt-1 space-y-1 text-slate-600 dark:text-slate-300">
          <li v-for="skip in status.skipped" :key="skip.username + skip.reason">
            <span class="font-mono">{{ skip.username || '(no username)' }}</span>: {{ reason(skip) }}
          </li>
        </ul>
      </div>
    </div>
  </section>
</template>
