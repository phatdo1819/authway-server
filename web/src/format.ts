import type { AuthMode, LockMode, PasswordPolicy, Role } from './api'

// lockLabel says how the session of a server holds to the public IP of the login: a value this version doesn't know
// says so, rather than read as unlocked
export function lockLabel(lock: LockMode | string): string {
  switch (lock) {
    case 'strict':
      return 'Locked to the login IP'
    case 'roaming':
      return 'Not locked to an IP'
    default:
      return `Unknown lock (${lock})`
  }
}

// the lock of the session to the public IP of the login, on and off
export const lockOn =
  'If the device starts connecting from a different public IP than the one it logged in from, the session pauses. That usually means the device moved, or someone else is using its configuration. The session resumes if the original IP comes back, and ends after 5 minutes otherwise. Users who switch networks (from Wi-Fi to 4G, for example) have to log in again.'
export const lockOff =
  'Off: the session follows the device to a new network without a new login. Two devices using the same configuration at the same time are still detected, but a copy used while the real device is offline keeps the session.'

const alertKinds: Record<string, string> = {
  copy: 'Used by two devices',
  lockout: 'Locked out after failed logins',
  device_mismatch: 'Used on another device',
}

export function alertKind(kind: string): string {
  return alertKinds[kind] ?? kind
}

export function formatBytes(bytes: number): string {
  if (!bytes) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

// a rate of the network, given in bytes per second, written in bits per second as the links are
export function formatRate(bytesPerSecond: number): string {
  let value = bytesPerSecond * 8
  if (value < 1) {
    return '0 bit/s'
  }
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s']
  let unit = 0
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit++
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

export function formatPercent(value: number): string {
  return `${value < 10 && value > 0 ? value.toFixed(1) : Math.round(value)}%`
}

// how long something runs: 3 days 5 h, 5 h 12 min, 12 min
export function uptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days) {
    return `${days} ${days === 1 ? 'day' : 'days'}${hours ? ` ${hours} h` : ''}`
  }
  if (hours) {
    return `${hours} h${minutes ? ` ${minutes} min` : ''}`
  }
  return minutes ? `${minutes} min` : `${Math.max(0, Math.floor(seconds))} s`
}

export function dateTime(unix: number): string {
  if (!unix) {
    return '—'
  }
  return new Date(unix * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// a day, without the time
export function day(unix: number): string {
  return unix ? new Date(unix * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '—'
}

// an error of the server as a sentence: it starts with a lowercase letter
export function sentence(text: string): string {
  return text ? text[0].toUpperCase() + text.slice(1) : text
}

export function ago(unix: number): string {
  if (!unix) {
    return 'never'
  }
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - unix))
  if (seconds < 60) {
    return `${seconds} s ago`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)} min ago`
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)} h ago`
  }
  return dateTime(unix)
}

export function duration(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (hours >= 24 && hours % 24 === 0 && minutes === 0) {
    const days = hours / 24
    return days === 1 ? '1 day' : `${days} days`
  }
  if (hours && minutes) {
    return `${hours} h ${minutes} min`
  }
  if (hours) {
    return hours === 1 ? '1 hour' : `${hours} hours`
  }
  return `${minutes} min`
}

export const authModes: { value: AuthMode; label: string; description: string }[] = [
  { value: 'key', label: 'WireGuard key only', description: 'Peers connect with their configuration file alone. No login.' },
  {
    value: 'password',
    label: 'Password',
    description: 'Users log in with their password before the VPN lets their traffic through.',
  },
  {
    value: 'password_otp',
    label: 'Password and authenticator code',
    description: 'Users log in with their password and a code from an authenticator app.',
  },
]

// what the networks of a server see of its peers
export const routingModes: { value: boolean; label: string; description: string }[] = [
  {
    value: false,
    label: 'NAT',
    description: 'Your networks see all VPN traffic as coming from Authway Server. No router changes needed.',
  },
  {
    value: true,
    label: 'Routed',
    description:
      "Your networks see each peer's own VPN address, which is useful for logs and firewall rules. Your router needs a route back to the VPN through Authway Server (the server's panel shows which one). Internet traffic from peers still uses NAT.",
  },
]

export function authModeLabel(mode: AuthMode): string {
  return authModes.find((entry) => entry.value === mode)?.label ?? mode
}

const endReasons: Record<string, string> = {
  logout: 'Logged out',
  expired: 'Session expired',
  idle: 'No traffic for 5 minutes',
  ended_by_admin: 'Ended by an administrator',
  peer_changed: 'Peer changed',
  user_changed: 'User changed',
  server_changed: 'Server changed',
  endpoint_changed: 'Connected from another IP for 5 minutes',
  copy_suspected: 'Configuration used by two devices',
  blocked: 'Peer blocked',
  restored: 'Configuration restored',
  device_changed: 'Device revoked or replaced',
}

export function endReason(reason: string): string {
  return endReasons[reason] ?? reason
}

const eventKinds: Record<string, string> = {
  login_failed: 'Failed login',
  locked_out: 'Locked out for 15 minutes',
  session_paused: 'Session paused',
  session_resumed: 'Session resumed',
  copy_suspected: 'Used by two devices',
  admin_login: 'Administrator logged in',
  admin_login_failed: 'Failed administrator login',
  admin_added: 'Administrator added',
  admin_changed: 'Administrator changed',
  admin_deleted: 'Administrator deleted',
  admin_password_reset: 'Administrator password reset',
  admin_password_changed: 'Administrator changed their password',
  admin_mfa_on: 'Administrator set up an authenticator',
  admin_mfa_removed: "Administrator's authenticator removed",
  settings_changed: 'Settings changed',
  backup_made: 'Backup downloaded',
  backup_restored: 'Configuration restored',
  device_enrolled: 'Device enrolled',
  device_mismatch: 'Login from a different device',
  device_key: 'Device created its key',
  device_waiting: 'New device waiting for approval',
  host_address_changed: 'Docker host address changed',
  directory_failed: 'Active Directory sync failed',
  directory_restored: 'Active Directory sync works again',
  directory_held: 'Active Directory sync held users',
  directory_confirmed: 'Held users disabled',
  // the changes made in the web UI
  server_added: 'Server added',
  server_changed: 'Server changed',
  server_deleted: 'Server deleted',
  router_routes_updated: 'Router routes updated',
  peer_added: 'Peer added',
  peer_changed: 'Peer changed',
  peer_deleted: 'Peer deleted',
  peer_keys: 'New keys for a peer',
  peer_config: 'Configuration file viewed',
  session_ended: 'Session ended by an administrator',
  alerts_cleared: 'Alerts cleared',
  device_allowed: 'New device allowed',
  device_revoked: 'Device revoked',
  device_approved: 'Device approved',
  device_rejected: 'Device rejected',
  user_added: 'User added',
  user_changed: 'User changed',
  user_deleted: 'User deleted',
  user_mfa_on: 'New authenticator for a user',
  user_mfa_removed: "User's authenticator removed",
}

// the events of the web UI: the logins of the administrators and the changes (webKinds in internal/core/audit.go)
const webKinds = new Set([
  'directory_failed',
  'directory_restored',
  'directory_held',
  'directory_confirmed',
  'admin_login',
  'admin_login_failed',
  'admin_added',
  'admin_changed',
  'admin_deleted',
  'admin_password_reset',
  'admin_password_changed',
  'admin_mfa_on',
  'admin_mfa_removed',
  'settings_changed',
  'backup_made',
  'backup_restored',
  'server_added',
  'server_changed',
  'server_deleted',
  'router_routes_updated',
  'peer_added',
  'peer_changed',
  'peer_deleted',
  'peer_keys',
  'peer_config',
  'session_ended',
  'alerts_cleared',
  'device_allowed',
  'device_revoked',
  'device_approved',
  'device_rejected',
  'user_added',
  'user_changed',
  'user_deleted',
  'user_mfa_on',
  'user_mfa_removed',
])

export function eventTone(kind: string): 'red' | 'amber' | 'green' | 'gray' | 'sky' {
  switch (kind) {
    case 'locked_out':
    case 'copy_suspected':
    case 'admin_login_failed':
    case 'device_mismatch':
    case 'directory_failed':
      return 'red'
    case 'directory_held':
    case 'device_waiting':
      return 'amber'
    case 'directory_restored':
      return 'green'
    case 'server_deleted':
    case 'peer_deleted':
    case 'user_deleted':
    case 'admin_deleted':
    case 'peer_keys':
    case 'device_revoked':
    case 'device_rejected':
    case 'host_address_changed':
      return 'amber'
    case 'session_resumed':
    case 'admin_mfa_on':
    case 'device_enrolled':
    case 'device_key':
    case 'device_approved':
      return 'green'
    case 'admin_login':
    case 'admin_added':
    case 'admin_changed':
    case 'admin_password_reset':
    case 'admin_password_changed':
    case 'admin_mfa_removed':
    case 'settings_changed':
    case 'backup_made':
    case 'backup_restored':
      return 'sky'
    default:
      // the other changes of the web UI
      return webKinds.has(kind) ? 'sky' : 'amber'
  }
}

// the events of the web UI, not of a peer
export function isWebEvent(kind: string): boolean {
  return webKinds.has(kind)
}

export const roles: { value: Role; label: string; description: string }[] = [
  { value: 'admin', label: 'Administrator', description: 'Full access, including servers, administrators and settings.' },
  {
    value: 'operator',
    label: 'Operator',
    description: "Manages users, peers and their configuration files, sessions and alerts. Can't change servers, administrators or settings.",
  },
  { value: 'viewer', label: 'Read-only', description: "Can view servers, users and activity. Can't change anything or download configuration files." },
]

export function roleLabel(role: Role): string {
  return roles.find((entry) => entry.value === role)?.label ?? role
}

// the administrators have at least this, whatever the policy: see internal/core/policy.go
export const adminMinPassword = 12

// policyText says what a password needs, in a sentence
export function policyText(policy: PasswordPolicy | undefined, admin = false): string {
  if (!policy) {
    return ''
  }
  const length = admin ? Math.max(policy.min_length, adminMinPassword) : policy.min_length
  const needs: string[] = []
  if (policy.require_lower) needs.push('a lowercase letter')
  if (policy.require_upper) needs.push('an uppercase letter')
  if (policy.require_digit) needs.push('a digit')
  if (policy.require_symbol) needs.push('a symbol or a space')
  let text = `At least ${length} characters`
  if (needs.length) {
    text += ', with ' + (needs.length > 1 ? needs.slice(0, -1).join(', ') + ' and ' + needs[needs.length - 1] : needs[0])
  }
  return text + ". It can't contain the username."
}

// generatePassword makes a random password that follows any policy: 16 characters at least, easy to read and to
// type, one symbol
export function generatePassword(policy: PasswordPolicy | undefined, admin = false): string {
  const lower = 'abcdefghjkmnpqrstuvwxyz'
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  const digits = '23456789'
  const symbols = '-_.!?#%+='
  const all = lower + upper + digits
  const minimum = Math.max(16, policy?.min_length ?? 0, admin ? adminMinPassword : 0)
  // a random number below n, every one as likely: the values past the largest multiple of n under 2^32 are drawn again
  const below = (n: number) => {
    const limit = Math.floor(0x100000000 / n) * n
    const value = new Uint32Array(1)
    do {
      crypto.getRandomValues(value)
    } while (value[0] >= limit)
    return value[0] % n
  }
  const pick = (set: string) => set[below(set.length)]
  // one of each kind, the rest letters and digits, then shuffled
  const chars = [pick(lower), pick(upper), pick(digits), pick(symbols)]
  while (chars.length < minimum) {
    chars.push(pick(all))
  }
  for (let index = chars.length - 1; index > 0; index--) {
    const other = below(index + 1)
    ;[chars[index], chars[other]] = [chars[other], chars[index]]
  }
  return chars.join('')
}

export function eventKind(kind: string): string {
  return eventKinds[kind] ?? kind
}

// the messages of the validation codes of the server
const messages: Record<string, string> = {
  required: 'Required.',
  invalid: 'Not valid.',
  taken: 'Already in use.',
  too_many: 'Too many entries.',
  too_short: 'Too short.',
  too_long: 'Too long.',
  size: 'Use a network from /16 to /29.',
  overlap: 'Two of these networks overlap.',
  overlaps_tunnel: 'Overlaps the VPN network.',
  overlaps_stand_ins: 'Overlaps the addresses Authway Server gives to internet names (AUTHWAY_STAND_IN_NETWORK, 198.18.0.0/16 by default).',
  size6: 'Use an IPv6 network from /64 to /120.',
  too_small: 'Must be at least as large as the IPv4 network, because every peer gets an address in both.',
  needs_ipv6: 'Set an IPv6 VPN network first. Without it, peers have no IPv6 address.',
  ipv6_off: 'IPv6 is turned off for Authway Server. Enable it as compose.yaml shows, then recreate the container.',
  no_networks: 'Add at least one network for peers to reach. Only these networks are routed; internet traffic still uses NAT.',
  has_peers: "Can't be changed while the server has peers, because their configuration files use the current addresses.",
  outside: "Not inside this server's networks.",
  names_only: 'This server has no networks, so enter only names, such as app.example.com.',
  invalid_ports: 'Enter ports from 1 to 65535: one such as 443, several such as 80, 443, or a range such as 8000-8090, up to 32 in a rule.',
  in_peer_access: 'A peer still has access to part of a network you removed. Change that peer first.',
  has_peer: 'This user already has a peer on this server.',
  network_full: "No free addresses left in this server's network.",
  wrong: 'Wrong password.',
  duplicate: "An address is listed twice, or is the server's own public address.",
  needs_lower: 'Add a lowercase letter.',
  needs_upper: 'Add an uppercase letter.',
  needs_digit: 'Add a digit.',
  needs_symbol: 'Add a symbol or a space.',
  contains_username: "Can't contain the username.",
  same: 'Choose a password different from the current one.',
  wrong_code: "Wrong code. Make sure the phone's clock is correct, then enter the latest code.",
  invalid_otp: "That code doesn't match. Make sure the phone's clock is correct, then enter the current code.",
  no_otp: 'This user no longer has an authenticator.',
  otp_in_use: 'This authenticator is already in use.',
  own_account: "You can't change this on your own account.",
  last_admin: 'This is the last active administrator. Give another account the Administrator role first.',
  enroll_first: 'Set up your own authenticator first, under Your account.',
  same_server: "A server can't be in its own list.",
  server_not_found: 'One of these servers no longer exists. Reload the page.',
  duplicate_server: 'A server is listed twice.',
  device_binding_not_required: "This server doesn't require enrolled devices.",
  not_waiting: 'No device is waiting for approval anymore. Someone may have approved or rejected it already.',
  directory: 'This comes from Active Directory. Change it there.',
  // the rows of an import
  twice: 'This username already appears in an earlier row.',
  extra_cells: 'This row has more cells than the header has columns.',
}

export function fieldMessage(code: string | undefined): string {
  if (!code) {
    return ''
  }
  return messages[code] ?? code
}

export function errorMessage(error: unknown): string {
  const code = (error as { code?: string })?.code ?? ''
  switch (code) {
    case 'unreachable':
      return "Authway Server isn't responding."
    case 'not_found':
      return 'This item no longer exists. Reload the page.'
    case 'validation':
      return 'Check the fields marked in red.'
    case 'changed':
      return 'Another administrator saved changes in the meantime. Open it again to see them.'
    case 'too_many_attempts':
      return 'Too many attempts. Wait a few minutes and try again.'
    case 'invalid_credentials':
      return 'Wrong username or password.'
    case 'invalid_otp':
      return 'Wrong code. Enter the latest code from your app.'
    case 'disabled':
      return 'This account is disabled. Ask another administrator for help.'
    case 'not_allowed':
      return "Your role can't do this."
    case 'setup_required':
      return 'Finish setting up your account first.'
    case 'own_account':
      return "You can't do this on your own account."
    case 'last_admin':
      return 'This is the last active administrator. Give another account the Administrator role first.'
    case 'mfa_required':
      return 'Settings require every administrator to use an authenticator. You can replace it, but not remove it.'
    case 'setup_expired':
      return 'Setup took longer than 10 minutes. Start again.'
    case 'directory_off':
      return 'Turn on Active Directory sync and save first.'
    default:
      return 'Something went wrong. Try again.'
  }
}
