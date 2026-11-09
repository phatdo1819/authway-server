import type { AuthMode, LockMode, PasswordPolicy, Role } from './api'

export const lockModes: { value: LockMode; label: string; description: string }[] = [
  {
    value: 'strict',
    label: 'Strict',
    description:
      'The session pauses while the peer sends from another public IP than at login: another device has its key, or the device moved. It resumes when the IP comes back, and ends after 5 minutes. A user who moves logs in again.',
  },
  {
    value: 'roaming',
    label: 'Roaming',
    description:
      'The session follows the device to its new network. Two devices at once are still caught, but a copy used while the real device is off keeps the session.',
  },
  { value: 'off', label: 'Off', description: 'The public IP is ignored: for clients behind a NAT that changes their IP.' },
]

export function lockModeLabel(mode: LockMode): string {
  return lockModes.find((entry) => entry.value === mode)?.label ?? mode
}

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
  { value: 'key', label: 'WireGuard key only', description: 'The peers connect with their configuration file, no login.' },
  {
    value: 'password',
    label: 'Password',
    description: 'The peers log in with the password of their user before their traffic passes.',
  },
  {
    value: 'password_otp',
    label: 'Password and authenticator code',
    description: 'The peers log in with the password and a code of an authenticator app.',
  },
]

// what the networks of a server see of its peers
export const routingModes: { value: boolean; label: string; description: string }[] = [
  {
    value: false,
    label: 'NAT',
    description: 'The networks see the address of the container. Nothing to set up on the router.',
  },
  {
    value: true,
    label: 'Routed',
    description:
      'The networks see the address of each peer, for their logs and firewall rules. Their router needs a route to the tunnel networks through the Docker host, with compose.host-routes.yaml, or through the container on macvlan. The internet of the peers stays NAT.',
  },
]

export function authModeLabel(mode: AuthMode): string {
  return authModes.find((entry) => entry.value === mode)?.label ?? mode
}

const endReasons: Record<string, string> = {
  logout: 'Logged out',
  expired: 'Session expired',
  idle: 'No handshake for 5 minutes',
  ended_by_admin: 'Ended by an administrator',
  peer_changed: 'Peer changed',
  user_changed: 'User changed',
  server_changed: 'Server changed',
  endpoint_changed: 'Another public IP for 5 minutes',
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
  admin_password_changed: 'Administrator changed the password',
  admin_mfa_on: 'Administrator authenticator set up',
  admin_mfa_removed: 'Administrator authenticator removed',
  settings_changed: 'Settings changed',
  backup_made: 'Backup downloaded',
  backup_restored: 'Configuration restored',
  device_enrolled: 'Device enrolled',
  device_mismatch: 'Another device',
  device_key: 'Device made its own key',
  host_address_changed: 'Docker host address changed',
  // the changes made in the web UI
  server_added: 'Server added',
  server_changed: 'Server changed',
  server_deleted: 'Server deleted',
  router_routes_updated: 'Router routes updated',
  peer_added: 'Peer added',
  peer_changed: 'Peer changed',
  peer_deleted: 'Peer deleted',
  peer_keys: 'New keys for a peer',
  peer_config: 'Configuration file opened',
  session_ended: 'Session ended by an administrator',
  alerts_cleared: 'Alerts cleared',
  device_allowed: 'New device allowed',
  device_revoked: 'Device revoked',
  user_added: 'User added',
  user_changed: 'User changed',
  user_deleted: 'User deleted',
  user_mfa_on: 'User authenticator set up',
  user_mfa_removed: 'User authenticator removed',
}

// the events of the web UI: the logins of the administrators and the changes (webKinds in internal/core/audit.go)
const webKinds = new Set([
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
      return 'red'
    case 'server_deleted':
    case 'peer_deleted':
    case 'user_deleted':
    case 'admin_deleted':
    case 'peer_keys':
    case 'device_revoked':
    case 'host_address_changed':
      return 'amber'
    case 'session_resumed':
    case 'admin_mfa_on':
    case 'device_enrolled':
    case 'device_key':
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
  { value: 'admin', label: 'Administrator', description: 'Everything: the servers, the administrators and the settings too.' },
  {
    value: 'operator',
    label: 'Operator',
    description: 'The users, the peers and their configuration files, the sessions and the alerts. Not the servers, the administrators or the settings.',
  },
  { value: 'viewer', label: 'Read-only', description: 'Sees the servers, the users and the activity. Changes nothing, and gets no configuration file.' },
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
  return text + ', without the username.'
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
  taken: 'Already used by another one.',
  too_many: 'Too many.',
  too_short: 'Too short.',
  too_long: 'Too long.',
  size: 'Use a network from /16 to /29.',
  overlap: 'Two of these networks overlap.',
  overlaps_tunnel: 'Overlaps a network of the tunnel.',
  size6: 'Use an IPv6 network from /64 to /120.',
  too_small: 'Smaller than the IPv4 network: each peer needs its address in both.',
  needs_ipv6: 'An IPv6 network needs the IPv6 tunnel network: the peers have no IPv6 address without it.',
  ipv6_off: 'IPv6 is off in the container: turn it on as compose.yaml does, then create the container again.',
  no_networks: 'Add a network the peers reach: only those are routed, the internet of the peers stays NAT.',
  has_peers: "Can't change while the server has peers: their configuration files have the old addresses.",
  has_peer: 'This user already has a peer on this server.',
  network_full: 'No address left in the network of the server.',
  wrong: 'Wrong password.',
  duplicate: 'An address appears twice, or is the public address of the server.',
  needs_lower: 'Add a lowercase letter.',
  needs_upper: 'Add an uppercase letter.',
  needs_digit: 'Add a digit.',
  needs_symbol: 'Add a symbol or a space.',
  contains_username: "Can't contain the username.",
  same: 'Choose another one than the current password.',
  wrong_code: 'Wrong code: check the time of the phone, and type the latest code.',
  own_account: "Can't change on your own account.",
  last_admin: 'The last active Administrator keeps this role: give it to another one first.',
  enroll_first: 'Set up your own authenticator first, in Your account.',
  same_server: "A server can't be in its own list.",
  server_not_found: 'One of these servers no longer exists: reload the page.',
  duplicate_server: 'A server appears twice.',
  device_binding_not_required: "This server doesn't ask for a device.",
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
      return "The server doesn't answer."
    case 'not_found':
      return 'It no longer exists: reload the page.'
    case 'validation':
      return 'Check the fields in red.'
    case 'too_many_attempts':
      return 'Too many attempts: wait a few minutes.'
    case 'invalid_credentials':
      return 'Wrong username or password.'
    case 'invalid_otp':
      return 'Wrong code: type the latest code of the app.'
    case 'disabled':
      return 'This account is disabled: ask another administrator.'
    case 'not_allowed':
      return "Your role can't do this."
    case 'setup_required':
      return 'Finish the setup of your account first.'
    case 'own_account':
      return "You can't do this on your own account."
    case 'last_admin':
      return 'The last active Administrator stays: give the role to another one first.'
    case 'mfa_required':
      return 'The settings ask an authenticator of every administrator: it can be replaced, not removed.'
    case 'setup_expired':
      return 'The setup took more than 10 minutes: start again.'
    default:
      return 'Something went wrong. Try again.'
  }
}
