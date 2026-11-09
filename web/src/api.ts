// The JSON API of the server, see internal/admin. Every request carries X-Requested-With: the server refuses the
// ones without it, which a page of another site can't send.

export type AuthMode = 'key' | 'password' | 'password_otp'
export type LockMode = 'strict' | 'roaming' | 'off'

export interface Server {
  id: number
  name: string
  interface: string
  enabled: boolean
  public_host: string
  listen_port: number
  public_port: number
  network: string
  address: string
  // "" without an IPv6 network: the IPv6 network of the tunnel and the address of the server in it
  network6: string
  address6: string
  networks: string[]
  dns: string[]
  mtu: number
  keepalive: number
  auth_mode: AuthMode
  session_timeout: number
  lock_endpoint: LockMode
  detect_copies: boolean
  block_copies: boolean
  redirect: boolean
  fallback_endpoints: string[]
  // only with a login: the peers log in from their enrolled device, and with machine_id from its computer
  device_binding: boolean
  machine_id: boolean
  // the peers reach each other, and the peers of the servers listed (by id), one way
  client_to_client: boolean
  reachable_servers: number[]
  // the networks see the address of each peer, not the one of the container; inbound: they start connections to
  // the peers too
  routed: boolean
  inbound: boolean
  // routed: what the router of the networks needs
  routes?: Route[]
  public_key: string
  login_url?: string
  peers: number
  // the peers with no user: with a login they can't log in until they get one
  peers_without_user: number
  connected: number
  sessions: number
  created_at: number
  updated_at: number
}

export type ServerInput = Pick<
  Server,
  | 'name'
  | 'enabled'
  | 'public_host'
  | 'listen_port'
  | 'public_port'
  | 'network'
  | 'network6'
  | 'networks'
  | 'dns'
  | 'mtu'
  | 'keepalive'
  | 'auth_mode'
  | 'session_timeout'
  | 'lock_endpoint'
  | 'detect_copies'
  | 'block_copies'
  | 'redirect'
  | 'fallback_endpoints'
  | 'device_binding'
  | 'machine_id'
  | 'client_to_client'
  | 'reachable_servers'
  | 'routed'
  | 'inbound'
>

// a route to the tunnel network through the address of the container (via, "" when unknown) towards a network;
// driver: macvlan works, veth (a Docker bridge) needs the routes of the Docker host, ipvlan doesn't work
export interface Route {
  tunnel: string
  network: string
  via: string
  driver: string
  // on a Docker bridge: what the helper of compose.host-routes.yaml did. address: the Docker host, for the router
  host?: HostRoute
}

export interface HostRoute {
  state: 'off' | 'stopped' | 'pending' | 'routed' | 'failed'
  address: string
  // the address of before, when address changed: the router still has the route through it
  previous?: string
  error: string
}

// what the server proposes: free values; ipv6_off says why the tunnels can't carry IPv6, network6 is then empty
export type ServerSuggestion = ServerInput & { ipv6_off?: string }

export interface Session {
  id: number
  server_id: number
  server_name: string
  peer_id: number
  peer_name: string
  user_id: number
  username: string
  address: string
  endpoint: string
  started_at: number
  expires_at: number
  ended_at: number
  end_reason: string
  paused_at: number
}

export interface Alert {
  id: number
  peer_id: number
  peer_name: string
  server_id: number
  server_name: string
  blocked: boolean
  at: number
  kind: string
  username: string
  addresses: string[]
}

export interface Peer {
  id: number
  server_id: number
  name: string
  enabled: boolean
  user_id: number
  username: string
  address: string
  // "" when the server has no IPv6 network: the address of the IPv4 one in it
  address6: string
  public_key: string
  route_all: boolean
  blocked: boolean
  alerts: number
  connected: boolean
  last_handshake: number
  endpoint: string
  received: number
  sent: number
  session: Session | null
  // only on a server with device binding
  device: PeerDevice | null
  created_at: number
  updated_at: number
}

// the device of a peer: enrolled, waiting for one (until enrollment_until) or closed (an administrator allows one)
export interface PeerDevice {
  state: 'enrolled' | 'waiting' | 'closed'
  enrollment_until: number
  name: string
  kind: string
  // a machine ID is recorded
  machine_id: boolean
  enrolled_at: number
  last_used_at: number
  last_from: string
  // the key the peer connects with: the one of its configuration file, or the one its device made
  wireguard_key: '' | 'configuration' | 'device'
  wireguard_key_at: number
}

// a run of handshakes of a peer from one public IP
export interface Connection {
  id: number
  server_id: number
  server_name: string
  peer_id: number
  peer_name: string
  username: string
  address: string
  endpoint: string
  started_at: number
  last_seen: number
  ended_at: number
  received: number
  sent: number
  connected: boolean
}

export interface PeerInput {
  name: string
  enabled: boolean
  user_id: number
  route_all: boolean
  address?: string
}

export interface User {
  id: number
  username: string
  full_name: string
  disabled: boolean
  totp: boolean
  peers: string[]
  sessions: number
  created_at: number
  updated_at: number
}

export interface UserInput {
  username: string
  full_name: string
  password: string
  disabled: boolean
}

export interface EventItem {
  id: number
  at: number
  kind: string
  server_name: string
  peer_name: string
  username: string
  source: string
  detail: string
  // the administrator who made the change, for the events of the web UI
  by: string
}

// a page of a history list, and how many rows match the filter in all
export interface Page<T> {
  items: T[]
  total: number
}

// the filter of the history lists of Activity: q, the words to find; server, its id; since and until, Unix times;
// type, for the events: the ones of the web UI or of the peers
export interface HistoryFilter {
  q?: string
  server?: number
  since?: number
  until?: number
  type?: '' | 'web' | 'vpn'
  limit?: number
  offset?: number
}

export type HistoryList = 'history' | 'connections' | 'events'

function query(filter: HistoryFilter): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filter)) {
    if (value !== undefined && value !== '' && value !== 0) {
      params.set(key, String(value))
    }
  }
  const text = params.toString()
  return text ? '?' + text : ''
}

// The System page, see internal/system: the sizes in bytes, the rates in bytes per second, the shares in percent
export type CheckStatus = 'ok' | 'warning' | 'error' | 'unknown'

export interface SystemCheck {
  id: string
  status: CheckStatus
  title: string
  detail: string
}

export interface SystemInterface {
  name: string
  kind: 'ethernet' | 'wireguard' | 'loopback' | 'other'
  up: boolean
  mtu: number
  addresses: string[]
  received: number
  sent: number
  received_bytes: number
  sent_bytes: number
  received_packets: number
  sent_packets: number
  errors: number
  drops: number
}

export interface SystemDisk {
  // data: the folder of the database; system: the root of the container, on another disk
  name: 'data' | 'system'
  path: string
  total: number
  used: number
  available: number
  inodes: number
  inodes_free: number
}

export interface SystemSnapshot {
  at: number
  // made up: the server doesn't run on Linux
  simulated: boolean
  host: {
    hostname: string
    kernel: string
    os: string
    timezone: string
    container: boolean
    processors: number
    uptime: number
    load: [number, number, number]
    cpu: number
    iowait: number
    memory_total: number
    memory_available: number
    swap_total: number
    swap_free: number
    clock_synced: boolean | null
  }
  authway: {
    version: string
    go_version: string
    platform: string
    started: number
    cpu: number
    memory: number
    memory_limit: number
    heap: number
    goroutines: number
    open_files: number
    max_files: number
  }
  interfaces: SystemInterface[]
  disks: SystemDisk[]
  database: { size: number; log: number }
  ip_forward: boolean | null
  ipv6_on: boolean | null
  ipv6_forward: boolean | null
  ipv6_route: boolean | null
  // max 0: unknown
  conntrack: { count: number; max: number }
  // null without HTTPS, behind a reverse proxy
  certificate: { not_after: number; self_signed: boolean; names: string[]; error: string } | null
  checks: SystemCheck[]
}

export interface SystemPoint {
  at: number
  cpu: number
  own_cpu: number
  memory: number
  own_memory: number
  // received and sent, by interface
  network: Record<string, [number, number]>
}

export interface SystemHistory {
  // seconds between two points
  step: number
  memory_total: number
  points: SystemPoint[]
}

export interface LogEntry {
  at: number
  level: 'debug' | 'info' | 'warn' | 'error'
  message: string
  attrs: string
}

export interface Status {
  apply_error: string
  servers: number
  peers: number
  connected: number
  sessions: number
  login_port: number
  version: string
  // the routes to change on the routers: the address of the Docker host changed
  host_changes: HostAddressChange[]
}

export interface HostAddressChange {
  server: string
  tunnel: string
  address: string
  // the address the router still has
  previous: string
  at: number
}

export interface PasswordPolicy {
  min_length: number
  require_lower: boolean
  require_upper: boolean
  require_digit: boolean
  require_symbol: boolean
}

export interface Settings {
  public_host: string
  password_policy: PasswordPolicy
  require_admin_mfa: boolean
  // with device binding, the hours a new peer can enroll its device
  enroll_hours: number
  // the days Activity keeps the history
  history_days: number
}

// admin: everything; operator: the users, the peers and the sessions; viewer: sees, changes nothing
export type Role = 'admin' | 'operator' | 'viewer'
// what an administrator must do before the rest of the web UI
export type SetupStep = '' | 'password' | 'mfa'

export interface Me {
  id: number
  username: string
  full_name: string
  role: Role
  totp: boolean
  setup: SetupStep
  require_admin_mfa: boolean
  password_policy: PasswordPolicy
}

export interface AdminAccount {
  id: number
  username: string
  full_name: string
  role: Role
  totp: boolean
  disabled: boolean
  must_change_password: boolean
  last_login_at: number
  last_login_from: string
  created_at: number
  updated_at: number
}

export interface AdminInput {
  username: string
  full_name: string
  role: Role
  disabled: boolean
  // only when added: the first password, changed at the first login
  password?: string
}

export interface TotpSetup {
  secret: string
  uri: string
}

// what a backup has, before a restore
export interface BackupSummary {
  created_at: number
  made_by: string
  servers: number
  peers: number
  users: number
  administrators: number
  // the enabled administrators with the role Administrator: they can log in after the restore
  admin_usernames: string[]
  // the administrator logged in is in the backup: the same username logs in after the restore
  includes_you: boolean
}

export class ApiError extends Error {
  status: number
  code: string
  fields: Record<string, string>
  // what's wrong, in words, when a code isn't enough: the content of a backup
  detail: string

  constructor(status: number, code: string, fields: Record<string, string> = {}, detail = '') {
    super(code)
    this.status = status
    this.code = code
    this.fields = fields
    this.detail = detail
  }
}

let onUnauthorized: () => void = () => {}
let onSetupRequired: (step: SetupStep) => void = () => {}

// the router sends the user back to the login page when the session of the web UI ends
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler
}

// and to the setup of the account when the server asks for it first
export function setSetupRequiredHandler(handler: (step: SetupStep) => void) {
  onSetupRequired = handler
}

async function send(method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { 'X-Requested-With': 'authway', Accept: 'application/json' }
  const init: RequestInit = { method, headers, credentials: 'same-origin', cache: 'no-store' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  let response: Response
  try {
    response = await fetch('/api' + path, init)
  } catch {
    throw new ApiError(0, 'unreachable')
  }
  if (!response.ok) {
    let data: { error?: string; fields?: Record<string, string>; setup?: SetupStep; detail?: string } = {}
    try {
      data = await response.json()
    } catch {
      // not JSON: the status says enough
    }
    if (response.status === 401 && path !== '/login') {
      onUnauthorized()
    }
    if (response.status === 403 && data.error === 'setup_required' && data.setup) {
      onSetupRequired(data.setup)
    }
    throw new ApiError(response.status, data.error ?? 'http_' + response.status, data.fields ?? {}, data.detail ?? '')
  }
  return response
}

async function json<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await send(method, path, body)
  return (await response.json()) as T
}

export const api = {
  login: (username: string, password: string, otp = '') =>
    json<{ username: string; role: Role; setup: SetupStep }>('POST', '/login', { username, password, otp }),
  logout: () => json('POST', '/logout'),
  me: () => json<Me>('GET', '/me'),
  startTotp: (password: string) => json<TotpSetup>('POST', '/me/totp', { password }),
  confirmTotp: (code: string) => json('PUT', '/me/totp', { code }),
  removeMyTotp: (password: string) => json('DELETE', '/me/totp', { password }),

  admins: () => json<AdminAccount[]>('GET', '/admins'),
  createAdmin: (input: AdminInput) => json<AdminAccount>('POST', '/admins', input),
  updateAdmin: (id: number, input: AdminInput) => json<AdminAccount>('PUT', `/admins/${id}`, input),
  deleteAdmin: (id: number) => json('DELETE', `/admins/${id}`),
  resetAdminPassword: (id: number, password: string) => json('PUT', `/admins/${id}/password`, { password }),
  removeAdminTotp: (id: number) => json('DELETE', `/admins/${id}/totp`),
  changePassword: (current: string, password: string) => json('PUT', '/me/password', { current, password }),
  status: () => json<Status>('GET', '/status'),
  // the routers have the routes through the new addresses of the Docker host
  confirmHostAddresses: () => json('POST', '/host-addresses/confirm'),
  system: () => json<SystemSnapshot>('GET', '/system'),
  // the points of the latest seconds, after since only
  systemHistory: (seconds: number, since = 0) =>
    json<SystemHistory>('GET', `/system/history?range=${seconds}${since ? `&since=${since}` : ''}`),
  // the warnings and the errors, or all the latest lines
  systemLog: (all = false) => json<LogEntry[]>('GET', `/system/log${all ? '?level=all' : ''}`),
  settings: () => json<Settings>('GET', '/settings'),
  saveSettings: (settings: Partial<Settings>) => json<Settings>('PUT', '/settings', settings),
  // the file of a backup: the whole configuration, sealed with the passphrase
  async backup(password: string, passphrase: string): Promise<{ name: string; text: string }> {
    const response = await send('POST', '/backup', { password, passphrase })
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const match = /filename="?([^";]+)"?/.exec(disposition)
    return { name: match?.[1] ?? 'authway-backup.json', text: await response.text() }
  },
  checkBackup: (passphrase: string, backup: string) => json<BackupSummary>('POST', '/restore/check', { passphrase, backup }),
  restore: (password: string, passphrase: string, backup: string) =>
    json<BackupSummary>('POST', '/restore', { password, passphrase, backup }),

  servers: () => json<Server[]>('GET', '/servers'),
  // for a new server, or with serverId the values that server can take, its IPv6 network
  serverDefaults: (serverId?: number) =>
    json<ServerSuggestion>('GET', serverId ? `/servers/defaults?server=${serverId}` : '/servers/defaults'),
  createServer: (input: ServerInput) => json<Server>('POST', '/servers', input),
  updateServer: (id: number, input: ServerInput) => json<Server>('PUT', `/servers/${id}`, input),
  deleteServer: (id: number) => json('DELETE', `/servers/${id}`),

  peers: (serverId: number) => json<Peer[]>('GET', `/servers/${serverId}/peers`),
  createPeer: (serverId: number, input: PeerInput) => json<Peer>('POST', `/servers/${serverId}/peers`, input),
  updatePeer: (id: number, input: PeerInput) => json<Peer>('PUT', `/peers/${id}`, input),
  deletePeer: (id: number) => json('DELETE', `/peers/${id}`),
  newPeerKeys: (id: number) => json<Peer>('POST', `/peers/${id}/keys`),
  logoutPeer: (id: number) => json('POST', `/peers/${id}/logout`),
  peerAlerts: (id: number) => json<Alert[]>('GET', `/peers/${id}/alerts`),
  clearPeerAlerts: (id: number) => json('DELETE', `/peers/${id}/alerts`),
  // hours 0: the ones of the settings
  allowDevice: (id: number, hours = 0) => json<Peer>('POST', `/peers/${id}/device`, { hours }),
  revokeDevice: (id: number) => json<Peer>('DELETE', `/peers/${id}/device`),
  alerts: (limit = 200) => json<Alert[]>('GET', `/alerts?limit=${limit}`),
  async peerConfig(id: number): Promise<{ name: string; text: string }> {
    const response = await send('GET', `/peers/${id}/config`)
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const match = /filename="?([^";]+)"?/.exec(disposition)
    return { name: match?.[1] ?? 'wireguard.conf', text: await response.text() }
  },

  users: () => json<User[]>('GET', '/users'),
  createUser: (input: UserInput) => json<User>('POST', '/users', input),
  updateUser: (id: number, input: UserInput) => json<User>('PUT', `/users/${id}`, input),
  deleteUser: (id: number) => json('DELETE', `/users/${id}`),
  setupTotp: (id: number) => json<TotpSetup>('POST', `/users/${id}/totp`),
  removeTotp: (id: number) => json('DELETE', `/users/${id}/totp`),

  sessions: () => json<Session[]>('GET', '/sessions'),
  endSession: (id: number) => json('DELETE', `/sessions/${id}`),
  history: (filter: HistoryFilter = {}) => json<Page<Session>>('GET', '/history' + query(filter)),
  connections: (filter: HistoryFilter = {}) => json<Page<Connection>>('GET', '/connections' + query(filter)),
  events: (filter: HistoryFilter = {}) => json<Page<EventItem>>('GET', '/events' + query(filter)),
  // every row of a list that matches the filter, as a CSV file
  async historyCSV(list: HistoryList, filter: HistoryFilter): Promise<{ name: string; text: string }> {
    const response = await send('GET', `/${list}/csv` + query({ ...filter, limit: undefined, offset: undefined }))
    const disposition = response.headers.get('Content-Disposition') ?? ''
    const match = /filename="?([^";]+)"?/.exec(disposition)
    return { name: match?.[1] ?? `authway-${list}.csv`, text: await response.text() }
  },
}
