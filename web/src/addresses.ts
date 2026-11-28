// The IPv4 addresses of the peers in the tunnel network of their server, with the rules of peerAddress and
// freeAddress in internal/core/service.go and peers.go: not the network, the broadcast or the address of the server
// (the first one), and one address for each peer.

interface Tunnel {
  network: number
  broadcast: number
  cidr: string
}

// parseIPv4 reads a dotted address, like Go's netip: four numbers up to 255, no leading zeros
export function parseIPv4(text: string): number | null {
  const parts = text.split('.')
  if (parts.length !== 4) {
    return null
  }
  let value = 0
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) {
      return null
    }
    value = value * 256 + Number(part)
  }
  return value
}

export function formatIPv4(value: number): string {
  return [Math.floor(value / 2 ** 24) % 256, Math.floor(value / 2 ** 16) % 256, Math.floor(value / 256) % 256, value % 256].join('.')
}

function parseTunnel(cidr: string): Tunnel | null {
  const [address, bits] = cidr.split('/')
  const value = parseIPv4(address ?? '')
  const length = Number(bits)
  if (value === null || !/^[0-9]{1,2}$/.test(bits ?? '') || length > 32) {
    return null
  }
  const size = 2 ** (32 - length)
  const network = Math.floor(value / size) * size
  return { network, broadcast: network + size - 1, cidr: `${formatIPv4(network)}/${length}` }
}

// networkOf is an IPv4 network without its host part, 192.168.1.0/24 for 192.168.1.7/24, or '' when the text isn't
// one: an IPv6 network for example
export function networkOf(cidr: string): string {
  return parseTunnel(cidr.trim())?.cidr ?? ''
}

// anyAddressOf writes any address of an IPv4 network. With a length of /8, /16 or /24, x for the numbers that change
// in it: 192.168.1.x for 192.168.1.0/24. Else one address of it, the one offset from its start: 10.0.16.2 for
// 10.0.16.0/20 with offset 2, as 10.0.x.x would read the same for 10.0.32.0/20. '' when the text isn't an IPv4 network.
export function anyAddressOf(cidr: string, offset = 2): string {
  const tunnel = parseTunnel(cidr.trim())
  if (!tunnel) {
    return ''
  }
  const [address = '', bits = ''] = tunnel.cidr.split('/')
  const length = Number(bits)
  if (length % 8 === 0 && length > 0 && length < 32) {
    const kept = length / 8
    return address
      .split('.')
      .map((part, index) => (index < kept ? part : 'x'))
      .join('.')
  }
  // inside the network, before its broadcast address when it's that small
  const last = Math.max(tunnel.network, tunnel.broadcast - 1)
  return formatIPv4(Math.min(tunnel.network + offset, last))
}

// nextFreeAddress is the first address of the network that no peer has, as the server chooses it, or '' when the
// network is full
export function nextFreeAddress(cidr: string, used: string[]): string {
  const tunnel = parseTunnel(cidr)
  if (!tunnel) {
    return ''
  }
  const taken = new Set(used.map(parseIPv4))
  for (let value = tunnel.network + 2; value < tunnel.broadcast; value++) {
    if (!taken.has(value)) {
      return formatIPv4(value)
    }
  }
  return ''
}

// addressProblem says why an address can't go to a new peer, or '' when it can. Empty is fine: the server chooses.
export function addressProblem(text: string, cidr: string, peers: { name: string; address: string }[]): string {
  const address = text.trim()
  if (!address) {
    return ''
  }
  const value = parseIPv4(address)
  const tunnel = parseTunnel(cidr)
  if (value === null) {
    return 'Not an IPv4 address, like 10.8.0.5.'
  }
  if (!tunnel) {
    return ''
  }
  const next = nextFreeAddress(cidr, peers.map((peer) => peer.address))
  const suggestion = next ? ` The next free one is ${next}.` : ''
  if (value < tunnel.network || value > tunnel.broadcast) {
    return `Not in the tunnel network of the server, ${tunnel.cidr}.${suggestion}`
  }
  if (value === tunnel.network) {
    return `The address of the network itself can't go to a peer.${suggestion}`
  }
  if (value === tunnel.broadcast) {
    return `The broadcast address of the network can't go to a peer.${suggestion}`
  }
  if (value === tunnel.network + 1) {
    return `The address of the server.${suggestion}`
  }
  const owner = peers.find((peer) => parseIPv4(peer.address) === value)
  if (owner) {
    return `Already used by the peer ${owner.name}.${suggestion}`
  }
  return ''
}

// IPv6: a server with an IPv6 network gives each peer the address in the same place of it as its IPv4 one, as
// address6 does in internal/core/ipv6.go: 10.8.0.5 in 10.8.0.0/24 is fd12:3456:789a:1::5 in fd12:3456:789a:1::/64.

// parseIPv6 reads an IPv6 address into its 8 groups, null when it isn't one: no zone, no IPv4 part
export function parseIPv6(text: string): number[] | null {
  if (!/^[0-9a-fA-F:]{2,39}$/.test(text)) {
    return null
  }
  const halves = text.split('::')
  if (halves.length > 2) {
    return null
  }
  const groupsOf = (part: string) => (part === '' ? [] : part.split(':'))
  const head = groupsOf(halves[0] ?? '')
  const tail = halves.length === 2 ? groupsOf(halves[1] ?? '') : []
  const all = [...head, ...tail]
  if (all.some((group) => !/^[0-9a-fA-F]{1,4}$/.test(group)) || (halves.length === 1 ? all.length !== 8 : all.length > 7)) {
    return null
  }
  const zeros = halves.length === 2 ? 8 - all.length : 0
  return [...head, ...Array<string>(zeros).fill('0'), ...tail].map((group) => parseInt(group, 16))
}

// formatIPv6 writes the 8 groups as Go and the browsers do (RFC 5952): lower case, the longest run of zeros as ::
export function formatIPv6(groups: number[]): string {
  let start = -1
  let length = 1
  for (let index = 0; index < 8; ) {
    if (groups[index] !== 0) {
      index++
      continue
    }
    let end = index
    while (end < 8 && groups[end] === 0) {
      end++
    }
    if (end - index > length) {
      start = index
      length = end - index
    }
    index = end
  }
  const hex = groups.map((group) => group.toString(16))
  if (start < 0) {
    return hex.join(':')
  }
  return `${hex.slice(0, start).join(':')}::${hex.slice(start + length).join(':')}`
}

// address6Of is the IPv6 address of an IPv4 address of the tunnel, '' without an IPv6 network or a valid address
export function address6Of(address: string, network: string, network6: string): string {
  const tunnel = parseTunnel(network)
  const value = parseIPv4(address.trim())
  const [base, bitsText] = network6.split('/')
  const groups = parseIPv6(base ?? '')
  const bits = Number(bitsText)
  if (!tunnel || value === null || !groups || !/^[0-9]{2,3}$/.test(bitsText ?? '') || bits < 64 || bits > 120) {
    return ''
  }
  if (value < tunnel.network || value > tunnel.broadcast) {
    return ''
  }
  const offset = value - tunnel.network
  if (offset >= 2 ** Math.min(16, 128 - bits)) {
    return ''
  }
  // the network part only; the offset goes in the last group, whose host part is long enough for it
  const masked = groups.map((group, index) => {
    const keep = Math.min(16, Math.max(0, bits - 16 * index))
    return keep === 0 ? 0 : group & ((0xffff << (16 - keep)) & 0xffff)
  })
  masked[7] = (masked[7] ?? 0) | offset
  return formatIPv6(masked)
}

// ruleTarget is what an access rule reaches, without the ports that can follow it: 10.0.0.5 of 10.0.0.5 tcp/3389
export function ruleTarget(entry: string): string {
  return entry.trim().split(/\s+/)[0] ?? ''
}

// isName tells whether an access rule is a name, files.corp.lan or *.corp.lan, with ports or not: neither an IPv4
// address or network (digits, dots and a slash) nor an IPv6 one
export function isName(entry: string): boolean {
  const text = ruleTarget(entry)
  return text !== '' && !text.includes(':') && !/^[\d./]+$/.test(text)
}

// An access rule as the peer's form shows it, in three columns: the address, network or name, the traffic it allows,
// and the ports of TCP and UDP ('' for all of them)
export type RuleProtocol = 'all' | 'tcp' | 'udp' | 'both' | 'icmp'
export interface AccessRow {
  target: string
  protocol: RuleProtocol
  ports: string
}

export const ruleProtocols: { value: RuleProtocol; label: string }[] = [
  { value: 'all', label: 'All traffic' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP and UDP' },
  { value: 'icmp', label: 'Ping (ICMP)' },
]

// the protocols with ports
export function hasPorts(protocol: RuleProtocol): boolean {
  return protocol === 'tcp' || protocol === 'udp' || protocol === 'both'
}

// the ports as typed, 80, 443 or 80 443 or 8000 - 8090, as the server takes them: 80,443 and 8000-8090
export function portsText(typed: string): string {
  return typed
    .replace(/\s*-\s*/g, '-')
    .split(/[\s,]+/)
    .filter(Boolean)
    .join(',')
}

// the most ports and ranges a rule can have, as the server says
const maxPortItems = 32

// whether the server takes the ports typed: 1 to 65535, a range from low to high. Empty is all of them
export function portsValid(typed: string): boolean {
  const items = portsText(typed).split(',').filter(Boolean)
  return (
    items.length <= maxPortItems &&
    items.every((item) => {
      const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(item)
      if (!match) {
        return false
      }
      const from = Number(match[1])
      const to = match[2] === undefined ? from : Number(match[2])
      return from >= 1 && to <= 65535 && from <= to
    })
  )
}

export function emptyRow(): AccessRow {
  return { target: '', protocol: 'all', ports: '' }
}

// the rows of the rules as the server keeps them (10.0.0.5/32 tcp/3389 icmp): a row for each protocol, one for TCP and
// UDP with the same ports. A rule the form can't show stays as it is in the first column, for the server to judge
export function rowsOf(rules: string[]): AccessRow[] {
  return rules.flatMap((rule) => {
    const [target = '', ...words] = rule.trim().split(/\s+/)
    if (words.length === 0) {
      return [{ target, protocol: 'all' as const, ports: '' }]
    }
    // the ports of each protocol: undefined for none, '' for all of them
    const lists: { tcp?: string; udp?: string } = {}
    let icmp = false
    for (const word of words) {
      const slash = word.indexOf('/')
      const protocol = (slash < 0 ? word : word.slice(0, slash)).toLowerCase()
      const ports = slash < 0 ? '' : word.slice(slash + 1)
      if (protocol === 'icmp' && slash < 0) {
        icmp = true
      } else if ((protocol === 'tcp' || protocol === 'udp') && (slash < 0 || ports !== '')) {
        const known = lists[protocol]
        // all of them stay all
        lists[protocol] = known === '' || ports === '' ? '' : known === undefined ? ports : `${known},${ports}`
      } else {
        return [{ target: rule.trim(), protocol: 'all' as const, ports: '' }]
      }
    }
    const rows: AccessRow[] = []
    if (lists.tcp !== undefined && lists.tcp === lists.udp) {
      rows.push({ target, protocol: 'both', ports: lists.tcp })
    } else {
      if (lists.tcp !== undefined) {
        rows.push({ target, protocol: 'tcp', ports: lists.tcp })
      }
      if (lists.udp !== undefined) {
        rows.push({ target, protocol: 'udp', ports: lists.udp })
      }
    }
    if (icmp) {
      rows.push({ target, protocol: 'icmp', ports: '' })
    }
    return rows
  })
}

// the rules of the rows, as the server takes them: the rows of an address or a name with ports make one rule, as the
// server keeps it (TCP 80,443 and ping: 10.0.0.0/24 tcp/80,443 icmp). Rows without an address are left out
export function rulesOf(rows: AccessRow[]): string[] {
  const rules: string[] = []
  // the rule of each address or name with ports, by its place in the list
  const limited = new Map<string, number>()
  for (const row of rows) {
    const target = row.target.trim()
    if (!target) {
      continue
    }
    const ports = hasPorts(row.protocol) ? portsText(row.ports) : ''
    const word = (protocol: string) => (ports ? `${protocol}/${ports}` : protocol)
    const words =
      row.protocol === 'tcp'
        ? [word('tcp')]
        : row.protocol === 'udp'
          ? [word('udp')]
          : row.protocol === 'both'
            ? [word('tcp'), word('udp')]
            : row.protocol === 'icmp'
              ? ['icmp']
              : []
    if (words.length === 0) {
      rules.push(target)
      continue
    }
    const key = target.toLowerCase()
    const index = limited.get(key)
    if (index === undefined) {
      limited.set(key, rules.length)
      rules.push([target, ...words].join(' '))
    } else {
      rules[index] += ` ${words.join(' ')}`
    }
  }
  return rules
}

// what's wrong with a row: ports the server wouldn't take, or a protocol or ports without the address
export function rowProblem(row: AccessRow): '' | 'ports' | 'target' {
  if (hasPorts(row.protocol) && !portsValid(row.ports)) {
    return 'ports'
  }
  if (!row.target.trim() && (row.protocol !== 'all' || row.ports.trim() !== '')) {
    return 'target'
  }
  return ''
}
