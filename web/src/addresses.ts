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
