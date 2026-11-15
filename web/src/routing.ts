import { networkOf, parseIPv4 } from './addresses'
import type { Route, Server } from './api'

// The routes that the routers of the networks need for a routed server: its tunnel network through the address of
// Authway Server in each IPv4 network the peers reach. That address comes from the routes the routed servers show,
// the same for all of them in that network: the Docker host, as the helper of compose.host-routes.yaml says it, or
// the container itself with compose.macvlan.yaml. It's also the address the computers of the network see with NAT.
export interface RouterRoute {
  tunnel: string
  network: string
  via: string
  // via is the address of the Docker host, not of the container
  dockerHost: boolean
}

// What is known of the routes of a server: the ones whose address is known, and the networks still without one (an
// IPv4 network no enabled routed server reaches yet, or whose route isn't in place)
export interface RouterRoutes {
  known: RouterRoute[]
  unknown: string[]
}

// routerRoutes finds, for each IPv4 network of a server, the address of Authway Server there. tunnel: the IPv4
// tunnel network, from the form while it's edited.
export function routerRoutes(tunnel: string, networks: string[], servers: Server[]): RouterRoutes {
  const ownTunnel = networkOf(tunnel)
  const result: RouterRoutes = { known: [], unknown: [] }
  const seen = new Set<string>()
  for (const network of networks.map(networkOf)) {
    if (network === '' || seen.has(network)) {
      continue
    }
    seen.add(network)
    const hop = ownTunnel ? hopFor(network, servers) : null
    if (hop) {
      result.known.push({ tunnel: ownTunnel, network, ...hop })
    } else {
      result.unknown.push(network)
    }
  }
  return result
}

// routerRoute is the first route known, for the drawing of the help: null while none is
export function routerRoute(tunnel: string, networks: string[], servers: Server[]): RouterRoute | null {
  return routerRoutes(tunnel, networks, servers).known[0] ?? null
}

// hopFor is the address of Authway Server in a network, from the routes of the enabled servers towards it: the same
// network first, then one that holds it or that it holds (192.168.1.0/25 in 192.168.1.0/24, the same router)
function hopFor(network: string, servers: Server[]): { via: string; dockerHost: boolean } | null {
  let near: { via: string; dockerHost: boolean } | null = null
  for (const server of servers) {
    if (!server.enabled) {
      continue
    }
    for (const route of server.routes ?? []) {
      const other = networkOf(route.network)
      const hop = other ? hopOf(route) : null
      if (!hop) {
        continue
      }
      if (other === network) {
        return hop
      }
      if (!near && overlaps(other, network)) {
        near = hop
      }
    }
  }
  return near
}

// the next hop of a route on the router: the Docker host once its helper routes it, or the container on macvlan
function hopOf(route: Route): { via: string; dockerHost: boolean } | null {
  if (route.host) {
    return route.host.state === 'routed' && route.host.address ? { via: route.host.address, dockerHost: true } : null
  }
  return route.driver === 'macvlan' && route.via ? { via: route.via, dockerHost: false } : null
}

// the IPv4 networks the helper of the Docker host routes by itself: the private ones and the shared space of carriers,
// as privateIPv4 in internal/hostroute/helper.go
const privateIPv4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10']

// isPublicTunnel tells whether a tunnel network is one the helper of the Docker host routes only when its
// AUTHWAY_ROUTE_PUBLIC lists it: IPv4 outside the private networks, IPv6 outside the unique local ones (fc00::/7).
// false for a text that isn't a network: the form says what's wrong with it.
export function isPublicTunnel(cidr: string): boolean {
  if (cidr.includes(':')) {
    const first = cidr.split(':')[0]?.toLowerCase() ?? ''
    if (!/^[0-9a-f]{1,4}$/.test(first)) {
      return false
    }
    // fc00::/7: the first 7 bits are 1111110
    return (parseInt(first.padStart(4, '0'), 16) & 0xfe00) !== 0xfc00
  }
  const network = networkOf(cidr)
  if (!network) {
    return false
  }
  return !privateIPv4.some((outer) => {
    const inner = range(network)
    const around = range(outer)
    return inner !== null && around !== null && around[0] <= inner[0] && inner[1] <= around[1]
  })
}

// the first and last addresses of an IPv4 network, as numbers
function range(cidr: string): [number, number] | null {
  const [address, bits] = cidr.split('/')
  const start = parseIPv4(address ?? '')
  if (start === null) {
    return null
  }
  return [start, start + 2 ** (32 - Number(bits)) - 1]
}

// overlaps tells whether two IPv4 networks share addresses: one holds the other
function overlaps(a: string, b: string): boolean {
  const first = range(a)
  const second = range(b)
  return first !== null && second !== null && first[0] <= second[1] && second[0] <= first[1]
}
