[Authway Server](../README.md) › Routed servers

# Routed servers

By default a server uses NAT: what its peers send to its networks goes out with the address of the container, and
Docker sends it on with the address of the host. Nothing to set up, but the networks can't tell the peers apart, and
can't start a connection to one. A routed server keeps the address of each peer, `10.8.0.5`, towards its networks.

- **Choose it for each server**: **Edit > Networks > What the networks see of the peers > Routed**. Only the networks
  the peers reach are routed, so a routed server needs at least one. What else the peers that send all their traffic
  through the tunnel reach, the internet for one, still goes out with the address of the container: the router of
  the networks doesn't have to translate the tunnels.
- **The networks start connections to the peers**: an option of a routed server. From its networks only, to its peers
  logged in only when it has a login, and only while the option is on: turning it off cuts the connections already
  open. A peer with access rules gets connections only from its own networks. The firewall of each device still
  decides what it accepts. Without it, the networks only answer the peers.
- **Two ways to run it**: through the Docker host, the simpler one, or with an address of its own for the container.
  The **?** next to the setting in the web UI explains NAT and routed with a drawing.

## Through the Docker host

The container stays on the Docker bridge of compose.yaml, and a helper on the network of the host adds there a route
to the tunnel network of each routed server, through the container. Put in the file `.env` next to compose.yaml:

```
COMPOSE_FILE=compose.yaml:compose.host-routes.yaml
```

then `docker compose up -d`, or run the install script again with `--host-routes`, which does both. With a
`compose.override.yaml`, list it too,
`compose.yaml:compose.override.yaml:compose.host-routes.yaml`: Compose reads it by itself only without `COMPOSE_FILE`.
The same goes for compose.macvlan.yaml.

- **The route on the router of the networks**: to the tunnel network, through the address of the Docker host in the
  network: `10.8.0.0/24 via 192.168.1.10`. The panel of the server shows it, with the address the helper found, and
  the IPv6 one when the server has IPv6 networks. That's all: the Docker host sends the tunnels on to the container.
- **When the address of the Docker host changes**, after a new DHCP lease for example, the route on the router is
  wrong, and nothing in the container can change it. Authway Server sees it within seconds, after a restart too: a
  warning at the top of every page of the web UI gives the routes to change, the panel of the server and the System
  page say it, and the Activity page records it. Once the router has the new routes, an Administrator clicks **The
  router has the new routes**. The warning also goes by itself when the address comes back. Better: give the host a
  fixed address.
- **Nothing else moves**: the web UI and the WireGuard ports stay at the address of the host. Works on a virtual
  machine, on Wi-Fi and on a cloud server whose network takes routes to an instance.
- **The helper** (the container `authway-host-routes`) changes only its own routes, `ip route show proto 77`, and,
  for a server whose networks start connections to its peers, its own rules in the chain `DOCKER-USER` of Docker,
  comment `authway-server`: Docker blocks the connections started from outside otherwise. It refuses a tunnel network
  that overlaps a network of the host or that the host already has a route to, and the server shows why. A route goes
  when its server isn't routed any more, and all of them when the helper stops. It needs `NET_ADMIN` on the network
  of the host: that's why it's in a file of its own. It shares with Authway Server only a folder in memory.
- **The answers come back through the router**: the computers send what they have for the peers to their router,
  which sends it back into the same network, to the Docker host. Most routers do; one whose firewall drops what it
  sees in one direction only needs the route on the computers that talk to the peers instead.

## An address of its own

The container gets an address of its own in the local network, on a macvlan network: compose.macvlan.yaml. Put in the
file `.env` next to compose.yaml:

```
COMPOSE_FILE=compose.yaml:compose.macvlan.yaml
AUTHWAY_LAN_PARENT=eth0
AUTHWAY_LAN_SUBNET=192.168.1.0/24
AUTHWAY_LAN_GATEWAY=192.168.1.1
AUTHWAY_LAN_ADDRESS=192.168.1.50
```

`AUTHWAY_LAN_PARENT` is the interface of the host in that network (`ip -br address`), and `AUTHWAY_LAN_ADDRESS` a free
address, outside the range of the DHCP server. Then `docker compose down` and `docker compose up -d`: the data stays.
Docker Compose 2.24 or later.

- **Then everything is at that address**: the web UI at `https://192.168.1.50:8443`, and the WireGuard ports, so the
  router forwards the UDP ports from the internet to `192.168.1.50`, no longer to the host. The servers that keep NAT
  work as before, with that address.
- **The route on the router of the networks**: to the tunnel network of each routed server, through the address of
  the container: `10.8.0.0/24 via 192.168.1.50`. The panel of the server shows it, and the IPv6 one when the server
  has IPv6 networks. Until the route is there, the networks don't answer the peers.
- **The Docker host can't reach the container**: macvlan keeps them apart. Open the web UI from another computer.
- **A virtual machine as the host** needs its virtual switch to let the MAC address of the container through, in
  promiscuous mode. Until then the networks get no answer from the container, though they may find its MAC address:

  | Hypervisor | Setting |
  |---|---|
  | VMware Fusion | Settings > Network: uncheck "Require authentication to enter promiscuous mode" |
  | VMware ESXi | Promiscuous mode and Forged transmits on Accept, for the port group of the VM |
  | Hyper-V | Enable MAC address spoofing, in the advanced features of the network adapter of the VM |
  | VirtualBox | Promiscuous Mode on Allow All, for the bridged adapter |
  | Proxmox | works on its bridge; with the firewall of the VM on, turn its MAC filter off |

  A host on Wi-Fi can't: use a cable. Most cloud servers can't either, their network knows only the MAC address of
  the VM: go through the Docker host there.

## Both ways

- **Not on ipvlan**: its containers share the MAC address of the host, and the kernel gives the packets for the tunnels
  to the host, not to the container.
- **The System page** checks the way to the networks of each routed server: the helper of the Docker host and what it
  did, macvlan, or ipvlan, which can't route, and lists the routes to add on the router.
- **Backups** of version 4 keep which servers are routed; an older Authway Server refuses them.

## Switching between NAT and routed

A server switches in its settings, at any time. Its tunnel stays up and its peers keep their handshakes, the sessions
go on, nobody logs in again, and the configuration files of the peers stay the same: only the firewall rules of the
container change, all at once, and the routes of the helper. The **Activity** page records the change.

### From NAT to routed

- **The route on the router**, before or right after: until it's there, the new connections of the peers to the
  networks get no answer. The server shows the route once saved, and the IPv6 one for a server with IPv6 networks.
  The System page checks the Docker host and the container, not the router: try from a peer, a ping to a computer of
  the network for example.
- **The connections already open go on** with the address of the host until they close: Linux keeps the translation
  of a connection for its whole life.
- **The devices that accept only their own network** now refuse the peers, which no longer come from an address of
  that network: some printers, NAS and cameras, and the rules of the Windows firewall whose remote address is *Local
  subnet*. Let the tunnel network in on them.
- **The logs and the firewall rules** of the networks see each peer from then on: a rule for the peers names the
  tunnel network, or the address of a peer.

### From routed to NAT

- **The connections opened while routed drop once**, through the Docker host: the helper takes its route away at
  once, so their answers no longer reach the container. Their apps connect again, through NAT. On macvlan they go on
  until the route on the router goes.
- **The networks no longer start connections to the peers**, and that option turns off: turn it on again if the
  server goes back to routed.
- **The rules that name the addresses of the peers**, on the devices or on the router, no longer match: everything
  comes from the address of the host again, or of the container on macvlan.
- **The route on the router can stay**: nothing sends to the tunnel network any more. Take it away to keep things
  clean, or keep it for a server that may go back to routed.
