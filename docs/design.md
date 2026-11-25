[Authway Server](../README.md) › Design

# How Authway Server works

## The parts

- `internal/store`: the SQLite database (pure Go, no C compiler): administrators, users, servers, peers, their
  devices, sessions, connections, events. The schema changes are numbered migrations, see `PRAGMA user_version`.
  Before it changes the schema of an existing database, `store.Open` copies it with `VACUUM INTO` to
  `before-schema<N>-<UTC date>/authway.db` next to it (`Migrated` says it, and the log); a database of a newer schema
  isn't opened at all. `authway-server schema [-data folder]` prints the schema of the version, or of the database in
  the folder without changing it: `install.sh` uses it to say when an upgrade changes the schema, and for
  `--rollback`.
- `internal/core`: the checks, the changes, the logins and the sessions. Every change is applied at once: there is no
  configuration saved but not applied, so the gate always does what the database says.
- `internal/network`: puts the configuration on the system. `Linux` uses the kernel WireGuard through wgctrl, `ip`
  and `nft`; `Fake` keeps it in memory, for the tests and `-fake-network`.
- `internal/portal`: the login page and its API, on the port 8181 of the address of each server.
- `internal/admin`: the web UI and its API, on the port 8443.
- `internal/backup`: the file of a backup, sealed with a passphrase.
- `internal/directory`: reads Active Directory over LDAP (go-ldap): the members of a group, and one user's password.
  `third_party/asn1-ber` is asn1-ber v1.5.8, which go-ldap needs, with `io.ReadAll` instead of `ioutil.ReadAll`, since
  Go 1.27 has no `io/ioutil`; `go.mod` replaces the module with it until a release builds.
- `internal/system`: the System page: the resources of the host and their history, the checks, the latest lines of
  the log.
- `internal/names`: the names of the access rules, the DNS answers that give their addresses, and the queries that
  Authway Server sends to the DNS servers, for the peers and for the names it looks up itself.
- `internal/peerconf`: the configuration file of a peer, with the comments that Authway reads: `# Name`, `# Login`,
  `# NameRoutes` and `# Fallback`.
- `internal/hostroute`: the route through the Docker host to the tunnels of the routed servers on a Docker bridge.
- `internal/secret`: the password hashes and the random tokens.
- `internal/totp`: the codes of the authenticator apps (RFC 6238).

## The network of the container

The container has a network namespace of its own: the WireGuard interfaces `wg0`, `wg1`... and the nftables table
`inet authway` live there, and nothing of the host changes. Docker keeps its own rules in the same namespace, in its
own tables, which this table never touches.

`Apply` replaces the whole table in one nftables transaction (`table`, `delete table`, `table { ... }` in one
`nft -f`): the old rules stay until the new ones are all in. The open sessions are in the script, so a change keeps
them. When the rules can't be set, every WireGuard interface goes down: no tunnel carries traffic without the gate.
The interfaces change after the rules, and only the peers that differ, like `wg syncconf`: the others keep their
handshakes.

The rules, for each server:

- `input`: from the tunnels, only ping of the server and the login page on its addresses; the ports of the login
  page, of the redirect and of the DNS answers are dropped from every other interface, also when no server redirects.
- `forward`: for a server with login, a packet from or to a peer whose address isn't in the set `<wg>_sessions`
  (IPv4) or `<wg>_sessions6` (IPv6) is dropped. Both sets exist on every server with login, with an IPv6 network or
  not. Then every packet of a peer goes through the chain of its server, the packets of the connections already
  open too: the peers in `<wg>_route_all` reach everything but the other tunnels, the others only the networks of their
  server. All of it comes before the rule of the established connections, which only the answers to the peers reach:
  a logout, fewer networks or a peer that no longer sends all its traffic cut the connections already open. The
  traffic to the other tunnels is dropped, but what the options of [Traffic between peers](#traffic-between-peers)
  open, before that drop. The chain of a server without an IPv6 network starts by dropping IPv6. What comes from
  outside the tunnels in the way a connection started (`ct direction original`) is dropped before a peer of any
  server, but from the networks of a routed server with Inbound: see [Routed servers](#routed-servers).
- `postrouting`: the tunnel networks, IPv4 and IPv6, are masqueraded out of the container, but towards the networks
  of a routed server.
- `prerouting`, for the servers with login and Redirect: before the login, UDP 53 (at most 100 queries a second for
  each server and IP version) goes to the port 8153 of the server and TCP 80 to 8180. The first answers every A query
  with the IPv4 address of the server, every AAAA query with its IPv6 address (no record without an IPv6 network) and
  the other types with no record; the second answers every request with a redirect to the login page, at the IPv4
  address. Nothing is forwarded. At login, `conntrack -D` forgets the redirected flows of both addresses of the peer,
  so its next query reaches the real DNS server at once.

IPv6 has the same rules as IPv4, line for line (`ip6 saddr`, `ip6 daddr`, `icmpv6`), on the servers with an IPv6
network; see [IPv6](#ipv6).

A peer that isn't logged in gets a TCP reset or an ICMP admin-prohibited, rather than a timeout: its apps see at once
that nothing is there.

The source address of a packet from a tunnel is the address of its peer: WireGuard accepts from each peer only its
`/32`, and its `/128` on a server with an IPv6 network (`AllowedIPs` of the server side).

## IPv6

A server has an optional IPv6 network (`servers.network6`, schema 6), from `/64` to `/120`, unicast (global or
unique local), never overlapping the one of another server, with a host part at least as long as the one of its IPv4
network. A peer has no IPv6 address of its own in the database: it's the one in the same place of the IPv6 network as
its IPv4 address in the IPv4 one (`address6`, `address4` in `internal/core/ipv6.go`). `10.8.0.5` in `10.8.0.0/24` is
`fd12:3456:789a:1::5` in `fd12:3456:789a:1::/64`, and the server is `::1` as it is `.1`. So the network can be added to
a server that has peers, changed or taken away: nothing more to choose or keep, the next configuration files have it,
and the files of before still connect over IPv4. The IPv4 network still can't change with peers.

The defaults propose a `/64` of a `/48` of unique local addresses (RFC 4193): the one of a server that has one, else a
random one kept in the meta table (`ipv6_prefix`). The subnet reads like the third number of the IPv4 network:
`10.8.12.0/24` gets `…:12::/64`. `GET /api/servers/defaults?server=<id>` proposes one for an existing server.
`Network.IPv6()` says whether the new interfaces of the container get IPv6 (`/proc/sys/net/ipv6/conf/default/
disable_ipv6`); when they don't, the defaults propose none and say why (`ipv6_off`), and a new or changed IPv6
network is refused (`ipv6_off`). A restore doesn't ask: its configuration applies, and an IPv6 address that the
interface can't take leaves the tunnel up, carrying IPv4, with the error shown.

What has the IPv6 address of a peer:

- the configuration file: `Address = 10.8.0.5/32, …::5/128`, the IPv6 network and the IPv6 networks of the linked
  servers in `AllowedIPs`, `::/0` with `0.0.0.0/0` for a peer that sends all its traffic. A server without an IPv6
  network writes what it wrote before: only `0.0.0.0/0`. The `# Login =` page stays the IPv4 one.
- the interface: the server address with the length of the network (`nodad`: a tunnel has no neighbors), the `/128` of
  each peer in its `AllowedIPs`. The addresses of the interface change one by one, never a flush: the routes of the
  IPv4 address never go.
- the gate: `AddSession` and `RemoveSession` take all the addresses of a peer (`addressesOf`), one nftables
  transaction to open both, one command each to close them, so one already out doesn't keep the other in.
- the login page: the peer can ask from its IPv6 address, with the IPv6 address of the server as host, in brackets
  (`ownHost`: an address of the server, the port of the page or none, never a name). `inTunnel` maps an IPv6 address
  back to the IPv4 one, by which the peers are found; an IPv6 address of the tunnel that no IPv4 address stands for
  finds nobody.

The networks the peers reach can be IPv6 ones, only on a server with an IPv6 network (`needs_ipv6`).

**The public IPs of the devices** can be IPv6 addresses: the endpoints of WireGuard, the lock of the sessions, the
copies, the failed logins and the connections. A device changes its IPv6 address within its network over the day
(privacy addresses), and a network has a `/64` of them: the protections compare them by `/64` (`clientKey`,
`sameClient`), as all the devices behind one IPv4 NAT share one address. The alerts of copies and lockouts list the
`/64`; the sessions and the connections keep the address seen. The failed logins of the web UI count by `/64` too.

**Docker**: compose.yaml turns on IPv6 on the network of the container and `net.ipv6.conf.all.forwarding`. Docker then
gives the network a `/64` of its own, NATs it out of the host, and publishes the UDP ports on IPv6 to the IPv6 address
of the container. Without it, Docker's proxy passes the devices that connect over IPv6 on from one IPv4 address of
its own, and the lock to the public IP can't tell them apart. The traffic of the peers is masqueraded twice, as IPv4
is: by the table of Authway Server, then by Docker. With unique local addresses on the tunnel, the devices prefer
IPv4 for a name that has both (RFC 6724), and use IPv6 for the sites and networks that have only IPv6.

The System page checks IPv6 when an enabled server has an IPv6 network: IPv6 on for the new interfaces, forwarding on,
a default route out of the container (`/proc/net/ipv6_route`, but the one of the loopback that rejects everything).

## Routed servers

A server is translated (NAT) or routed (`servers.routed`, schema 7). Routed, `postrouting` masquerades its tunnel
networks only towards what isn't one of its networks: `ip saddr 10.8.0.0/24 oifname != "wg*" ip daddr != { networks }
masquerade`, the same for IPv6. Its networks see the addresses of the peers; the rest, the internet of the peers that
send all their traffic, still leaves with the address of the container, so the router of the networks needs a route to
the tunnels but no NAT for them. A routed server needs a network (`routed`: `no_networks`).

With `inbound` (only on a routed server: `checkServer` turns it off otherwise) its networks also start connections to
its peers: in `forward`, after the gate and the jumps to the chains of the servers, `iifname != "wg*" oifname "<wg>"
ct direction original ip saddr { networks } accept`, then for every server `oifname "<wg>" ct direction original
drop`, before the rule of the established connections. So:

- the gate comes first: on a server with login only the peers logged in get anything, their answers included;
- the packets of the peers never reach these rules, the chain of each server ends with a verdict;
- what goes to a peer from outside the tunnels is an answer to a connection of the peer, or a connection from the
  networks of a server with `inbound`; turning `inbound` or `routed` off cuts the connections started from the
  networks at their next packet, as fewer networks cut the ones of the peers. The rule changes nothing for a
  translated server: the networks couldn't address its peers.

The container has to receive what the router of the networks sends to the tunnels. On the Docker bridge the host
gets it: it needs a route to the tunnel on to the container, and Docker's own rules drop the connections started from
outside. On ipvlan the containers share the MAC address of the host and the kernel gives each packet to the container
of its destination address: a tunnel address belongs to none, the host gets it. So two ways:

- **Through the Docker host**, `compose.host-routes.yaml`: the container stays on the bridge, and a helper adds the
  routes on the host. The router sends the tunnels to the address of the host.
- **An address of its own**, `compose.macvlan.yaml`: on macvlan the container has a MAC address of its own, and the
  router sends it the tunnels like to any other router, with `ports: !reset []` since nothing is published on the
  host. A virtual switch has to let that MAC address through.

`routesOf` (`internal/core/routed.go`) gives, for each version of the networks of a routed server, the tunnel through
the address of the container towards its first network: the interface of the longest route of `/proc/net/route` or
`/proc/net/ipv6_route` (the loopback and the reject routes left out, then the lowest metric), its driver from the
`ETHTOOL_GDRVINFO` ioctl (no right needed: `veth` for a Docker bridge, `macvlan`, `ipvlan`) and its first address of
that version. The view of the server has them (`routes`, with `no_route` when the container has no route to the
network, which its panel warns about), and the System page checks them (`routing`): an error on ipvlan, a warning on
veth without a helper or with a stopped one, an error when the helper refused a route, a warning when the container
has no route to a network (an internal Docker network has no gateway), else the routes to add on the router: through
the Docker host, or to the container.

The web UI takes that next hop from the routes of any routed server towards the same first IPv4 network
(`routerRoute`, `web/src/routing.ts`): the Docker host once its helper routes it, or the container on macvlan. The
help of NAT and routed then draws the server with its tunnel, its network and that address, with `x` for any peer
and any computer, and the drawer of a server turned routed gives the route before saving. Without one, the help
keeps its example addresses: the address of the Docker host can't be read from the container.

### The helper of the Docker host

`authway-server host-routes` (`internal/hostroute`) runs in a container of its own on the network of the host, with
`NET_ADMIN` only, and shares with Authway Server a folder in memory, a named volume of type tmpfs: `AUTHWAY_HOST_ROUTES`
in both. Authway Server knows the tunnels and its own addresses but can't touch the host; the helper can, and knows
nothing else.

- **`wanted.json`**, written by Authway Server (`syncHostRoutesLocked`, after each change and at each `Tick`, only when
  it differs or is gone): its addresses on the Docker network (the uplinks of its default routes), and for each
  enabled routed server on a `veth` uplink and each version of its networks the tunnel, the address of the container
  towards the first network, that network, and `inbound`.
- **`report.json`**, written by the helper at each pass (at once when `wanted.json` changes, else every 5 seconds):
  for each route the bridge, whether it's routed, whether the connections from the networks pass, an error, and the
  address of the host towards the network, the next hop for the router: the source of the route of the host there;
  for IPv6 a stable address of that interface, in the network if it has one, since the source is often a temporary
  address. A report older than 30 seconds means the helper is stopped.
- **A pass**: the bridge of the container is the interface of `ip route get` to its address, without a gateway, of
  kind `bridge`. A tunnel is refused when it's `/0`, holds the address of the container, overlaps a network of an
  address or a link route of the host, or has an exact route there that isn't of the helper. The routes are
  `ip route replace <tunnel> via <container> dev <bridge> proto 77`: the protocol tells them apart, and only those on
  the bridges of the container are taken away when not wanted, so another project on the same host keeps its own. For
  `inbound`, `insert rule ip filter DOCKER-USER oifname "<bridge>" ip daddr <tunnel> counter accept comment
  "authway-server"` (and `ip6`): first in the chain that Docker keeps for this, written with `nft` in the form
  `iptables-nft` reads back as `-A DOCKER-USER -d <tunnel> -o <bridge> -m comment --comment authway-server -j
  ACCEPT`, so Docker's own `iptables` calls go on working and the image needs no `iptables`. The source stays to the
  gate in the container: `ip saddr { networks }`. Without the chain (Docker with its nftables backend) the route
  stays and the error says the connections from the networks stay blocked.
- **Stopped** (`SIGTERM`), it takes its routes and rules away and removes the report. Started again after a crash, it
  learns the bridges of the routes it left from the report still in the folder.
- **The view** of a route on `veth` has `host`: `off` without `AUTHWAY_HOST_ROUTES`, `stopped`, `pending` until the
  report has it, `routed` with the address of the host, or `failed` with the reason. The System page check follows.
- **The address of the host** that the report gives for each route is kept by tunnel in the meta table
  (`host_addresses`, by `watchHostAddressesLocked` at each `Tick`; not in backups, it belongs to the host). When it
  changes, the address of before stays as `previous`, the first one whatever came between, until an Administrator
  says the router has the new route (`POST /api/host-addresses/confirm`, event `router_routes_updated`) or the
  address comes back. Each change is an event `host_address_changed`. `GET /api/status` lists them in
  `host_changes`, for the warning at the top of the web UI; the view of the route has `host.previous`, and the System
  page check warns.

## The login protocol

The same JSON as the WireGuard login of the NethSecurity fork (ns-wgauth), so Authway works with both. The page is
reachable only through the tunnel; the peer is the source address of the request, and the request must name the
address of the server as host: a page of another site whose name resolves to it (DNS rebinding) gets `403`.

- `GET /api/status[?device=<key ID>]` → `{authenticated, otp_required, server, blocked, no_user, no_otp, user?,
  expires?, device?}`; a paused session isn't `authenticated`; `device` only with
  [device binding](#device-binding)
- `POST /api/login` `{username, password, otp, device?}` → `{result, user, expires}`, or `401 invalid_credentials`,
  `401 password_expired` (a user of [Active Directory](#active-directory)), `503 unavailable`,
  `403 no_user | no_otp | blocked | forbidden`, `429 too_many_attempts` with `retry_after`, and the errors of device
  binding
- `POST /api/logout` → `{result}`
- `POST /api/device-key` `{challenge, wireguard_key, signature}`: see
  [The WireGuard key of the device](#the-wireguard-key-of-the-device)

The POST requests need `Content-Type: application/json`: a form of another site can't send it without a CORS
preflight, which the API never answers. Each address gets 30 requests a minute, 10 at once, on login, logout and
device-key together, and 120 a minute, 20 at once, on status, which reads WireGuard: `429 too_many_requests` with
`retry_after` past them.

The configuration file of a peer of a server with login has `# Login = http://<server>:8181/` in `[Interface]`.

## Sessions

A session belongs to a peer: its tunnel address is in the gate set until the session ends. It ends:

- at logout, from the page or by an administrator;
- at the end of its length; a new login before that starts it again;
- after 5 minutes without a handshake: WireGuard makes one every 2 minutes while packets flow, and the keepalive of
  the peers keeps them flowing. After a restart of the server the time counts from the restart;
- when the user is disabled, deleted, gets a new password or a new authenticator; when the peer is disabled,
  deleted, gets new keys or another user; when the server is disabled, deleted, changes its login or turns device
  binding on;
- when an administrator revokes the device of the peer or allows a new one (`device_changed`);
- when a backup is restored.

The sessions are in the database, so a restart of the container keeps them. Their history, the connections, the
events and the alerts are kept 90 days by default, the setting `history_days` (1 to 3650): every hour, `Tick`
deletes the older rows, and at once when the setting goes down. A backup has the setting, not the history.

## Copied configurations

WireGuard tells peers apart only by their keys: a copy of a configuration file is the peer. Two things tell the
devices apart, both from the endpoint WireGuard reads for the peer, the public IP of its latest packet. They run every
5 seconds, and at each status request of the login page for its peer.

**The lock of a session to the IP of its login** (`lock_endpoint` of the server, a switch in the web UI, on by
default):

- `strict`, on: when the peer sends from another IP, the session pauses (`paused_at`): its address leaves the gate set,
  its connections are cut, the login page says it isn't logged in. A login while WireGuard can't be read has no IP
  yet: the session is locked to the first one WireGuard reports. When the peer sends from the IP of the login
  again, the session resumes for the time it has left: when a copy goes away, the device that logged in gets its
  session back without a new login. After 5 minutes paused, the session ends (`endpoint_changed`). A new login from
  the new IP moves the lock there: a user who changes network logs in again.
- `roaming`, off: the session follows the peer to its new IP. Two devices at once are still caught by the detection,
  but a copy used while the real device is off keeps the session.
- `off`, up to 0.2.0, ignored the IP: it protected no more than `roaming`, which the store reads it as now, and the
  API takes it as (the backups and the clients of before).

**Two devices at once** (`detect_copies`): while both are on, WireGuard answers each in turn, so the endpoint switches
back and forth. Three changes in 5 minutes that come back to an IP already seen mean a copy; a device that moves goes
only to new IPs. The session of the peer ends (`copy_suspected`), an alert is recorded (at most one an hour for a
peer), and with `block_copies` the peer is blocked: the login page says so and refuses the login until an
administrator clears its alerts, or gives it new keys, which also drops its alerts.

Two devices behind the same NAT have the same public IP: neither check can tell them apart.

## Device binding

With the login, whoever has the configuration file and the password (and a code) logs in from any machine. A server
with `device_binding` lets each peer log in only from the device enrolled for it: the Authway app keeps a P-256 key
for each VPN, which never leaves the computer, and signs every login with it. With `machine_id`, Authway also sends
an HMAC of the hardware ID of the computer, recorded at the enrollment and compared at every login. Only an app that
signs can log in: the browser and the WireGuard apps can't. Both options exist only with a login. The protocol is
the one of the NethSecurity fork (`docs/design/wireguard_device_binding.md` there), so Authway works with both.

**Enrollment.** Whoever logs in first is the device. The enrollment of a peer is open for `enroll_hours` of the
settings (72 by default, at most 720) from its creation, its new keys, another user, or the binding of its server
turned on; an administrator opens it again with *Allow a device* (`POST /api/peers/{id}/device` `{hours}`, 0 for the
setting), which forgets the device and ends the session. *Revoke* (`DELETE /api/peers/{id}/device`) forgets it and
leaves the enrollment closed: nobody logs in for the peer until an administrator allows a device. The devices are in
the table `devices`, one row for each peer of a server with binding: the device, or the end of its enrollment window.
Turning the binding off keeps them, turning it on again uses them at once; the sessions of the server end when it's
turned on, so every peer logs in from its device.

**Login.** `GET /api/status` of a peer of a bound server returns `device`: `{required, enrolled, enrollment_open,
machine_id, challenge}`, the challenge 32 random bytes in base64, for that address only, valid 60 seconds and for one
login; the latest 4 of each address are kept. The app signs, with ECDSA P-256 and SHA-256, the lines

```text
ns-wgauth-device-v1
<challenge>
<public key of the server>
<public key of the peer: of its file, or the one its device gave it>
<address of the peer>
<username, as sent>
<machine ID, or empty>
```

and sends `device: {challenge, signature, public_key, kind, name, machine_id}` with the login: the signature in DER,
the public key in DER SubjectPublicKeyInfo, both base64; `kind` is `software`, `tpm` or `secure-enclave`; the machine
ID is `HMAC-SHA256(key: the 32 bytes of the public key of the server, data: the hardware ID in lower case)` in hex.
The device is checked before the password: from another device the password is never checked. Errors:
`403 device_required` (no proof: the browser), `401 challenge_expired` (unknown, used or old: the app asks a new one),
`403 device_not_enrolled` (no device and the enrollment closed), `401 device_mismatch` (another key, another machine,
no machine ID when the server asks for it, a wrong signature). A mismatch counts as a failed login of its public IP,
and is a `device_mismatch` alert of the peer, at most one an hour. The device is enrolled only once the password and
the code are right; when the server asks for the machine ID only after the enrollment, it's recorded at the next
login.

**Another device with the file.** WireGuard knows a peer by its key only, so a copy completes the handshake, and its
keepalives take the endpoint of the peer. The app sends `?device=<key ID>` (the SHA-256 of its DER public key, hex,
empty when it has none) with every status: once a device is enrolled, `device.this_device` says whether it's that one.
With `false`, Authway takes the VPN down at once and says it's enrolled on another device; the answer is a
`device_mismatch` alert too. The strict lock pauses the session of the peer meanwhile, see above.

## The WireGuard key of the device

As long as the peer has the key of its file, every copy completes the handshake. Once logged in, the enrolled device
gives its peer a WireGuard key of its own (`device.wireguard_key` of the status is `configuration`, then `device`):
it makes the key pair, keeps the private key, and sends `POST /api/device-key` `{challenge, wireguard_key,
signature}`, signed with its device key over the lines `ns-wgauth-wireguard-key-v1`, the challenge, the key of the
server, the key of the peer in its file, the address of the peer and the new key. The server takes it only from a peer
of a bound server logged in (not paused), with its device enrolled and its signature, for a key that no peer, device
or server uses (WireGuard tells the peers apart by their key only); the same key again is accepted, for an app that
missed the answer. `200 {result}`, then a second later the interface has the new key instead of the one of the file:
the answer goes back through the tunnel of the old key, and the app switches its key too. Errors: `401
not_authenticated | challenge_expired`, `403 device_binding_not_required | blocked | device_not_enrolled |
device_mismatch`, `400 invalid_key`, `409 key_in_use`.

From then on the configuration file, and every copy of it, gets no handshake at all. The key is kept with the device
(`devices.wireguard_key`), and the configuration applied uses it instead of the key of the file while the server has
the binding. Everything that reads WireGuard (the sessions, the copy detection, the views, the history) looks for the
peer by the key of its device first, then by the key of its file. A new enrollment, a revoke or new keys go back to the
file at once. The file downloaded again doesn't connect either: after a reinstall, allow a new device.

## Traffic between peers

By default the peers of a server reach the networks of the server, not each other and not the peers of the other
servers. Two options of a server open more:

- `client_to_client`: its peers reach each other. A rule `oifname "<wg>" accept` in the chain of the server.
- `reachable_servers` (ids): its peers start connections to the peers of those servers. One way: `oifname "<other>"
  accept` in the chain of the server, and `oifname "<wg>" ct state established,related accept` in the chain of the
  other one, so the answers pass and new connections from there don't. For the other way, the other server lists
  this one. A disabled or deleted server is reached by nobody; deleting a server takes it out of the lists.

With a login, the gate comes first: both peers must be logged in. The configuration file of a peer that doesn't send
all its traffic through the tunnel routes, after the networks of its server, the tunnel networks of the servers
linked to it, the ones it reaches and the ones that reach it: the answers come back through the tunnel too. The
peers need their file again when the lists change.

## Access rules of the peers

A peer reaches all the networks of its server, or only those of its access rules (`peers.access`, schema 8: `''`
for all of them, else a JSON list of networks, an address alone stored as `/32` or `/128`). Each rule is inside a
network of the server (`access`: `outside`), they don't overlap (`overlap`), at most 32, and a list of blank lines is
refused (`required`) rather than taken for all. `PUT /api/peers/{id}` without `access` keeps the rules, so an older
web UI can't take them away; `"access": []` is all the networks. The server refuses networks that leave out part of
a rule of one of its peers (`networks`: `in_peer_access`), and the firewall gets only the rules still inside the
networks of the server: a peer with rules and none left reaches none, never all.

In the chain of the server, after the traffic between peers and before the rules of all its peers, for each version:

```
ip saddr <peer> ip daddr { <its rules> } accept                                   one line per peer with rules
ip saddr { <peers with rules> } ip daddr { <DNS servers> } meta l4proto { tcp, udp } th dport 53 accept
ip saddr { <peers with rules> } ip daddr { <networks of the server> } drop
ip saddr { <peers with rules> } ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
```

(`fc00::/7, fe80::/10` for IPv6). What's left, the internet, follows the rules of every peer: accepted only with
`route_all`. So a peer with rules that sends all its traffic reaches the internet, but not the networks of the
Docker host, the Docker networks or the host behind them. The DNS servers of the server stay reachable on port 53,
wherever they are, since the configuration file names them. On a routed server with `inbound`, before the rule of
its networks: `iifname != "wg*" oifname "<wg>" ct direction original ip daddr <peer> ip saddr { <its rules> }
accept` for each peer with rules, then `ip daddr { <peers with rules> }` dropped. The translation doesn't change:
NAT and routed work the same. Every packet goes through these rules, so a change cuts the connections already open.

The configuration file of a peer with rules that doesn't send all its traffic routes its rules, and the DNS servers
of the server that are inside the networks of the server but not inside its rules, instead of the networks of the
server.

### Names in the access rules

A rule can also be a name, `files.corp.lan`, or `*.corp.lan` for every name under `corp.lan` at any depth (not
`corp.lan` itself): `internal/names`, letters, digits, hyphens and underscores, two labels at least for a name alone,
kept in lowercase in `peers.access` with the other rules (no schema change; an older version skips them, so the peer
reaches less, never more). A server without networks takes names alone, for their internet addresses, and refuses
addresses and networks (`names_only`). The addresses of a name aren't known in advance, so they're learned from the
DNS answers of the peer:

- **Its DNS goes to Authway Server.** Its configuration file has `DNS = <the server's address>` (and the IPv6 one),
  and routes all the networks of the server, as without rules: the firewall does the narrowing. Once it's logged in
  (always, on a server without a login), `prerouting` redirects its UDP and TCP port 53, to any address, to
  `-resolver-port` (8154, `AUTHWAY_RESOLVER_PORT`), so an older file or an app with its own DNS server works too, as
  long as the query goes through the tunnel; `input` accepts that port from those peers only, and drops it from
  outside the tunnels.
- **The resolver** (`internal/portal/resolver.go`) sends each query on to the DNS servers of the server (the server's
  own addresses left out), or the ones of `/etc/resolv.conf` when it has none, over the protocol it came with, 3
  seconds each, and answers `SERVFAIL` when none answers. 100 queries a second for each peer, 300 at once, 256 under
  way in all. It answers only an enabled, unblocked peer with names, logged in on a server with a login.
- **Learning** (`core.Learn`, before the answer goes back, so the device connects at once): for a question that
  matches a rule of the peer, the A and AAAA records of the name, through the CNAME chain of the answer, inside the
  networks of the server and of a version its tunnel carries. Each one stays for the shortest time to live on its way,
  plus `LearnedMargin` (10 minutes), a day at most; a new answer extends it. 1024 addresses per peer at most. They're
  kept in memory, written in each ruleset, and added (`add element`) or removed at the `Tick` after they expire
  (`delete element`) between two.
- **Exact names looked up by Authway Server** (`core/lookups.go`): `files.corp.lan`, not `*.corp.lan`, whose names it
  can't list. For the peers the resolver answers, every 30 seconds (`LookupInterval`) and at once after a login, a
  resumed session or an apply, it asks the DNS servers of their server for each exact name due, A and, for a server
  with IPv6 networks, AAAA, over UDP (TCP when the reply is cut), 8 at once, and learns the answer for each of those
  peers like one of their own, but only the addresses inside the networks: the internet ones work only through the
  answer the device gets. A name is due again when its shortest time to live runs out, 30 seconds to an hour
  (`LookupMin`, `LookupMax`), or a minute after a failure or an answer without an address (`LookupRetry`); until
  then, each round learns the answer it has, for the time it has left, so a peer that logs in gets it at once.
  After a failure the answer before stays until its time to live runs out; three in a row log a warning. Only the
  A query counts: a DNS server that never answers AAAA still gives the IPv4 addresses (`lookUpName`). A change
  of the DNS servers or the networks of a server forgets its names, a restore all of them, and the lookups under
  way then keep nothing (`lookupsReset`). A device that kept an answer, an app that keeps an address for hours, or a
  browser asking DNS over HTTPS reaches the exact names this way.
- **Across restarts** (`core/namessaved.go`): the learned and stand-in addresses are kept in the meta key `names`
  too (JSON, no schema change, not in the backups), written at the first `Tick` a minute or more after a change
  (`NamesSaveInterval`), at once after a restore, and when Authway Server stops (`Service.Close`). At the start,
  `New` reads what still holds, before the first apply: the addresses whose time isn't up, of a peer and a server
  whose id, creation and version are the same (a version that doesn't know the key, after a downgrade, changes them
  without forgetting; a new peer can get the id of a deleted one), inside the networks of now, the stand-in
  addresses of the same stand-in network, and the internet addresses routed by the app. An apply marks them
  changed, so the versions written follow the changes that keep them.
- **Internet names** (`-stand-in-network`, `AUTHWAY_STAND_IN_NETWORK`: 198.18.0.0/16 by default, an IPv4 network from
  /8 to /24, or `off`): a configuration file routes only networks known in advance, so for a peer that doesn't send
  all its traffic through the tunnel, each IPv4 internet address of its names gets a stand-in address from that
  network, which its file routes through the tunnel too. The answer to the device has the stand-in address instead,
  with the same time to live, learned like an address inside the networks; the IPv6 internet addresses go from the
  answer, so the device takes the IPv4 ones. The HTTPS and SVCB records of its names go too, whatever their addresses:
  their hints would skip the stand-in addresses. "Internet" is global unicast, not private, and none of 0.0.0.0/8,
  100.64.0.0/10, 192.0.0.0/24, 198.18.0.0/15 or 240.0.0.0/4; a private address outside the networks is left in the
  answer and not learned. A stand-in address stands for one internet address, for every peer of every server: an
  FNV-1a hash of the address picks it, or the next free one after it (never .0 or .255), so a restart gives the same
  ones unless another address took one first. It keeps its internet address `StandInGrace` (a day) after the last
  peer that could use it, so a device that keeps an answer too long still reaches the same site. When they're all
  taken, the new internet addresses go to the device as they are, with a warning. The VPN network and the networks of
  a server can't overlap them (`overlaps_stand_ins`); a server whose networks already do (the setting changed) gets
  none, with a warning at start.
- **The Authway app** routes the internet addresses of the names itself, with their real addresses. The file of a
  peer with names, unless it sends all its traffic, has `# NameRoutes = 1` (`peerconf`); the app then answers the
  DNS of the computer itself and asks Authway Server with the EDNS option `names.RoutesOption` (65430, a code for
  local use) in its queries. The resolver takes the option out before the query goes to the DNS servers, and out of
  their answers too: only Authway Server gives routes. For such a query, an internet address of a name stays as it is,
  learned for the peer like an address inside the networks (an IPv6 one only when the tunnel carries IPv6, otherwise
  it goes from the answer), no stand-in address, and the answer lists the addresses to route in the same option: for
  each one, 4 or 6, the address, then the seconds it stays open on 4 bytes. Before the computer gets the answer, the
  app adds each one to the allowed IPs of the server in its WireGuard and a route of it through the tunnel. The file
  keeps the stand-in network for the other apps, and for the Authway app when its DNS server can't start.
- **The firewall**, for a server with such peers: the sets `<wg>_learned` (`ipv4_addr . ipv4_addr`) and
  `<wg>_learned6`, of `peer . address`; in the chain of the server, before the drops of the peers with rules:

  ```
  ip saddr . ip daddr @<wg>_learned ct mark set 0x00415701 accept
  ip saddr { <peers with names> } ct mark 0x00415701 accept
  ```

  so a connection opened while the address was learned stays open after it expires, as long as the session does.
  With `inbound`, `ip daddr . ip saddr @<wg>_learned` also lets those addresses start connections to the peer. With
  stand-in addresses, the map `stand_ins` (`ipv4_addr : ipv4_addr`, stand-in to internet address, for all the
  servers), and in `prerouting`, after the redirects:

  ```
  iifname "<wg>" ip saddr @<wg>_sessions ip daddr <stand-ins> ip saddr . ip daddr @<wg>_learned ct mark set 0x00415701 dnat ip to ip daddr map @stand_ins
  ```

  (without `ip saddr @<wg>_sessions` on a server without a login). The chain of the server drops `ip daddr
  <stand-ins>` before the rules of its peers, so a stand-in address that wasn't translated goes nowhere, and accepts
  the translated connections by their mark; `postrouting` sends them out with the address of the container, like the
  rest of the tunnel, routed server or not.
- **Changes**: when the rules of a peer with names change, it's disabled or gets another user, or the networks of its
  server change, what it learned is forgotten and its marked connections are deleted from conntrack
  (`conntrack -D -s <peer> -m 0x00415701`), so the next packet goes through the rules of now; a restore deletes
  them all. A new or deleted peer, and new keys, forget too.

What this can't do: queries the device sends another way (DNS over HTTPS or TLS) teach nothing, so the names of a
wildcard inside the networks stay blocked (the exact names are looked up by the server) and their internet names go
out directly, not through the server. Without the Authway app, an internet name goes through the server over IPv4
only, and the device sees its stand-in address (in `ping`, say). Sites that share an address, behind a CDN, share its
stand-in address too: a peer allowed one of them reaches the others behind it through the server. A wildcard covers
every name that can be created under it: in Active Directory, any user can register one by default. Backups of
version 7 have them.

## Connection history

WireGuard has no connections and no hooks when a peer comes or goes. Every minute (`RecordInterval`) the server reads
WireGuard and records, for each peer of the enabled servers, with a login or not, the runs of handshakes in the table
`connections`: a peer with a handshake in the last 3 minutes and no open row starts a connection from the time of that
handshake; an open row follows the byte counters of the peer (`last_seen` is their latest change), and ends at
`last_seen` when the latest handshake is older than 3 minutes, when the peer sends from another public IP (a new row
starts), when its counters are lower than a minute before (the interface started again: a new row), or when the peer,
its server or its interface is gone or disabled. The bytes are the ones counted since the row started (`rx_start`,
`tx_start`). When the device gives the peer its own key, WireGuard counts from zero for that key: the row goes on,
its bytes added to the ones before. At start the interfaces are new: the open rows end at their `last_seen`.

`GET /api/connections?limit=` returns the latest, the open ones first; the web UI shows them in Activity, and
downloads them as CSV. A connection shorter than a minute is recorded once seen; a peer without keepalive that stays
idle for 3 minutes is out, and back as a new connection when it sends again. The rows are kept as long as the rest
of the history.

## Failed logins

They count for each peer and public IP: 5 in 15 minutes lock that IP out for 15 minutes, so a copy of the
configuration used from another network can't lock out the real user. 20 failures of a peer from any IPs lock it out
from all of them, but the IP of its latest login: many IPs don't multiply the attempts. Each lockout is an alert. The
password is checked with argon2id (64 MiB, 3 passes), at most two at once; an unknown username takes as long. Each
authenticator code works once: its period is remembered for 3 minutes. The event of a failed login has the user of the
peer, never the username typed: it can be a password typed in the wrong field, and every role reads the events. A
change of the login of the server during the check of the password (a code asked now) refuses the login.

## Active Directory

The members of one Active Directory group can be VPN users (`internal/core/directory.go`); the guide is
[Active Directory](active-directory.md). The settings are JSON in the meta table (`directory`), with the password of
the service account, which the API never answers: `GET /api/directory` has `bind_password_set` instead, and a `PUT`
with an empty password keeps the one saved. Only an Administrator reads or changes them, tests them
(`POST /api/directory/test`, the values of the form, nothing changes) or syncs at once (`POST /api/directory/sync`,
with `{"disable": n}` to confirm a sync that held users).

A user of the directory has its `objectGUID` in hex in `users.directory_id` (schema 12) and no password hash. Its
username, full name and state follow the account: `PUT /api/users/{id}` refuses a change of them, or a password
(`directory`). Its authenticator, its peers and the rest are the same as for a local user.

**The sync** runs every `sync_minutes` (15 by default, 5 to 1440), its first one 10 seconds after the start and at
once when the settings turn it on, one at a time, the LDAP calls out of the lock. It reads the group with
`(memberOf:1.2.840.113556.1.4.1941:=<group>)`, the members of nested groups too, in pages of 500, at most 10,000. By
`objectGUID`: a new member is added (`user_added`, by `directory sync`); a renamed account, a new display name, an
account disabled (`userAccountControl` bit 2) or expired (`accountExpires`) or enabled again changes its user
(`user_changed`); a user whose account is no longer in the group is disabled. A user disabled ends its sessions. An
empty group disables nobody: the status has an error instead. Nor does a sync that would disable more than
`DirectoryHoldMin` (5) users, and more than a quarter of the enabled users of the directory, at once: their usernames
are in the status (`held`, event `directory_held`), the other changes go on, and `{"disable": n}` from an Administrator
disables them when they're at most n (event `directory_confirmed`). A failed sync is tried again within
`MinSyncMinutes` (5); `directory_failed` and `directory_restored` mark the start and the end of the failures, and two in
a row show in the warning at the top of the web UI (`directory` in `GET /api/status`), as does a held sync and a
password of the service account that expires within 14 days (`msDS-UserPasswordExpiryTimeComputed` of the account,
read at each sync). Left out, with a reason in the status: a username that
`usernamePattern` refuses, the username of a local user (or, with `link_local_users`, that user becomes the account's:
its password hash goes, its sessions end), of another account of the directory, or a rename to a username taken.

**The login** of a user of the directory binds as the service account, looks the account up by `objectGUID` in the
group, refuses a disabled one, then binds as the account with the password: never with an empty password, which LDAP
takes as an anonymous bind. `data 775`, `532`/`773` and `533`/`701` in the error of Active Directory are a locked
account, an expired password and a disabled account: `invalid_credentials` all the same, the reason in the event of the
failed login; except an expired password (or one to change) with the right code, if the server asks for one:
`password_expired`, which tells nothing to someone who doesn't have both. A user principal name logs in with the part
before the `@` too. A directory that doesn't answer, or turned off, answers `503 unavailable` and counts no failure. The
failures of such a peer from any IPs but the one of its latest login lock it out after `DirectoryPeerFailures` (5)
instead of 20: Active Directory sees at most 10 wrong passwords of a user in 15 minutes.

The connection is LDAPS or StartTLS, the certificate checked against the system's certificate authorities and the
ones of `ca_certificates`. The domain controllers are tried in order, 5 seconds each to connect and encrypt, then 10
seconds for each request. One that doesn't connect, or stops answering a request, is remembered in memory: logins try
the others first, a sync tries them in order and forgets it once it answers. A sync whose domain controller stops
answering a request goes on with the next one; the ones that didn't answer are in the status (`unanswered`) and a
`directory_servers` check. The whole call ends by its deadline, 12 seconds for a login (the login page has 15 to
answer) and 50 for a sync or a test (the web UI has 60): the deadlines are set on the TCP connection itself, since
go-ldap has none for the TLS handshake of StartTLS. No call holds the lock of the service, so a directory that doesn't
answer slows down only the logins of its users and the sync; a Sync now during a sync waits for it and answers its
result. The System page has a
`directory` check while the sync is on. A backup (version 6) has the settings, with the password, and the users'
`directory_id`.

## Fallback addresses

A server can have up to 4 other `host:port`, written after `Endpoint` in the configuration files as
`# Fallback = a:51820, b:51821`. Authway tries them when the endpoint doesn't answer; the other apps ignore the
comment.

## Passwords

The policy (`password_policy` in the meta table, `internal/core/policy.go`) applies to every password that a person
chooses: the users', the administrators', the first password of a new administrator. Minimum length from 8 to 64
(10 by default), optionally a lowercase letter, an uppercase letter, a digit, a symbol (anything but a letter or a
digit, a space too); never the username (3 characters or more, in any case). The administrators have at least 12
characters whatever the policy. A change of the policy doesn't touch the current passwords: they're hashed, nobody
can check them. There is no expiry, on purpose: forced changes make weaker passwords (NIST SP 800-63B).

The passwords the server makes itself (16 random letters and digits: the first administrator, `reset-admin-password`)
skip the policy and must be changed at the next login.

## The web UI

The administrators log in with a password (10 failures in 15 minutes from one address wait), then the code of their
authenticator app when they have one. The login answers `otp_required` when the password is right and a code is
missing: the page asks for it, and sends both again. With "Remember this device" ticked, a login with a code also
gets a second cookie, `authway_device` (HttpOnly, sent to `/api/login` only), for the days of the setting
(`admin_remember_days`, 30 by default, 0 off). The database keeps only its SHA-256 in `admin_devices`, with a
fingerprint of the password hash and the authenticator secret of that moment: from that browser, the right password
is then enough until the days run out, the setting gets shorter or off, or the password or the authenticator
changes. An administrator keeps the latest 10; deleting the administrator or a restore deletes them. Each code works once; 5 wrong codes for an administrator, from
any address, stop its codes for 15 minutes, so the password alone can't be used to try them all. A login counts
before its password is checked, so logins sent at once can't pass these limits, and a login that works clears only
the failures of its own username: an account of its own doesn't reset the guesses at another one. The logins of the
web UI check one password at a time, taking turns with the imports at one slot of the hashing: a flood of them, even
during an import, leaves the other slot to the logins of the VPN.

The session is a random cookie, `HttpOnly`, `SameSite=Strict`, `Secure` with HTTPS, kept by its SHA-256 in memory: a
restart logs everybody out. It ends after 4 hours without anyone at the page, or 12 hours:
the refreshes the page makes by itself, more than a minute after the latest input, don't count. Every request reads the
administrator from the database again: a role taken away, a disabled or deleted administrator apply at the next
request. Every API request needs the header `X-Requested-With: authway`, which a page of another site can't send
without a preflight. The pages have a strict Content Security Policy. The API never sends a private key, except in
the configuration file of a peer.

### Peers

On a server with login, a peer belongs to a user, one peer per user and server. On a server without login the form
doesn't ask for one: a new peer has none, and an edited peer keeps the user it had, for when the login comes back.
The view of a server counts its peers without a user (`peers_without_user`): with a login they reach only the login
page and can't log in, so the form of the server warns before the login is turned on, and the server with login lists
them.

The address of a new peer is the next free one of the tunnel network, after the address of the server. The form fills
it in, and checks what is typed with the rules of the API (`web/src/addresses.ts`, like `peerAddress` and
`freeAddress`): in the network, not its first or last address, not the address of the server, not the address of
another peer. The API checks again, and answers `invalid` or `taken`.

A peer is `connected` (`connectedLocked`) while its latest handshake is younger than `ConnectedWindow`, 3 minutes,
and, when its server has a keepalive, while it sent something within two keepalives and a tick (`activeWindow`, 55
seconds with 25): each `Tick` notes when its received counter grew (`followActivityLocked`), a handshake counting
too. WireGuard makes a handshake only every 2 minutes, so the handshake alone shows a device gone after up to 3
minutes; the keepalive shows it within a minute. A peer seen for the first time, or whose counters start again with
its interface, last sent at its handshake. The connection history and the sessions keep their own rules.

WireGuard keeps the handshakes in the interfaces, and the container starting again makes them new. A peer without a
handshake since gets `last_seen` and `last_endpoint` in its view, from its latest row in `connections`
(`LatestConnections`): only a row of its server that started after the peer was made, since a new peer can take the
id of a deleted one.

### Two administrators at once

The users, the peers, the servers and the administrators count the changes made to them (`version`, from 1, and
`updated_by`, the administrator who made the latest; schema 9). Their views have both. Every update that an
administrator makes adds one (`UPDATE ... version = version + 1 RETURNING version`): the forms, an authenticator set
up or removed, new keys for a peer, a server taken out of the lists of the others when it's deleted. What the system
changes by itself, a peer blocked after a copy say, doesn't count.

A form sends the version it opened with (`version` in `UserInput`, `PeerInput`, `ServerInput`, `AdminInput`). When it
isn't the one of now, nothing is saved: `409 {"error": "changed", "current": <the view of now>, "by", "at"}`
(`ChangedError`). The form then compares, field by field (`web/src/conflict.ts`), what it opened with, what is typed
and what was saved meanwhile: the fields that only the other administrator changed take their values, the ones that
only this one changed keep theirs, and the ones both changed keep what is typed and are named, with *Use theirs
instead*. A notice says who saved, when, and what; the next save sends the new version. When only what the form
doesn't show changed (an authenticator, new keys), it saves again at once. Without a version (`0`), nothing is
checked, as before: a client of the API that doesn't know it.

A user's password is hashed out of the lock; the update then reads the user again, so an authenticator set up during
the hash stays. A deletion has no version: the next save of a form opened before answers `404`.

### Import

`POST /api/import` `{csv, check, skip_existing}` adds users from a CSV file (`internal/core/import.go`), an Operator or an
Administrator: each row a user, as `POST /api/users` makes it, enabled. The peers are given to them afterwards, on
their servers. The header names the columns, in any case, with spaces or dashes: `username` (or `user`), `full_name`
(or `fullname`, `display_name`, `name`) and `password`; any other name is refused, so a mistyped password column can't
make the server choose the passwords without a word. The separator is the one the header has most of: a comma, a
semicolon or a tab. A UTF-8 byte order mark is skipped, the empty rows too; at most 500 rows and 512 KB.

Each row is checked as the form is (`planImportLocked`), and against the users there and the rows before it: a
username already there is `taken` (without regard to case, as in the database: an import adds users, it never changes
one), twice in the file `twice`. A password follows the policy; without one, the server makes one (`newPassword`: 16
characters at least, the policy followed, never a symbol first, since a spreadsheet reads `=`, `+` or `-` first as a
formula). The answer has each row, `ImportRow`, with its errors by column.

With `skip_existing`, a row whose user is already there is `skipped` instead of `taken`, whatever its other cells
say: that user doesn't change, its password neither, and it gets no event. The rows that add a user are checked as
always: an error among them still stops the import. `users` counts the users added, `skipped` the rows skipped; a file
of users that are all there adds nothing.

With `check`, or a row in error, nothing is added: `{rows, users, skipped, invalid, imported: false}`. Else the
passwords are hashed out of the lock, one at a time and in turn with the logins of the web UI, so the logins of the VPN keep the other slot of the hashing, then the file is checked again under it (another administrator may have added
or deleted a user meanwhile: errors again and nothing added, or a row skipped no more), and the users are added in
one transaction, each a `user_added` event with the detail `imported`. The answer adds `passwords`, the ones the server
made: the only time they're seen. The hashes of hundreds of passwords may take longer than the 60 seconds an answer
of the web UI may take: that route waits up to 10 minutes (200 took 6 seconds on a small ARM host two at a time).

### Roles

| | Administrator | Operator | Read-only |
|---|---|---|---|
| See the servers, the peers, the users, the activity | yes | yes | yes |
| Users, their authenticators; peers, their keys, configuration files and devices; end sessions; clear alerts | yes | yes | no |
| Servers, settings, administrators | yes | no | no |

The server checks the role on every route (`internal/admin`, `need*`): the web UI only hides what the role can't do.
Nobody changes their own role, disables or deletes themselves; the last active Administrator stays.

### What comes before the rest

An administrator with `must_change_password` (a password given by another administrator or by the command line, or
the random first one) or without an authenticator while the settings require one (`require_admin_mfa`) gets
`403 setup_required` with `setup: password | mfa` on every route but its own account (`/api/me`, its password, its
authenticator, logout), and the web UI shows the setup page until it's done.

An authenticator is set up in two steps: `POST /api/me/totp` with the password of the administrator makes a secret,
kept in memory for 10 minutes; `PUT /api/me/totp` saves it when the code of the app is right, and logs out the other
sessions of that administrator. The password is asked so that a session left open, or kept after
`reset-admin-password`, can't put another authenticator on the account and lock its owner out. The changes of the own
account that ask for the password (the authenticator, its removal, a new password) stop for 15 minutes after 10 wrong
passwords: a session alone can't be used to find the password. Requiring an authenticator of everybody needs one of
the administrator who asks.

A failed login of the web UI keeps the username only when it's the one of an administrator, in the events and in the
log: an unknown one is recorded as `unknown username`, since it can be a password typed in the wrong field.

### The events

The events of the peers are `login_failed`, `locked_out`, `session_paused`, `session_resumed`, `copy_suspected`,
`device_enrolled`, `device_mismatch` and `device_key`, with the user of the peer and its public IP.

The events of the web UI (`webKinds` in `internal/core/audit.go`) are the logins of the administrators
(`admin_login`, `admin_login_failed`, with the administrator as user and the address of the login) and every change,
made through the API:

- the administrators and the settings: `admin_added`, `admin_changed`, `admin_deleted`, `admin_password_reset`,
  `admin_password_changed`, `admin_mfa_on`, `admin_mfa_removed`, `settings_changed`, `backup_made`, `backup_restored`;
- the servers: `server_added`, `server_changed`, `server_deleted`;
- the peers: `peer_added`, `peer_changed`, `peer_deleted`, `peer_keys` (new keys), `peer_config` (its configuration
  file, with its private key, sent to the web UI: each time it's opened), `session_ended` (ended by an administrator),
  `alerts_cleared`, `device_allowed`, `device_revoked`;
- the users: `user_added`, `user_changed`, `user_deleted` (with the peers it took away), `user_mfa_on`,
  `user_mfa_removed`.

Each change names the administrator who made it (column `actor` of the events, `by` in the API) and the address of
the request (`source`); the user is the one changed, or the user of the peer. The detail says what changed, in words:
`networks: 192.168.1.0/24 → 192.168.1.0/24, 10.1.0.0/16, login: password → password and code`. A save that changes
nothing records nothing. The events before this version kept the administrator in the detail (`by olga`).

### The history lists

`GET /api/history` (the ended sessions), `/api/connections` and `/api/events` answer a page, `{items, total}`, of the
rows that match their filter: `q`, words that each must be in one of the names, addresses, administrator or detail
(`LIKE`, so the case of the ASCII letters doesn't count; `%` and `_` are letters); `server`, an id (the events keep
the name of their server, so a renamed server loses its older events, which the words still find); `since` and
`until`, Unix times, for the sessions and the connections that overlap them and the events in them; `type`, for the
events, `web` or `vpn`; `limit` (up to 1000) and `offset`. `GET /api/<list>/csv` takes the same filter and answers
every row that matches, up to 100,000, as CSV: times in UTC, bytes as numbers, reasons and kinds as codes, and a `'`
before a cell that a spreadsheet would read as a formula. `X-Row-Count` and `X-Total-Count` say how many rows the file
has and how many match, so the web UI says when the file stops at 100,000. The open sessions and the alerts are few: the web UI filters
them itself.

Every list has the newest on top and the oldest at the bottom: the sessions, open or ended, and the connections, open
or ended, by the time they started; the alerts and the events by their time.

## Backup and restore

A backup (`internal/core/backup.go`) has the whole configuration: the settings, the administrators, the users, the
servers and the peers, with their keys, password hashes and authenticator secrets, the devices and the keys they gave
their peers, and their ids. Not the history of the sessions and of the connections, the events, the alerts, the
certificate of the web UI, or the count of the changes (`version`, `updated_by`): it starts again at 1, and the
restore logs every administrator out, their forms with them. The content is JSON with its own version (`BackupVersion`, 2 since the devices, 3 since the
IPv6 networks, 4 since the routed servers, 5 since the access rules of the peers, 6 since Active Directory and its
users, 7 since the names in the access rules); a restore takes that version and
the older ones, and refuses a newer one: an older Authway Server refuses a backup with IPv6 networks rather than lose
them, with routed servers rather than translate them, or with access rules rather than open all the networks to the
peers. A backup of version 1 has no device: the peers of the servers with binding enroll one at their next login. One
of version 1 or 2 has no IPv6 network, one of version 1 to 3 no routed server, one of version 1 to 4 no access rule.

The file (`internal/backup`) is JSON too: a header in clear (`format`, `version`, `created_at`, the parameters of the
key, `cipher`, `nonce`) and `data`, the content encrypted with AES-256-GCM. The key comes from the passphrase through
argon2id (64 MiB, 3 passes, a random salt of 16 bytes), in the same two slots as the password checks. The header is
the additional data of GCM: a changed date or parameter fails like a wrong passphrase. The parameters of a file must
stay in a range (at most 256 MiB, 10 passes), so a file can't make the server take all its memory; a file is at most
8 MiB. The passphrase has at least 12 characters.

Only an Administrator makes or restores a backup, with its password: a session left open can't take the keys of
every tunnel, or replace them. The wrong passwords count with the other changes of the own account (10 in 15
minutes stop them).

- `POST /api/backup` `{password, passphrase}` → the file, `authway-backup-<UTC date>.json`
- `POST /api/restore/check` `{passphrase, backup}` → what the backup has (`servers`, `peers`, `users`,
  `administrators`, `admin_usernames`, `includes_you`, `created_at`, `made_by`): nothing changes
- `POST /api/restore` `{password, passphrase, backup}` → the same, once restored

A restore checks the content as the API checks what it gets: the names, the networks, the ports, the addresses of
the peers in their network, the keys (the public key of a peer must be the one of its private key), the hashes, the
authenticator secrets, the interface names (`wg0`...), the servers that each one reaches, the devices (one for each
peer at most, their keys, names and machine IDs, a WireGuard key that no peer, server or other device has), and one
enabled Administrator at least. A file edited by
someone who has the passphrase can't put on the system what the web UI refuses. Then, in one transaction, the open
sessions end (`restored`), the configuration and the alerts are deleted and the backup is inserted with its ids. The
state in memory (failed logins, trusted IPs, copy tracking, used codes, authenticators being set up, challenges, the
counters of the history) is forgotten: an
id of the backup can be another peer or user. A login whose password was checked before the restore is refused. The
configuration is applied, and every session of the web UI ends: the administrators are the ones of the backup, maybe
with other ids. Each session keeps the generation of the configuration at its login (the count of the restores), and
the check of every request compares it in the same lock as the read of the administrator: a request of a session
opened before the restore never runs as the administrator that has its id now.

## The System page

`internal/system` reads the host through a probe: `/proc` and `/sys` on Linux, made-up values elsewhere (the page
says so), to try the web UI on a computer without Linux.

The page has five tabs (`web/src/views/SystemView.vue`), the one open in the address (`?tab=history`): Overview (the
checks and a summary), History, Network (the interfaces), Host (the disks, the host, Authway Server) and Log. The
snapshot is read every 5 seconds whatever the tab; the history and the log only while their tab is open, and a tab
opened again asks the points it missed. A dot on Overview, and on Log for the errors of the log, says a check isn't
right. Like every page that refreshes itself (`web/src/polling.ts`), it asks nothing while the browser tab is in the
background, and refreshes at once when it's shown again.

- **Every 5 seconds** the monitor reads the counters: the ticks of the processors (`/proc/stat`), the memory
  (`MemTotal`, `MemAvailable`), the bytes of each interface (`/proc/net/dev`, the network of the container), and what
  Authway Server uses: its cgroup (`cpu.stat` `usage_usec`; `memory.current` less `inactive_file`, as `docker stats`),
  else its process. The rates of two readings are a point. An hour of points is kept, and a day of points of one
  minute, made from the readings a minute apart: the averages are exact, the peaks of a few seconds are lost. All in
  memory: the history starts again with Authway Server. An interface made again starts its counters from 0: its rate
  counts from there, never negative. `lo` isn't in the history, and 16 interfaces at most are.
- **When the page asks** (`GET /api/system`), the probe reads the rest: the load, the uptime, the swap, the kernel
  status of the clock (`adjtimex`, which reads without any right: `STA_UNSYNC` means no time service keeps it right),
  `ip_forward`, the connection tracking table of the container, the limit of memory of the cgroup, the open files,
  the interfaces (`net.Interfaces`, the kind from `/sys/class/net/*/uevent` and `type`), `statfs` of the data folder
  and of `/` when it's another file system, and the size of the database and of its WAL.
- **The checks** add what the core knows: the configuration applied, its error, or a warning when a tunnel works but
  its MTU or its IPv6 address can't be set (not a failure: not retried, not in the health), the latest reading of the tunnels
  (an error, or older than 30 seconds), and the interfaces of the enabled servers. Then IP forwarding, IPv6 (only
  when a server has an IPv6 network: see [IPv6](#ipv6)), the way to the networks of the routed servers (only with
  one: see [Routed servers](#routed-servers)), the clock, the
  disks (a warning under 10% free, an error under 5%, or under 5% of the inodes), the memory (the same, and 90% of
  the limit of the container), the load over 5 minutes above twice the processors, connection tracking (a warning
  above 75%, an error above 90%) and the errors of the log in the last hour. The web UI compares the clock of the
  server with its own, from the time of the answer: past 30 seconds, the clock check is a warning.
- **The log**: the logger writes to the standard output, the log of the container, and keeps the latest 500 lines
  and the latest 200 warnings and errors in memory, with their attributes as the text handler writes them. Nothing
  secret is logged (the password of the first administrator is printed apart), so the read-only administrators can
  read them.

`GET /api/system/history?range=<seconds>&since=<unix>` answers the points of the range, from the points of 5 seconds
up to an hour and of a minute past it, after `since` only: the page asks once for the range, then only for the new
points, every 5 seconds (every minute for the points of a minute). `GET /api/system/log` answers the warnings and the
errors, `?level=all` every line, the newest first.

## The container

- **Rights**: compose.yaml drops every capability but `NET_ADMIN` (`wgctrl`, `ip`, `nft` and `conntrack` work through
  netlink in the network of the container), sets `no-new-privileges` and a read-only root with a `/tmp` in memory.
  The process is root without the rights of root: it reads and writes only what root owns, which is everything in
  `/data` when Docker makes the folder. The ports are above 1024 (the DNS and HTTP redirects reach 8153 and 8180
  through nftables, the DNS of the peers with names 8154), so `NET_BIND_SERVICE` isn't needed either.
- **Network**: the sysctls `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding`, and IPv6 on the Docker network
  (`enable_ipv6`): see [IPv6](#ipv6). Changing the network needs `docker compose down`, then `up -d`. For routed
  servers, `compose.host-routes.yaml` adds the helper of the Docker host, or `compose.macvlan.yaml` puts the container
  on a macvlan network of the local network instead.
- **Health**: `GET /healthz` on the port of the web UI, without a login, answers `{"status":"ok"}` or 503 and the
  codes of what fails: `stuck` (no pass of `Tick` for 30 seconds, or the lock of the service held for 3 seconds:
  `Health` tries it, it doesn't wait in line), `database`, `configuration` (the error of the latest apply),
  `tunnels` (the error of the latest reading of WireGuard). Nothing more, since anybody who reaches the port can
  ask. `authway-server healthcheck` is the `HEALTHCHECK` of the image: it asks 127.0.0.1 on the port of
  `AUTHWAY_ADMIN_LISTEN`, without checking the certificate (its own, on the same host).
- **Version**: `main.version` is the version of the source; `-ldflags -X main.version=...` (the build argument
  `VERSION`, `AUTHWAY_VERSION` in compose) replaces it. `/api/status` gives it to the web UI. The workflow
  `.github/workflows/image.yml` checks that the tag is the version of the source, then builds the image for amd64
  and arm64: the web UI and the server are built on the machine of the build (`$BUILDPLATFORM`, Go cross-compiles),
  only `apk add` of the last stage runs on the target.
- **Certificate** (`cmd/authway-server/tls.go`): `GetCertificate` gives the pair of now. The files are read again
  every minute, and during the handshakes at most every 30 seconds, and compared by their SHA-256: a new pair that
  loads replaces the one in use, one that doesn't is an error on the System page while the one before stays.
  Without both files, a self-signed certificate is made (P-256, 2 years, for localhost, `AUTHWAY_PUBLIC_HOST`, the
  name of the container and 127.0.0.1) and written whole (`.new` then a rename). One whose name is `Authway Server`
  and that signed itself is made again 30 days before its end; any other is never replaced, and the System page
  warns 30 days before it ends.
