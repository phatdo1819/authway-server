[Authway Server](../README.md) › IPv6

# IPv6

- **In the tunnels**: a new server proposes an IPv6 network, a `/64` of unique local addresses (`fd…`) picked at
  random once and then shared by your servers, one `/64` each. Leave it empty for IPv4 only. From `/64` to `/120`,
  with at least as many addresses as the IPv4 network. An existing server gets one in **Edit > IPv6 tunnel network >
  Suggest an IPv6 network**.
- **A server with peers can get it, or lose it, at any time**: the peers' addresses follow from their IPv4 ones. Their
  configuration files of before still connect, over IPv4; download them again for IPv6.
- **The traffic of the peers** goes out with the address of the container, as IPv4 does, and Docker sends it out with
  the address of the host. Unique local addresses come with a habit of the devices: when a site has both, they choose
  IPv4, and IPv6 for what has only IPv6. The networks the peers reach can be IPv6 ones too.
- **A server without an IPv6 network** drops IPv6, as before. A peer of it that sends all its traffic through the
  tunnel sends only IPv4 there: its IPv6 goes out of the device, as with any WireGuard file that lists only
  `0.0.0.0/0`. With an IPv6 network, the file lists `::/0` too.
- **The login page** stays at the IPv4 address of the server, the one in the files. It answers on the IPv6 address too,
  and before the login a name resolves to both addresses of the server.
- **Docker**: compose.yaml turns on IPv6 on the network of the container (`enable_ipv6`) and IPv6 forwarding inside it.
  Docker 27 or later gives the network a `/64` by itself and sends its IPv6 out through the host as it does IPv4. An
  older Docker needs a subnet written in compose.yaml and `ip6tables` in the settings of its daemon: update Docker,
  or take the IPv6 lines away for IPv4 only. With IPv6 on, the WireGuard ports see the real IPv6 address of each
  device. Without it, Docker passes the devices that connect over IPv6 on from an IPv4 address of its own: they all
  look like one device, for the lock and for the failed logins.
- **An installation of before** needs the network made again: `docker compose down`, then `docker compose up -d`. The
  data stays in `./data`.
- **A host whose kernel has no IPv6** (booted with `ipv6.disable=1`) can't start the container with these settings:
  take the line `net.ipv6.conf.all.forwarding=1` and the `networks:` part away from compose.yaml.
- **The System page** checks IPv6 when a server has it: IPv6 on in the container, forwarding on, a route out.
- **The web UI** listens on IPv4. For IPv6 put an IPv6 address of the host in `AUTHWAY_UI_ADDRESS`.
