[Authway Server](../README.md) › Features

# Features

## WireGuard servers and peers

- **Several WireGuard servers on one host**, each with its own UDP port, tunnel network, peers and settings.
- **Peers in a few clicks**: a configuration file to download, or a QR code for the phones. The address of a new peer
  in the tunnel is the next free one. On a server with login each peer belongs to a user, one peer per user and
  server.
- **Many users at once**, from a CSV file made with a spreadsheet: a username, a full name and a password for each.
  Every row is checked and shown before anything is added, and the file is imported whole or not at all. The
  passwords left empty are made by the server and shown once.
- **IPv4 and IPv6 in the tunnels**: a server can have an IPv6 network besides its IPv4 one, and each of its peers then
  has the IPv6 address that matches its IPv4 one: `10.8.0.5` is `…::5`. The devices reach the server over IPv4 or
  IPv6.
- **Fallback addresses**: up to 4 other addresses of a server, a second internet line for example, in the
  configuration files. Authway tries them when the main address doesn't answer.

## A login before any access

- **The login of each server**: *WireGuard key only*, as plain WireGuard; *password*; or *password and authenticator
  code*, from Google Authenticator, Microsoft Authenticator, 2FAS or any other app that makes such codes.
- **The gate**: until its user logs in, a peer reaches nothing but the login page and ping of its server. The gate
  is a set of nftables rules inside the container.
- **The login page finds the user**: before the login, any name resolves to the server and any plain `http://`
  address opens the login page, so the users of the official WireGuard apps log in from a browser. Authway shows its
  own login window. Nothing is forwarded before the login, so DNS can't carry data out either.
- **Sessions end** at logout, at the end of their length (8 hours by default), after 5 minutes without a WireGuard
  handshake, and when the user, the peer or the server change.
- **Failed logins**: 5 in 15 minutes from the same public IP lock that IP out for 15 minutes, and 20 from any IPs lock
  the peer out everywhere but at the IP of its latest login, so a copy used from another network can't lock out the
  real user. Each lockout is an alert. An IPv6 address counts by its `/64`, the network it belongs to. Each
  authenticator code works once.

## Protection against copied configuration files

A WireGuard configuration file is a key: anyone with a copy connects. With a login a copy alone isn't enough, and each
server can add more:

- **The lock of the session to the public IP of the login.** *Strict*: while the peer sends from another IP, the
  session pauses and the peer is out; it resumes when the IP of the login comes back, and ends after 5 minutes.
  *Roaming*: the session follows the device to its new network. *Off*.
- **Two devices with the same key**: the endpoint of the peer keeps switching between their public IPs. The session
  ends and an alert is recorded; optionally the peer is blocked until an administrator clears its alerts or gives it
  new keys.
- **Device binding**, for a server with login and the users of Authway: each peer logs in only from the computer
  enrolled for it, the first one that logs in. The file and the password, copied to another computer, don't log in.
  Optionally the hardware of the computer is checked too. Once logged in, Authway gives the peer a WireGuard key of
  its own: from then on the configuration file, and every copy of it, doesn't even connect.

## Networks

- **What the peers reach**: the networks you list for each server, your LAN for example, or everything for a peer
  that sends all its traffic through the tunnel.
- **Access rules for each peer**: a peer can reach only some of the networks of its server, down to single
  addresses: the file server for one user, the printer for another. The firewall of the server enforces them, with
  NAT and routed alike, whatever the configuration file says. With all its traffic through the tunnel, such a peer
  reaches the internet too, but no other private network. On a server with login each user has one peer, so these
  are the access rules of the user.
- **NAT or routed**, for each server: its networks see the address of the host, with nothing to set up, or the address
  of each peer, for their logs and firewall rules. Routed, they can also start connections to the peers logged in.
  See [Routed servers](routed-servers.md).
- **Traffic between peers**: off by default. For each server, its peers can reach each other, and the peers of the
  other servers you choose, one way. With a login, both peers must be logged in.

## What you can see

- **Who is logged in now**, the history of the logins, and the **connection history** of every peer, with a login or
  not: from which public IP, when, how long, how many bytes. Every list has search, filters by server and dates,
  pages, and a CSV download.
- **Alerts**: lockouts, copied configurations, a device that isn't the enrolled one.
- **An audit trail**: every change made in the web UI is an event, with the administrator who made it, from which
  address, and what changed. Opening the configuration file of a peer, with its private key, is one too.
- **A System page** for when something goes wrong, in tabs: the checks of what breaks most (the configuration
  applied, WireGuard read, the interfaces of the servers up, IP forwarding, IPv6, the way of the routed servers to
  their networks, the clock, the disk, the memory, the load, connection tracking, errors in the log) with a summary;
  the history of the last 24 hours of the processors, the memory and the traffic of each interface; the network
  interfaces; the disks, the host and Authway Server; and the latest lines of the log. A dot on a tab says it has a
  warning or an error.

## Administration

- **Several administrators**, each with a role: **Administrator** (everything), **Operator** (the users, the peers,
  the sessions and the alerts, not the servers, the administrators or the settings) or **Read-only**. Each one can
  log in with an authenticator app too, and the settings can require it of everybody. A password given by someone
  else is changed at the first login.
- **A password policy** for the users and the administrators: minimum length, lowercase, uppercase, digit, symbol,
  never the username.
- **Two administrators at once**: a form saved over a change that another administrator made since it opened is
  refused instead of undoing it. The form then shows who changed what, takes their changes on the fields you didn't
  touch, keeps yours, and asks which to keep where you both changed the same field.
- **Backup and restore** of the whole configuration, in a file encrypted with a passphrase.
- **HTTPS for the web UI** with a self-signed certificate made and renewed by itself, or your own.
- **A locked-down container**: no right but `NET_ADMIN`, a read-only system, and nothing written outside `./data`. A
  health check shows in `docker ps`.


## Not yet

These may come next:

- LDAP or Active Directory users.
- Device keys in the TPM or the Secure Enclave, which not even an administrator of the computer can copy.
