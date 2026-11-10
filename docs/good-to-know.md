[Authway Server](../README.md) › Good to know

# Good to know

## Ports and security

- **Ports**: compose.yaml publishes the UDP ports 51820 to 51829, for 10 servers, and 8443 for the web UI. Change
  them there. A server whose port Docker publishes under another number has a **Public port** in its advanced
  settings. Without `AUTHWAY_UI_ADDRESS`, the web UI is on every address of the host, and the rules of Docker come
  before a firewall such as ufw.
- **The web UI is for your local network**: don't forward 8443 from the internet. To use your own certificate,
  replace `data/tls/cert.pem` and `data/tls/key.pem`: no restart needed.
- **The container has no right but NET_ADMIN**, for the WireGuard interfaces and the firewall rules inside its own
  network: compose.yaml drops all the others, forbids gaining new ones and makes its system read-only, so it writes
  only in `./data` and a `/tmp` in memory. Docker creates `./data` for root; a folder made by another user before
  the first start can't be written: `sudo chown root: data`.
- **The networks behind the server see the address of the Docker host**, not the ones of the peers: the traffic is
  masqueraded twice, by Authway Server and by Docker. For the addresses of the peers, see
  [Routed servers](routed-servers.md).
- **"Send all the traffic through the tunnel"** on a peer lets it reach everything the host reaches, the internet
  and the Docker networks included. The other peers reach only the networks of their server.
- **Traffic between peers** is off by default. The peers of a server reach the peers of another server only when
  the server lists it (**Edit > Traffic between peers**), and only that way: for both ways, each one lists the other.
  When the list changes, the peers that don't send all their traffic through the tunnel need their file again: it
  routes the networks of the linked servers.

## Running it

- **Health**: `docker ps` shows *healthy* or *unhealthy*. The check (`authway-server healthcheck`, every 30 seconds)
  asks `https://127.0.0.1:8443/healthz`, which answers 503 with what fails: `configuration` (not applied),
  `tunnels` (WireGuard can't be read), `database`, `stuck` (the loop of the sessions). It needs no login and says
  nothing else. Docker doesn't restart an unhealthy container by itself: a monitoring tool can.
- **The log of the container** keeps 3 files of 10 MB at most (`logging` in compose.yaml). The latest lines are also
  on the **System** page, in its **Log** tab.
- **The version** is at the bottom of the menu and on the System page: the one of the source, or what you give at
  the build to tell builds apart: `AUTHWAY_VERSION=0.2.0+$(git rev-parse --short HEAD) docker compose build`.
- **A published image**: `.github/workflows/image.yml` builds the image for amd64 and arm64 and publishes it on the
  GitHub Container Registry of the repository at each tag `v<version>` (the version of `cmd/authway-server/main.go`).
  To use it instead of building, replace `build:` in compose.yaml with `image: ghcr.io/phatdo1819/authway-server:0.2.0`.
- **The certificate of the web UI**: the self-signed one is valid 2 years and made again 30 days before its end (the
  browsers then warn once more). Your own `data/tls/cert.pem` and `data/tls/key.pem` are loaded within a minute,
  without a restart; a pair that doesn't load leaves the one before in use. Yours is never replaced: the System page
  warns 30 days before it expires. Delete both files to get a self-signed one again.
- **The System page** shows the host as the container sees it: the processors, the memory and the load are the ones
  of the whole host, the interfaces are the ones of the container (`eth0` carries the tunnels and the web UI, each
  `wg` interface the traffic of the peers inside their tunnels), and the disk is the one of `./data`. Its history is
  kept in memory and starts again with the container. The clock check compares the server with the computer of the
  browser too: authenticator codes fail past 30 seconds of difference.

## Data, backups and history

- **The data** is in `./data`: the database `authway.db` (the keys of the servers and of the peers, the users, the
  devices, the history) and the certificate. Keep it private.
- **Backups**: **Settings > Backup and restore** downloads the whole configuration (servers and their keys, peers,
  users with their passwords and authenticators, the devices enrolled, administrators, settings) in a file encrypted
  with a passphrase that you choose, at least 12 characters. Keep the passphrase apart from the file: without it nobody can restore
  the backup. A restore, on this host or on a new one, replaces the whole configuration: the open sessions end, every
  administrator is logged out and logs in again with the accounts of the backup. The history of the logins and of
  the connections, the events and the alerts aren't in the backup, nor the certificate of the web UI. On a new host, log in with the first password
  printed in the log, choose a new one, then restore: the peers connect again with their configuration files, as
  long as the host has the same public address and ports.
- **The history** (logins, connections, events, alerts) stays 90 days by default: **Settings > History**, from 1 day
  to 10 years. Fewer days delete the older rows within seconds.

## Administrators

- **Two administrators editing the same thing**: the second one to save is told who saved first, and what. Their
  changes come into the form, yours stay, and where you both changed the same field the form keeps yours until you
  choose theirs. Nothing is saved until you save again.
- **The roles**: an Operator gets the configuration files of the peers (their private keys) and sets up the
  authenticators of the users; a Read-only administrator gets neither. Only Administrators change the servers, the
  settings and the administrators. The last active Administrator can't be removed, demoted or disabled, and nobody
  changes their own role.
- **A lost administrator password or authenticator**: another Administrator gives a new password or removes the
  authenticator in **Administrators**. Without one, on the host:
  `docker exec authway-server authway-server reset-admin-password [username]` prints a new password, changed at the
  next login, and `docker exec authway-server authway-server reset-admin-mfa [username]` removes the authenticator.
  Without a username, they act on the first Administrator.

## Peers and devices

- **Access rules**: in the menu of a peer, **Edit > Networks it reaches > Only some of them**, addresses or networks
  inside the ones of the server. They apply at once, to the connections already open too. The peer still asks the
  DNS servers of the server, wherever they are, on port 53 only; its configuration file routes its networks and those
  DNS servers, so download it again after a change, unless it sends all its traffic. The server can't drop a network
  that a peer still reaches part of: change the peer first. The traffic between peers doesn't depend on them.
- **Import**: **Users > Import** reads a CSV file, from a spreadsheet saved as *CSV UTF-8*, with a header that names
  its columns in any order: `username`, `full_name` and `password`, the last two optional. Each row adds a user, as
  **Add user** does. An import never changes a user: a username already there stops the import, or, with **Skip the
  users that already exist**, its row is skipped, to import an updated list again. **Download a template**
  gives an example. Each row is shown with the user it adds or what's wrong, and nothing is added until every row is
  right. The passwords left empty are made, shown once and downloaded as CSV: give each user their own, apart from
  the configuration file. Then give each user a peer on its server. At most 500 rows a file.
- **The configuration file** is named after the server and the peer, `ABC-test22.conf`: the WireGuard apps name the
  tunnel after it, at most 32 characters, so long names are cut. A file imported again under another name is a
  second tunnel in the app: remove the old one.

- **Device binding needs Authway**, on Windows or macOS, and 0.2.0 or later for the WireGuard key of the device: the
  browser and the WireGuard apps can't sign the login. The first computer that logs in for a peer is enrolled, during 72 hours by default (**Settings >
  Device binding**). After a reinstall or for a new computer, choose **Replace the device** in the menu of the
  peer: the next computer that logs in is enrolled. **Revoke the device** leaves the peer without one until you
  allow a new one. Turning binding on logs out the peers of the server: they log in again from their computer.
- **The WireGuard key of the device**: once Authway gave it, a configuration file downloaded again doesn't connect,
  even on the same computer. Replace the device, or give the peer new keys, to start again with a file. Until the
  computer is enrolled, a copy of the file still connects, like without binding: it just can't log in.
- **Keepalive**: the peers send a keepalive every 25 seconds by default. With it off, an idle peer makes no handshake
  and its session ends after 5 minutes.
- **Connected or offline**: a peer shows *Connected* while it sends something at least every two keepalives, so it
  shows offline within a minute of leaving (55 seconds with 25 seconds of keepalive), and while its latest
  handshake is younger than 3 minutes. Without a keepalive an idle device sends nothing: only the handshake counts,
  and a device that left shows offline after up to 3 minutes.
- **Last handshake, or Seen**: WireGuard forgets the handshakes when Authway Server starts again, at an upgrade say.
  Until a peer connects again, its row shows *Seen* and the time and public IP from the connection history; *never*
  only for a peer that never connected.
- **The strict lock and phones**: a phone that moves from Wi-Fi to 4G gets a new public IP, so its session pauses
  and the user logs in again. Choose *Roaming* for the servers of devices that move a lot.
- **Two devices behind the same NAT** share a public IP: the lock and the detection can't tell them apart. The same for
  two devices of one IPv6 network: their addresses count by their `/64`, since a device changes its own IPv6 address
  in its network over the day.

## Troubleshooting

- **"Unknown device type"** in the log: the host kernel has no WireGuard module. Run `sudo modprobe wireguard` on the
  host, or update its kernel.
- **Look at the tunnels**: `docker exec authway-server wg show`.
- **The networks of a routed server stopped answering**: the System page says why. After a change of the address of
  the Docker host, the router needs the new route: see
  [Routed servers](routed-servers.md#through-the-docker-host).
