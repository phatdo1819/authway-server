[Authway Server](../README.md) › Install

# Install

## What you need

- **A Linux host**, physical, virtual or in the cloud, amd64 or arm64, with WireGuard in its kernel: Linux 5.6 or
  later has it. Debian 11 or later, Ubuntu 22.04 or later, Fedora, RHEL, Rocky Linux or AlmaLinux 9, and Raspberry Pi
  OS 64-bit all do.
- **Memory and disk**: building the image takes about 1.5 GB of memory, swap included, and 3 GB of disk. Running it
  takes far less. A small host can use a published image instead of building one.
- **Docker 27 or later**, with Compose 2.24 or later and Buildx. The install script installs them.
- **A public name or IP address** for the host, where the peers connect: a dynamic DNS name works. And **one UDP port
  for each WireGuard server**, forwarded to the host by your router.
- **root**, or `sudo`.

## Install with the script

From a copy of the source, on the host:

```sh
git clone https://github.com/phatdo1819/authway-server.git authway-server
cd authway-server
sudo ./install.sh
```

It asks for two addresses, and proposes the ones it finds:

- **The address of the host in your local network**, `192.168.1.10` say: the web UI listens only there.
- **The public name or IP address** where the peers connect, `vpn.example.com` say. It's the default of the new
  WireGuard servers: each server can have another one in the web UI.

Then it:

1. checks the host: Linux, WireGuard in the kernel (and loads it at every start), IPv6, memory, and whether its
   address comes from DHCP: it warns, and asks before going on with an address that can change;
2. installs Docker Engine with its Compose and Buildx plugins when they're missing, with the official packages of
   Docker, and starts it;
3. copies the source to `/opt/authway-server`;
4. writes the settings in `/opt/authway-server/.env`: the two addresses and the time zone of the host;
5. builds the image;
6. starts Authway Server, waits until it's healthy, and prints the first administrator, its password, the address of
   the web UI, and what to do next.

To ask nothing, give the addresses, or let it find them:

```sh
sudo ./install.sh --yes --public-host vpn.example.com --ui-address 192.168.1.10
```

| Option | What it does |
|---|---|
| `--public-host HOST` | The public name or IP address where the peers connect. |
| `--ui-address ADDR` | The address of the host in the local network: the web UI listens only there. Found from the default route if not given. `0.0.0.0` for every address, not advised. |
| `--timezone ZONE` | The time zone of the log, `Europe/Rome` say. The one of the host if not given. |
| `--host-routes`, `--no-host-routes` | Turn on or off the [routed servers through the Docker host](routed-servers.md#through-the-docker-host). |
| `--dir DIR` | The install folder: `/opt/authway-server`, or the folder of the Authway Server that already runs. |
| `--image REF` | Use a published image instead of building one, `ghcr.io/phatdo1819/authway-server:0.2.0`: for a host with little memory. |
| `--repo URL`, `--ref REF` | Get the source with git, when the script runs alone, not from a copy of the source. |
| `--no-docker-install` | Stop instead of installing Docker when it's missing. |
| `--rollback` | Go back to the version before the last upgrade: see [Go back](#go-back). |
| `--uninstall` | Stop and remove the containers and the image. The install folder and its data stay. |
| `-y`, `--yes` | Ask nothing. |

Docker is installed with [its official script](https://get.docker.com) on Debian, Ubuntu, Raspberry Pi OS, Fedora,
CentOS and RHEL, and from its repository for CentOS on Rocky Linux, AlmaLinux and Oracle Linux. Arch Linux, openSUSE
and Alpine get the Docker of their own packages, not tested. On other systems, install Docker first, then run the
script: it uses the Docker it finds, if recent enough.

The install folder holds:

- `.env`: the settings. Change them there, then run `docker compose up -d` in the folder, or the script again.
- `data/`: the database (the keys of the servers and of the peers, the users, the history) and the certificate of
  the web UI. Keep it private.
- the source and the compose files: don't change those, the next upgrade replaces them. Put your own changes in a
  `compose.override.yaml` next to them: the script keeps it, and lists it in `COMPOSE_FILE`.

Useful commands, in `/opt/authway-server`:

```sh
docker compose ps                        # running? healthy?
docker compose logs -f authway-server    # the log
docker compose restart authway-server
```

## Install by hand

The script only automates these steps:

```sh
git clone https://github.com/phatdo1819/authway-server.git authway-server && cd authway-server
sudo modprobe wireguard && echo wireguard | sudo tee /etc/modules-load.d/authway-server.conf
printf '%s\n' AUTHWAY_PUBLIC_HOST=vpn.example.com AUTHWAY_UI_ADDRESS=192.168.1.10 TZ=Europe/Rome > .env
docker compose up -d --build
docker compose logs authway-server
```

The log prints the first administrator and its random password, once:

```
  First administrator of the web UI: admin
  Password: ...
```

To set the first password yourself instead, start the first time with `AUTHWAY_ADMIN_PASSWORD` in the environment.

## On your router

- **Forward the UDP port of each WireGuard server** from the internet to the address of the host in the local
  network: 51820 for the first server, 51821 for the second, and so on up to 51829. compose.yaml publishes these 10.
- **Give the host a fixed address** in the local network, a DHCP reservation for example: the forwarded ports, the
  web UI and the routes of the routed servers follow it. With another address the web UI isn't there any more, and
  after a restart Docker can't start Authway Server until `AUTHWAY_UI_ADDRESS` in `.env` has the new one.
- **Never forward 8443**: the web UI is for your local network.
- **For a routed server**, add the route that the server shows, `10.8.0.0/24 via 192.168.1.10`: see
  [Routed servers](routed-servers.md).

## Upgrade

```sh
cd authway-server && git pull
sudo ./install.sh
```

The data, `.env` and `compose.override.yaml` stay. The script:

1. keeps the image that runs now as `authway-server:previous`;
2. builds the new one, or pulls it with `--image`;
3. stops Authway Server and copies the database to `data/pre-upgrade-<date>`, the newest 5 copies kept;
4. says when the new version changes the **schema** of the database, `schema 7 → 8` say;
5. starts the new version, which changes the schema as it starts, and waits until it's healthy.

### Schema changes

Some versions add to the database: the access rules of the peers, for one. The new version changes the schema at
its first start, by itself, and an older version can't open the database then: it stops at once with *the database
is from a newer version of Authway Server*, rather than run without what it doesn't know, and let the peers reach
more than their rules say. So before changing the schema, Authway Server copies the database to
`data/before-schema<N>-<date>/authway.db`, also when it's upgraded by hand, and its log says so.

### Go back

```sh
sudo ./install.sh --rollback
```

It goes back to the version before the last upgrade done with the script, `authway-server:previous`:

- **The upgrade didn't change the schema**: the database stays, with everything changed since.
- **It changed it**: the copy made by the upgrade goes back, and the database of the newer version goes aside to
  `data/pre-rollback-<date>`. What changed since the upgrade, users, peers or settings, isn't in the copy.

It goes back one version, once. To upgrade again, run `sudo ./install.sh` from the newer source.

### By hand

`git pull && docker compose up -d --build`. To go back by hand after a schema change: stop Authway Server with
`docker compose stop`, move the files `data/authway.db*` aside, copy `authway.db` from the newest
`data/before-schema<N>-<date>` back into `data/`, and start the version of before.

## Uninstall

```sh
sudo ./install.sh --uninstall
```

The containers and the image go; Docker stays, and so does `/opt/authway-server` with the configuration and the data.
Delete the folder to remove them too, the keys of the servers included: the configuration files of the peers then
stop working for good.
