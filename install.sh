#!/bin/sh
# Install or upgrade Authway Server on a Linux host, Docker included.
#
#   sudo ./install.sh                     from a copy of the source: asks for what it can't find out
#   sudo ./install.sh --yes --public-host vpn.example.com
#   sudo ./install.sh --help              all the options
#
# What it does:
#   1. checks the host: Linux with WireGuard in its kernel (5.6 or later has it), IPv6 on, enough memory and disk
#   2. installs Docker Engine and its Compose plugin when they're missing, with the official packages of Docker
#   3. copies the source to the install folder, /opt/authway-server by default
#   4. writes the settings in .env there: the public address, the address of the web UI, the time zone
#   5. builds the image, or pulls a published one with --image
#   6. starts it, waits until it's healthy, and prints the first administrator and what to do next
#
# Run again from a newer source, it upgrades: the data folder, .env and compose.override.yaml stay, and the database
# is copied first to data/pre-upgrade-<date>. --uninstall stops and removes the containers, never the data.
set -eu

DIR=/opt/authway-server
DIR_GIVEN=no
PUBLIC_HOST=""
UI_ADDRESS=""
TIME_ZONE=""
HOST_ROUTES=""
IMAGE=""
REPO=""
REF=""
YES=no
INSTALL_DOCKER=yes
UNINSTALL=no

# the versions it needs: IPv6 on the network of the container, and !reset in compose.macvlan.yaml
DOCKER_MIN=27
COMPOSE_MIN=2.24

usage() {
	cat <<'EOF'
Install or upgrade Authway Server on this Linux host, Docker included.

Usage: sudo ./install.sh [options]

  --public-host HOST   the public name or IP address where the peers connect, vpn.example.com say. The default
                       address of new WireGuard servers: each server can have another one in the web UI
  --ui-address ADDR    the address of this host in the local network: the web UI listens only there. Found from
                       the default route if not given; 0.0.0.0 for every address (not advised)
  --timezone ZONE      the time zone of the log, Europe/Rome say: the one of this host if not given
  --host-routes        turn on the routed servers through the Docker host (compose.host-routes.yaml)
  --no-host-routes     turn them off
  --dir DIR            the install folder: /opt/authway-server, or the folder of the Authway Server that runs
  --image REF          use a published image instead of building one: ghcr.io/phatdo1819/authway-server:0.1.0
  --repo URL           get the source with git from there, when the script doesn't run from a copy of it
  --ref REF            the branch or tag of --repo
  --no-docker-install  stop instead of installing Docker when it's missing
  --uninstall          stop and remove the containers and the image; the install folder and its data stay
  -y, --yes            ask nothing: what isn't given is found out, or left as it is
  -h, --help           this help

Run again later from a newer source to upgrade: the data, .env and compose.override.yaml stay.
EOF
}

# ---- output ----------------------------------------------------------------------------------------------------

if [ -t 1 ]; then
	BOLD=$(printf '\033[1m'); RED=$(printf '\033[31m'); YELLOW=$(printf '\033[33m'); GREEN=$(printf '\033[32m')
	RESET=$(printf '\033[0m')
else
	BOLD=""; RED=""; YELLOW=""; GREEN=""; RESET=""
fi
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    %sWarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() { printf '\n%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# ---- options ---------------------------------------------------------------------------------------------------

need_value() { # option value: stops when an option that needs a value has none
	[ -n "${2:-}" ] || die "$1 needs a value: ./install.sh --help"
}
while [ $# -gt 0 ]; do
	case "$1" in
	--public-host) need_value "$1" "${2:-}"; PUBLIC_HOST=$2; shift 2 ;;
	--public-host=*) PUBLIC_HOST=${1#*=}; shift ;;
	--ui-address) need_value "$1" "${2:-}"; UI_ADDRESS=$2; shift 2 ;;
	--ui-address=*) UI_ADDRESS=${1#*=}; shift ;;
	--timezone) need_value "$1" "${2:-}"; TIME_ZONE=$2; shift 2 ;;
	--timezone=*) TIME_ZONE=${1#*=}; shift ;;
	--host-routes) HOST_ROUTES=yes; shift ;;
	--no-host-routes) HOST_ROUTES=no; shift ;;
	--dir) need_value "$1" "${2:-}"; DIR=$2; DIR_GIVEN=yes; shift 2 ;;
	--dir=*) DIR=${1#*=}; DIR_GIVEN=yes; shift ;;
	--image) need_value "$1" "${2:-}"; IMAGE=$2; shift 2 ;;
	--image=*) IMAGE=${1#*=}; shift ;;
	--repo) need_value "$1" "${2:-}"; REPO=$2; shift 2 ;;
	--repo=*) REPO=${1#*=}; shift ;;
	--ref) need_value "$1" "${2:-}"; REF=$2; shift 2 ;;
	--ref=*) REF=${1#*=}; shift ;;
	--no-docker-install) INSTALL_DOCKER=no; shift ;;
	--uninstall) UNINSTALL=yes; shift ;;
	-y | --yes) YES=yes; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option $1: ./install.sh --help" ;;
	esac
done

# questions go to the terminal, also when the script comes through a pipe
INTERACTIVE=no
if [ "$YES" = no ] && (: </dev/tty) 2>/dev/null; then
	INTERACTIVE=yes
fi
ask() { # question default: the answer, or the default
	if [ "$INTERACTIVE" = yes ]; then
		printf '    %s [%s]: ' "$1" "$2" >/dev/tty
		read -r answer </dev/tty || answer=""
		printf '%s' "${answer:-$2}"
	else
		printf '%s' "$2"
	fi
}
confirm() { # question: true for yes; without questions, yes
	[ "$INTERACTIVE" = yes ] || return 0
	printf '    %s [Y/n]: ' "$1" >/dev/tty
	read -r answer </dev/tty || answer=""
	case "$answer" in [nN]*) return 1 ;; *) return 0 ;; esac
}

[ "$(uname -s)" = Linux ] || die "Authway Server runs on Linux."
[ "$(id -u)" = 0 ] || die "run it as root: sudo sh $0 $*"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM

# the Authway Server that runs now, if any: its folder, from the labels of Docker Compose
running_dir() {
	command -v docker >/dev/null 2>&1 || return 0
	docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' authway-server 2>/dev/null || true
}

# ---- uninstall -------------------------------------------------------------------------------------------------

if [ "$UNINSTALL" = yes ]; then
	current=$(running_dir)
	[ "$DIR_GIVEN" = yes ] || [ -z "$current" ] || DIR=$current
	grep -qs "container_name: authway-server" "$DIR/compose.yaml" || die "no Authway Server in $DIR: give its folder with --dir"
	step "Removing Authway Server of $DIR"
	confirm "Stop and remove the containers of Authway Server? The data stays in $DIR/data" || exit 0
	# the named volume is only the folder in memory of the helper: the data is a folder, it stays
	(cd "$DIR" && docker compose down --remove-orphans --volumes)
	docker image rm authway-server:latest >/dev/null 2>&1 || true
	info "Done. The configuration and the data stay in $DIR: delete the folder to remove them too, keys included."
	info "Docker stays installed."
	exit 0
fi

# ---- the host --------------------------------------------------------------------------------------------------

step "Checking this host"
if [ -r /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
fi
OS_ID=${ID:-unknown}
OS_LIKE=${ID_LIKE:-}
info "System: ${PRETTY_NAME:-$OS_ID}, kernel $(uname -r), $(uname -m)"

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*)
	ARCH=$(uname -m)
	warn "Authway Server is tested on amd64 and arm64, not on $ARCH: the build may work"
	[ -z "$IMAGE" ] || die "the published images are for amd64 and arm64 only: build it, without --image"
	;;
esac

# WireGuard: in the kernel since Linux 5.6, a module before on some systems
if [ ! -d /sys/module/wireguard ] && ! modprobe wireguard 2>/dev/null; then
	die "the kernel of this host has no WireGuard. Update the kernel to Linux 5.6 or later (the systems of the last
       years have it), or install the WireGuard module of your system, then run this again."
fi
info "WireGuard: in the kernel"
# loaded at every start: the container can't load a module
if [ -d /etc/modules-load.d ] && [ ! -f /etc/modules-load.d/authway-server.conf ]; then
	echo wireguard >/etc/modules-load.d/authway-server.conf
fi

[ -d /proc/sys/net/ipv6 ] || die "IPv6 is off in the kernel of this host (ipv6.disable=1), and compose.yaml needs it.
       Turn it on, or take the IPv6 lines away from compose.yaml as docs/ipv6.md says, then install by hand."

memory=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
swap=$(awk '/^SwapTotal:/ { print int($2 / 1024) }' /proc/meminfo)
info "Memory: $memory MB, swap $swap MB"
if [ -z "$IMAGE" ] && [ $((memory + swap)) -lt 1500 ]; then
	warn "building the image takes about 1.5 GB of memory, and this host has $((memory + swap)) MB with the swap.
             Add swap, or use a published image with --image."
	confirm "Try anyway?" || exit 1
fi

# ---- packages --------------------------------------------------------------------------------------------------

package_manager() {
	for manager in apt-get dnf yum zypper pacman apk; do
		if command -v $manager >/dev/null 2>&1; then
			echo $manager
			return
		fi
	done
}
PM=$(package_manager)
APT_UPDATED=no
install_packages() { # packages...
	case "$PM" in
	apt-get)
		if [ "$APT_UPDATED" = no ]; then
			DEBIAN_FRONTEND=noninteractive apt-get update -qq
			APT_UPDATED=yes
		fi
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
		;;
	dnf) dnf install -y -q "$@" ;;
	yum) yum install -y -q "$@" ;;
	zypper) zypper --non-interactive --quiet install "$@" ;;
	pacman) pacman -Sy --noconfirm --needed "$@" ;;
	apk) apk add --no-cache -q "$@" ;;
	*) die "no package manager known to this script: install $* by hand, then run this again" ;;
	esac
}
need() { # command package: installs the package when the command is missing
	command -v "$1" >/dev/null 2>&1 && return
	info "Installing $2"
	install_packages "$2"
}
need curl curl
need tar tar
case "$PM" in
dnf | yum) need ip iproute ;;
*) need ip iproute2 ;;
esac
[ -z "$REPO" ] || need git git
[ "$PM" != apt-get ] || [ -f /etc/ssl/certs/ca-certificates.crt ] || install_packages ca-certificates

# ---- Docker ----------------------------------------------------------------------------------------------------

version_at_least() { # version minimum: true when version >= minimum, by numbers
	printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n -C
}
start_docker() {
	if [ -d /run/systemd/system ]; then
		systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker
	elif command -v rc-service >/dev/null 2>&1; then
		rc-update add docker default >/dev/null 2>&1 || true
		rc-service docker start
	else
		service docker start
	fi
	for _ in $(seq 1 30); do
		docker info >/dev/null 2>&1 && return
		sleep 1
	done
	die "Docker doesn't answer: look at its log (journalctl -u docker), then run this again"
}
install_docker() {
	like=" $OS_ID $OS_LIKE "
	case "$OS_ID" in
	debian | ubuntu | raspbian | fedora | centos | rhel)
		# the official script of Docker: its repository, Docker Engine, containerd, Buildx and Compose
		info "Installing Docker with its official script, get.docker.com"
		curl -fsSL https://get.docker.com -o "$TMP/get-docker.sh"
		sh "$TMP/get-docker.sh" >"$TMP/get-docker.log" 2>&1 || {
			tail -20 "$TMP/get-docker.log" >&2
			die "Docker couldn't be installed: see above"
		}
		;;
	*)
		case "$like" in
		*" rhel "* | *" centos "* | *" fedora "*)
			# Rocky, AlmaLinux, Oracle Linux...: the repository of Docker for CentOS, as its documentation says
			info "Installing Docker from its repository for CentOS"
			curl -fsSL https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo
			install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
			;;
		*" debian "* | *" ubuntu "*)
			# Linux Mint, Pop!_OS...: the script of Docker knows only the systems they come from
			die "this script installs Docker only on Debian, Ubuntu, Raspberry Pi OS, Fedora, CentOS, RHEL and
       their rebuilds. Install Docker Engine $DOCKER_MIN or later with its Compose plugin for $OS_ID
       (https://docs.docker.com/engine/install/), then run this again."
			;;
		*)
			case "$PM" in
			pacman) install_packages docker docker-compose docker-buildx ;;
			zypper) install_packages docker docker-compose docker-buildx ;;
			apk) install_packages docker docker-cli-compose docker-cli-buildx ;;
			*) die "install Docker Engine $DOCKER_MIN or later with its Compose plugin (https://docs.docker.com/engine/install/), then run this again." ;;
			esac
			;;
		esac
		;;
	esac
}

step "Docker"
if ! command -v docker >/dev/null 2>&1; then
	[ "$INSTALL_DOCKER" = yes ] || die "Docker isn't installed, and --no-docker-install says not to install it."
	confirm "Docker isn't installed. Install it now?" || die "Authway Server needs Docker."
	install_docker
fi
case "$(command -v docker)" in
/snap/*) warn "this Docker is the snap one, which can't use every folder: Docker of docker.com works better" ;;
esac
docker info >/dev/null 2>&1 || start_docker
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null | sed 's/[^0-9.].*//')
version_at_least "$docker_version" "$DOCKER_MIN" ||
	die "this host has Docker $docker_version, and Authway Server needs $DOCKER_MIN or later. Update Docker
       (https://docs.docker.com/engine/install/), then run this again."
docker compose version >/dev/null 2>&1 ||
	die "Docker has no Compose plugin: install docker-compose-plugin, then run this again."
compose_version=$(docker compose version --short | sed 's/^v//')
version_at_least "$compose_version" "$COMPOSE_MIN" ||
	die "this host has Docker Compose $compose_version, and Authway Server needs $COMPOSE_MIN or later."
if [ -z "$IMAGE" ] && ! docker buildx version >/dev/null 2>&1; then
	die "Docker has no Buildx plugin, which builds the image: install docker-buildx-plugin, or use --image."
fi
info "Docker $docker_version, Compose $compose_version"

# ---- the source ------------------------------------------------------------------------------------------------

step "The source"
current=$(running_dir)
if [ -n "$current" ]; then
	if [ "$DIR_GIVEN" = no ]; then
		DIR=$current
	elif [ "$current" != "$DIR" ]; then
		die "Authway Server already runs from $current: upgrade it there with --dir $current, or remove it first
       (./install.sh --uninstall --dir $current)."
	fi
fi
case "$DIR" in
/*) ;;
*) die "--dir needs an absolute path" ;;
esac
case "$DIR" in
/ | /bin | /boot | /dev | /etc | /home | /lib | /proc | /root | /run | /sbin | /sys | /tmp | /usr | /var)
	die "$DIR can't be the install folder: choose a folder of its own, /opt/authway-server say"
	;;
esac

SRC=""
case "$0" in
*/*) script_dir=$(cd "$(dirname "$0")" && pwd) ;;
*) script_dir="" ;;
esac
if [ -n "$script_dir" ] && [ -f "$script_dir/Dockerfile" ] && [ -f "$script_dir/compose.yaml" ] &&
	[ -d "$script_dir/cmd/authway-server" ]; then
	SRC=$script_dir
elif [ -n "$REPO" ]; then
	info "Getting the source from $REPO"
	if [ -n "$REF" ]; then
		git clone -q --depth 1 --branch "$REF" "$REPO" "$TMP/source"
	else
		git clone -q --depth 1 "$REPO" "$TMP/source"
	fi
	SRC=$TMP/source
else
	die "run this script from a copy of the source of Authway Server, or give --repo https://github.com/phatdo1819/authway-server.git"
fi
[ -f "$SRC/compose.yaml" ] || die "$SRC has no compose.yaml: is it the source of Authway Server?"

UPGRADE=no
[ -f "$DIR/data/authway.db" ] && UPGRADE=yes
# a folder of its own: empty, or one of Authway Server, never the files of something else
if [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ] && ! grep -qs "container_name: authway-server" "$DIR/compose.yaml"; then
	die "$DIR isn't empty and holds no Authway Server: choose another folder with --dir"
fi
mkdir -p "$DIR"
if [ "$(cd "$SRC" && pwd -P)" != "$(cd "$DIR" && pwd -P)" ]; then
	# what the new source has replaces what was there, so no file of an older version stays behind. The data, the
	# settings and the overrides of this host stay
	for entry in "$SRC"/* "$SRC"/.[!.]*; do
		[ -e "$entry" ] || continue
		name=$(basename "$entry")
		case "$name" in
		.git | data | .env | compose.override.yaml) continue ;;
		esac
		rm -rf "${DIR:?}/$name"
	done
	tar -C "$SRC" --exclude=./.git --exclude=./data --exclude=./.env --exclude=./compose.override.yaml \
		--exclude=./web/node_modules --exclude=./internal/admin/ui/dist --exclude='*.exe' -cf - . |
		tar -C "$DIR" --no-same-owner -xf -
	info "Copied to $DIR"
else
	info "Installing in place, in $DIR"
fi
SOURCE_VERSION=$(sed -n 's/^var version = "\(.*\)"/\1/p' "$DIR/cmd/authway-server/main.go")
BUILD_VERSION=""
if commit=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null); then
	BUILD_VERSION="$SOURCE_VERSION+$commit"
fi
info "Version: ${BUILD_VERSION:-$SOURCE_VERSION}"

# ---- the settings ----------------------------------------------------------------------------------------------

ENV_FILE=$DIR/.env
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
get_env() { # key: its value in .env
	sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}
set_env() { # key value: replaces the line of the key, or adds one
	grep -v "^$1=" "$ENV_FILE" >"$TMP/env" || true
	printf '%s=%s\n' "$1" "$2" >>"$TMP/env"
	cat "$TMP/env" >"$ENV_FILE"
}
local_addresses() {
	ip -o address show | awk '{ split($4, a, "/"); print a[1] }'
}

step "Settings, in $ENV_FILE"
detected=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
[ -n "$UI_ADDRESS" ] || UI_ADDRESS=$(get_env AUTHWAY_UI_ADDRESS)
if [ -z "$UI_ADDRESS" ]; then
	UI_ADDRESS=$(ask "Address of this host in the local network, for the web UI" "${detected:-0.0.0.0}")
fi
if [ "$UI_ADDRESS" != 0.0.0.0 ] && ! local_addresses | grep -qx "$UI_ADDRESS"; then
	die "$UI_ADDRESS isn't an address of this host. Its addresses: $(local_addresses | tr '\n' ' ')"
fi
[ "$UI_ADDRESS" != 0.0.0.0 ] || warn "the web UI listens on every address of this host: keep port 8443 closed to the internet"

# an address from DHCP, or a dynamic IPv6 one, can change: the web UI bound to it, the ports forwarded to it and the
# routes of the routers through it then lead nowhere
dynamic_address() { # address: true when the kernel says it's dynamic, a lease that ends
	ip -o address show | awk -v a="$1" '{ split($4, p, "/"); if (p[1] == a) print }' | grep -qw dynamic
}
host_address=$UI_ADDRESS
[ "$host_address" != 0.0.0.0 ] || host_address=$detected
DYNAMIC=no
if [ -n "$host_address" ] && dynamic_address "$host_address"; then
	DYNAMIC=yes
	case $host_address in
	*:*) origin="is a dynamic IPv6 address" ;;
	*) origin="comes from DHCP" ;;
	esac
	warn "$host_address $origin, and can change. Your router forwards the WireGuard ports to it, and sends the tunnels of the routed servers through it."
	if [ "$UI_ADDRESS" != 0.0.0.0 ]; then
		warn "the web UI listens only on $UI_ADDRESS: with another address, Docker can't start Authway Server until AUTHWAY_UI_ADDRESS in $ENV_FILE has the new one."
	fi
	info "Give this host a fixed address first: a DHCP reservation for $host_address on your router, or a static address."
	confirm "Continue with $host_address?" || die "give this host a fixed address, then run the script again"
fi

[ -n "$PUBLIC_HOST" ] || PUBLIC_HOST=$(get_env AUTHWAY_PUBLIC_HOST)
if [ -z "$PUBLIC_HOST" ]; then
	info "The peers connect to the public name or IP of this host, the one your router has on the internet."
	PUBLIC_HOST=$(ask "Public name or IP address" "${detected:-vpn.example.com}")
fi
case "$PUBLIC_HOST" in
*[[:space:]]* | "") die "the public host can't be empty or hold spaces" ;;
esac

[ -n "$TIME_ZONE" ] || TIME_ZONE=$(get_env TZ)
if [ -z "$TIME_ZONE" ]; then
	if command -v timedatectl >/dev/null 2>&1; then
		TIME_ZONE=$(timedatectl show -p Timezone --value 2>/dev/null || true)
	fi
	[ -n "$TIME_ZONE" ] || TIME_ZONE=$(cat /etc/timezone 2>/dev/null || true)
	[ -n "$TIME_ZONE" ] || TIME_ZONE=$(readlink /etc/localtime 2>/dev/null | sed -n 's|.*/zoneinfo/||p')
	[ -n "$TIME_ZONE" ] || TIME_ZONE=UTC
fi

# the compose files: compose.yaml, the override of this host, then the ways of the routed servers
compose_file=$(get_env COMPOSE_FILE)
if [ -z "$HOST_ROUTES" ]; then
	case ":$compose_file:" in
	*:compose.host-routes.yaml:*) HOST_ROUTES=yes ;;
	*) HOST_ROUTES=no ;;
	esac
fi
files=compose.yaml
[ ! -f "$DIR/compose.override.yaml" ] || files="$files:compose.override.yaml"
case ":$compose_file:" in
*:compose.macvlan.yaml:*)
	files="$files:compose.macvlan.yaml"
	[ "$HOST_ROUTES" = no ] || { warn "the container is on macvlan: the routes through the Docker host aren't needed"; HOST_ROUTES=no; }
	;;
esac
[ "$HOST_ROUTES" = no ] || files="$files:compose.host-routes.yaml"

set_env AUTHWAY_PUBLIC_HOST "$PUBLIC_HOST"
set_env AUTHWAY_UI_ADDRESS "$UI_ADDRESS"
set_env TZ "$TIME_ZONE"
set_env COMPOSE_FILE "$files"
info "Public host: $PUBLIC_HOST"
info "Web UI: $UI_ADDRESS"
info "Time zone: $TIME_ZONE"
info "Routed servers through the Docker host: $HOST_ROUTES"

# ---- the image -------------------------------------------------------------------------------------------------

if [ -n "$IMAGE" ]; then
	step "Pulling $IMAGE"
	docker pull "$IMAGE"
	docker tag "$IMAGE" authway-server:latest
else
	step "Building the image: a few minutes the first time"
	docker build -t authway-server:latest --build-arg VERSION="$BUILD_VERSION" "$DIR"
fi

# ---- start -----------------------------------------------------------------------------------------------------

if [ "$UPGRADE" = yes ]; then
	step "Copying the database before the upgrade"
	(cd "$DIR" && docker compose stop >/dev/null 2>&1) || true
	copy=$DIR/data/pre-upgrade-$(date +%Y%m%d-%H%M%S)
	mkdir -p "$copy"
	cp -p "$DIR"/data/authway.db* "$copy"/
	chmod 700 "$copy"
	info "In $copy"
	# the newest 5 copies stay: their names sort by date, the oldest first
	set -- "$DIR"/data/pre-upgrade-*
	while [ $# -gt 5 ]; do
		rm -rf "$1"
		shift
	done
fi

step "Starting Authway Server"
(cd "$DIR" && docker compose up -d --no-build --remove-orphans)
status=""
for _ in $(seq 1 60); do
	status=$(docker inspect -f '{{.State.Health.Status}}' authway-server 2>/dev/null || true)
	[ "$status" = healthy ] && break
	sleep 2
done
if [ "$status" != healthy ]; then
	(cd "$DIR" && docker compose logs --tail 40 authway-server) >&2 || true
	die "Authway Server isn't healthy after 2 minutes ($status): see its log above"
fi
info "${GREEN}Healthy${RESET}: $(docker logs authway-server 2>&1 | sed -n 's/.*msg=starting version=//p' | tail -1)"
if [ "$HOST_ROUTES" = yes ]; then
	sleep 3
	if docker exec authway-host-routes authway-server host-routes -health >/dev/null 2>&1; then
		info "The helper of the Docker host works"
	else
		warn "the helper of the Docker host doesn't answer yet: docker logs authway-host-routes"
	fi
fi

# ---- what next -------------------------------------------------------------------------------------------------

web_host=$UI_ADDRESS
[ "$web_host" != 0.0.0.0 ] || web_host=${detected:-<this host>}
lan_address=${detected:-<the address of this host>}

step "Done"
if [ "$UPGRADE" = no ]; then
	user=$(docker logs authway-server 2>&1 | sed -n 's/^  First administrator of the web UI: //p' | tail -1)
	password=$(docker logs authway-server 2>&1 | sed -n 's/^  Password: //p' | tail -1)
	if [ -n "$password" ]; then
		info "First administrator: ${BOLD}$user${RESET}"
		info "Password:            ${BOLD}$password${RESET}   (the web UI asks for a new one at the first login)"
		info ""
	fi
fi
info "Web UI:   ${BOLD}https://$web_host:8443${RESET}   (accept the self-signed certificate)"
info "Folder:   $DIR   (settings in .env, data in data/)"
info ""
if [ "$DYNAMIC" = yes ]; then
	warn "$host_address can change: give this host a fixed address, a DHCP reservation on your router for example."
	info ""
fi
info "Next:"
info "  1. On your router, forward UDP ports 51820 to 51829 (one per WireGuard server, 51820 for the first)"
info "     to $lan_address. Never forward 8443: the web UI is for the local network."
info "  2. In the web UI: your account and its authenticator, the users, then a WireGuard server and its peers."
info "     docs/first-steps.md walks through it."
if [ "$HOST_ROUTES" = yes ]; then
	info "  3. For a routed server, add on the router of its networks the route that the server shows:"
	info "     <its tunnel network> via $lan_address."
fi
info ""
info "Log:        cd $DIR && docker compose logs -f authway-server"
info "Upgrade:    run this script again from a newer source"
info "Uninstall:  ./install.sh --uninstall"
