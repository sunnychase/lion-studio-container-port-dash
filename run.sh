#!/bin/bash
# Created by Sunny Chase (https://github.com/sunnychase) in collaboration with Claude (Anthropic) · Lion Studio - Container Port Dash
# run.sh -- build the image and start Container Port Dash for the account that runs this script.
#   ./run.sh                     page on port 8660, Kill checks this account's login password
#   NAME=container-port-dash PORT=8660 DATA=~/container-port-dash-data ./run.sh
# Why each flag (see SECURITY.md): --network host and --pid host to see this machine's sockets and processes; --cgroupns host
# so `ss` names the service or container that owns each socket; the user D-Bus for systemd --user; the Docker socket to name
# and stop containers (this gives the container control of Docker: keep the page on a trusted network); the host's
# /etc/passwd (read only) to name accounts. It runs as your user, read-only, with every capability dropped.
set -eu
cd "$(dirname "$(readlink -f "$0")")"
NAME=${NAME:-container-port-dash}
PORT=${PORT:-8660}
DATA=${DATA:-$HOME/container-port-dash-data}
IMAGE=${IMAGE:-lion/container-port-dash:2}
U=$(id -u); G=$(id -g)
mkdir -p "$DATA" && chmod 700 "$DATA"
[ -s "$DATA/token" ] || { python3 -c "import secrets; print(secrets.token_urlsafe(24))" > "$DATA/token"; chmod 600 "$DATA/token"; echo "new panel token in $DATA/token"; }
docker build -q -t "$IMAGE" .
DOCKER_GID=$(stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  --network host --pid host --cgroupns host --user "$U:$G" ${DOCKER_GID:+--group-add $DOCKER_GID} \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --security-opt apparmor=unconfined \
  -v /run/user/$U:/run/user/$U -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$U/bus -e XDG_RUNTIME_DIR=/run/user/$U \
  ${DOCKER_GID:+-v /var/run/docker.sock:/var/run/docker.sock} -v /etc/passwd:/host/passwd:ro -v "$DATA:/data" \
  -e PORTS_PORT="$PORT" -e PORTS_LOGIN="$(id -un)" ${PORTS_LAN:+-e PORTS_LAN=$PORTS_LAN} \
  "$IMAGE" >/dev/null
echo "Container Port Dash: http://$(hostname -I | awk '{print $1}'):$PORT"
