#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "netns-test.sh must run as root" >&2
  exit 1
fi

for command in ip nft python3 readlink sysctl conntrack jq; do
  command -v "${command}" >/dev/null || {
    echo "missing required command: ${command}" >&2
    exit 1
  }
done

agent_bin=${FLUX_AGENT_BIN:-"$(pwd)/bin/flux-agent"}
if [[ ! -x ${agent_bin} ]]; then
  echo "build the Linux agent first or set FLUX_AGENT_BIN" >&2
  exit 1
fi
agent_bin=$(readlink -f "${agent_bin}")

suffix=$$
client_ns="flux-client-${suffix}"
ingress_ns="flux-ingress-${suffix}"
target_ns="flux-target-${suffix}"
work_dir=$(mktemp -d)
tcp_server_pid=
udp_server_pid=
held_client_pid=

cleanup() {
  set +e
  [[ -n ${held_client_pid} ]] && kill "${held_client_pid}" 2>/dev/null
  [[ -n ${tcp_server_pid} ]] && kill "${tcp_server_pid}" 2>/dev/null
  [[ -n ${udp_server_pid} ]] && kill "${udp_server_pid}" 2>/dev/null
  ip netns del "${client_ns}" 2>/dev/null
  ip netns del "${ingress_ns}" 2>/dev/null
  ip netns del "${target_ns}" 2>/dev/null
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

ip netns add "${client_ns}"
ip netns add "${ingress_ns}"
ip netns add "${target_ns}"
client_root_if="fc${suffix}"
ingress_client_root_if="fic${suffix}"
ingress_target_root_if="fit${suffix}"
target_root_if="ft${suffix}"
ip link add "${client_root_if}" type veth peer name "${ingress_client_root_if}"
ip link add "${ingress_target_root_if}" type veth peer name "${target_root_if}"
ip link set "${client_root_if}" netns "${client_ns}"
ip link set "${ingress_client_root_if}" netns "${ingress_ns}"
ip link set "${ingress_target_root_if}" netns "${ingress_ns}"
ip link set "${target_root_if}" netns "${target_ns}"
ip -n "${client_ns}" link set "${client_root_if}" name flux-ci
ip -n "${ingress_ns}" link set "${ingress_client_root_if}" name flux-ic
ip -n "${ingress_ns}" link set "${ingress_target_root_if}" name flux-it
ip -n "${target_ns}" link set "${target_root_if}" name flux-ti

ip -n "${client_ns}" address add 10.40.0.2/24 dev flux-ci
ip -n "${ingress_ns}" address add 10.40.0.1/24 dev flux-ic
ip -n "${ingress_ns}" address add 10.41.0.1/24 dev flux-it
ip -n "${target_ns}" address add 10.41.0.2/24 dev flux-ti
for namespace in "${client_ns}" "${ingress_ns}" "${target_ns}"; do
  ip -n "${namespace}" link set lo up
done
ip -n "${client_ns}" link set flux-ci up
ip -n "${ingress_ns}" link set flux-ic up
ip -n "${ingress_ns}" link set flux-it up
ip -n "${target_ns}" link set flux-ti up
ip -n "${client_ns}" route add default via 10.40.0.1
ip -n "${target_ns}" route add default via 10.41.0.1
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null

ip netns exec "${target_ns}" python3 -u -c '
import socket, threading
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.41.0.2", 8080))
server.listen()
def serve(conn, peer):
    with conn:
        while True:
            try:
                data = conn.recv(1024)
            except socket.timeout:
                return
            if not data:
                return
            conn.sendall(peer[0].encode())
while True:
    conn, peer = server.accept()
    conn.settimeout(5)
    threading.Thread(target=serve, args=(conn, peer), daemon=True).start()
' >"${work_dir}/tcp-server.log" 2>&1 &
tcp_server_pid=$!

ip netns exec "${target_ns}" python3 -u -c '
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("10.41.0.2", 8080))
while True:
    data, peer = server.recvfrom(2048)
    server.sendto(peer[0].encode(), peer)
' >"${work_dir}/udp-server.log" 2>&1 &
udp_server_pid=$!

write_state() {
  local generation=$1
  local lifecycle=$2
  local drain_deadline=${3:-}
  local drain_json=
  if [[ -n ${drain_deadline} ]]; then
    printf -v drain_json ',\n    "drain_deadline": "%s"' "${drain_deadline}"
  fi
  cat >"${work_dir}/desired.json" <<JSON
{
  "schema_version": 2,
  "node_id": "node-a",
  "generation": ${generation},
  "forwards": [{
    "id": "netns-forward",
    "user_id": "netns-user",
    "protocols": ["tcp", "udp"],
    "ingress_node_id": "node-a",
    "listen": {"address": "10.40.0.1", "port": 18080},
    "target": {"address": "10.41.0.2", "port": 8080},
    "path_mode": "direct",
    "snat": {"mode": "masquerade"},
    "lifecycle": "${lifecycle}"${drain_json},
    "resource_version": ${generation}
  }]
}
JSON
}

apply_state() {
  local output=${1:-/dev/null}
  ip netns exec "${ingress_ns}" "${agent_bin}" apply \
    --file "${work_dir}/desired.json" \
    --state-dir "${work_dir}/state" \
    --nft nft >"${output}"
}

sleep 0.2
write_state 1 active
apply_state

tcp_source=$(ip netns exec "${client_ns}" python3 -c '
import socket
s = socket.create_connection(("10.40.0.1", 18080), timeout=2)
s.sendall(b"ping")
print(s.recv(128).decode())
')
[[ ${tcp_source} == "10.41.0.1" ]] || {
  echo "unexpected TCP source observed by target: ${tcp_source}" >&2
  exit 1
}

udp_source=$(ip netns exec "${client_ns}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"ping", ("10.40.0.1", 18080))
print(s.recv(128).decode())
')
[[ ${udp_source} == "10.41.0.1" ]] || {
  echo "unexpected UDP source observed by target: ${udp_source}" >&2
  exit 1
}

ip netns exec "${client_ns}" env \
  READY_FILE="${work_dir}/held-ready" \
  CONTINUE_FILE="${work_dir}/held-continue" \
  BLOCKED_FILE="${work_dir}/held-blocked" \
  python3 -u -c '
import os, socket, time
s = socket.create_connection(("10.40.0.1", 18080), timeout=2)
s.sendall(b"before-pause")
if not s.recv(128):
    raise SystemExit("initial response missing")
open(os.environ["READY_FILE"], "w").close()
while not os.path.exists(os.environ["CONTINUE_FILE"]):
    time.sleep(0.02)
s.settimeout(1)
try:
    s.sendall(b"after-pause")
    s.recv(128)
except (TimeoutError, socket.timeout, OSError):
    open(os.environ["BLOCKED_FILE"], "w").close()
    raise SystemExit(0)
raise SystemExit("paused existing connection still passed traffic")
' >"${work_dir}/held-client.log" 2>&1 &
held_client_pid=$!

for _ in $(seq 1 100); do
  [[ -e ${work_dir}/held-ready ]] && break
  sleep 0.02
done
[[ -e ${work_dir}/held-ready ]] || {
  echo "held TCP connection did not become ready" >&2
  exit 1
}

write_state 2 paused
apply_state
touch "${work_dir}/held-continue"
wait "${held_client_pid}"
held_client_pid=
[[ -e ${work_dir}/held-blocked ]] || {
  echo "Pause failed to block an existing TCP connection" >&2
  exit 1
}

write_state 3 active
apply_state
ip netns exec "${client_ns}" python3 -c '
import socket
s = socket.create_connection(("10.40.0.1", 18080), timeout=2)
s.sendall(b"resumed")
assert s.recv(128) == b"10.41.0.1"
'

ip netns exec "${client_ns}" env \
  READY_FILE="${work_dir}/drain-ready" \
  DRAIN_CONTINUE_FILE="${work_dir}/drain-continue" \
  DRAIN_PASSED_FILE="${work_dir}/drain-passed" \
  FORCE_CONTINUE_FILE="${work_dir}/force-continue" \
  FORCE_BLOCKED_FILE="${work_dir}/force-blocked" \
  python3 -u -c '
import os, socket, time
s = socket.create_connection(("10.40.0.1", 18080), timeout=2)
s.sendall(b"before-drain")
if s.recv(128) != b"10.41.0.1":
    raise SystemExit("initial drain response missing")
open(os.environ["READY_FILE"], "w").close()
while not os.path.exists(os.environ["DRAIN_CONTINUE_FILE"]):
    time.sleep(0.02)
s.sendall(b"during-drain")
if s.recv(128) != b"10.41.0.1":
    raise SystemExit("existing connection did not survive drain")
open(os.environ["DRAIN_PASSED_FILE"], "w").close()
while not os.path.exists(os.environ["FORCE_CONTINUE_FILE"]):
    time.sleep(0.02)
s.settimeout(1)
try:
    s.sendall(b"after-force")
    if not s.recv(128):
        raise ConnectionError("connection closed")
except (ConnectionError, TimeoutError, socket.timeout, OSError):
    open(os.environ["FORCE_BLOCKED_FILE"], "w").close()
    raise SystemExit(0)
raise SystemExit("force-deleted existing connection still passed traffic")
' >"${work_dir}/drain-client.log" 2>&1 &
held_client_pid=$!

for _ in $(seq 1 100); do
  [[ -e ${work_dir}/drain-ready ]] && break
  sleep 0.02
done
[[ -e ${work_dir}/drain-ready ]] || {
  echo "drain TCP connection did not become ready" >&2
  exit 1
}

drain_deadline=$(date -u -d '+60 seconds' '+%Y-%m-%dT%H:%M:%SZ')
write_state 4 draining "${drain_deadline}"
apply_state
if ip netns exec "${client_ns}" python3 -c '
import socket
s = socket.create_connection(("10.40.0.1", 18080), timeout=1)
' 2>/dev/null; then
  echo "draining listener accepted a new TCP connection" >&2
  exit 1
fi
touch "${work_dir}/drain-continue"
for _ in $(seq 1 100); do
  [[ -e ${work_dir}/drain-passed ]] && break
  sleep 0.02
done
[[ -e ${work_dir}/drain-passed ]] || {
  echo "existing TCP connection did not survive Drain" >&2
  exit 1
}

write_state 5 force_deleting
apply_state "${work_dir}/force-result.json"
jq -e '.conntrack_deleted >= 1' "${work_dir}/force-result.json" >/dev/null || {
  echo "Force did not report conntrack cleanup: $(cat "${work_dir}/force-result.json")" >&2
  exit 1
}
touch "${work_dir}/force-continue"
wait "${held_client_pid}"
held_client_pid=
[[ -e ${work_dir}/force-blocked ]] || {
  echo "Force failed to block an existing TCP connection" >&2
  exit 1
}

cat >"${work_dir}/desired.json" <<JSON
{"schema_version":2,"node_id":"node-a","generation":6,"forwards":[]}
JSON
apply_state
if ip netns exec "${client_ns}" python3 -c '
import socket
s = socket.create_connection(("10.40.0.1", 18080), timeout=1)
' 2>/dev/null; then
  echo "deleted listener still accepted a TCP connection" >&2
  exit 1
fi

ip netns exec "${ingress_ns}" nft -j list table inet flux >/dev/null
echo "netns TCP/UDP/Pause/Resume/Drain/Force/Delete checks passed"
