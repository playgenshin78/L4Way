#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "protocol-block-netns-test.sh must run as root" >&2
  exit 1
fi

for command in ip nft python3 readlink sysctl; do
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
client_ns="flux-proto-client-${suffix}"
ingress_ns="flux-proto-ingress-${suffix}"
target_ns="flux-proto-target-${suffix}"
work_dir=$(mktemp -d)
server_pid=

cleanup() {
  set +e
  [[ -n ${server_pid} ]] && kill "${server_pid}" 2>/dev/null
  ip netns del "${client_ns}" 2>/dev/null
  ip netns del "${ingress_ns}" 2>/dev/null
  ip netns del "${target_ns}" 2>/dev/null
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

ip netns add "${client_ns}"
ip netns add "${ingress_ns}"
ip netns add "${target_ns}"
ip link add "pc${suffix}" type veth peer name "pi${suffix}"
ip link add "pt${suffix}" type veth peer name "tp${suffix}"
ip link set "pc${suffix}" netns "${client_ns}"
ip link set "pi${suffix}" netns "${ingress_ns}"
ip link set "pt${suffix}" netns "${ingress_ns}"
ip link set "tp${suffix}" netns "${target_ns}"
ip -n "${client_ns}" link set "pc${suffix}" name flux-pc
ip -n "${ingress_ns}" link set "pi${suffix}" name flux-pi
ip -n "${ingress_ns}" link set "pt${suffix}" name flux-pt
ip -n "${target_ns}" link set "tp${suffix}" name flux-tp

ip -n "${client_ns}" address add 10.80.0.2/24 dev flux-pc
ip -n "${ingress_ns}" address add 10.80.0.1/24 dev flux-pi
ip -n "${ingress_ns}" address add 10.81.0.1/24 dev flux-pt
ip -n "${target_ns}" address add 10.81.0.2/24 dev flux-tp
for namespace in "${client_ns}" "${ingress_ns}" "${target_ns}"; do
  ip -n "${namespace}" link set lo up
done
ip -n "${client_ns}" link set flux-pc up
ip -n "${ingress_ns}" link set flux-pi up
ip -n "${ingress_ns}" link set flux-pt up
ip -n "${target_ns}" link set flux-tp up
ip -n "${client_ns}" route add default via 10.80.0.1
ip -n "${target_ns}" route add default via 10.81.0.1
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null

ip netns exec "${target_ns}" python3 -u -c '
import socket, threading
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.81.0.2", 8080))
server.listen()
def serve(conn):
    with conn:
        data = conn.recv(4096)
        if data:
            conn.sendall(data)
while True:
    conn, _ = server.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
' >"${work_dir}/server.log" 2>&1 &
server_pid=$!

write_state() {
  local generation=$1
  local http=$2
  local https=$3
  local socks=$4
  local tls=$5
  cat >"${work_dir}/desired.json" <<JSON
{
  "schema_version": 5,
  "node_id": "node-a",
  "generation": ${generation},
  "protocol_blocks": {"http": ${http}, "https": ${https}, "socks": ${socks}, "tls": ${tls}},
  "forwards": [{
    "id": "protocol-test",
    "user_id": "owner",
    "protocols": ["tcp"],
    "ingress_node_id": "node-a",
    "listen": {"address": "10.80.0.1", "port": 18080},
    "target": {"address": "10.81.0.2", "port": 8080},
    "path_mode": "direct",
    "snat": {"mode": "masquerade"},
    "lifecycle": "active",
    "resource_version": ${generation}
  }]
}
JSON
}

apply_state() {
  ip netns exec "${ingress_ns}" "${agent_bin}" apply \
    --file "${work_dir}/desired.json" \
    --state-dir "${work_dir}/state" \
    --nft nft >/dev/null
}

probe() {
  local name=$1
  local payload_hex=$2
  local expected=$3
  local result=blocked
  if ip netns exec "${client_ns}" env PAYLOAD_HEX="${payload_hex}" python3 -c '
import os, socket
payload = bytes.fromhex(os.environ["PAYLOAD_HEX"])
s = socket.create_connection(("10.80.0.1", 18080), timeout=1)
s.settimeout(1)
s.sendall(payload)
if s.recv(len(payload)) != payload:
    raise SystemExit(2)
' 2>/dev/null; then
    result=allowed
  fi
  if [[ ${result} != "${expected}" ]]; then
    echo "${name}: got ${result}, want ${expected}" >&2
    exit 1
  fi
  printf '%-24s %s\n' "${name}" "${result}"
}

random_aes="8fb2135789acd04176e29b5c330fd8a451ee70926d4bb8610ca3f71495e67d20"
http_get="474554202f20485454502f312e310d0a486f73743a20746573740d0a0d0a"
https_connect="434f4e4e454354206578616d706c652e636f6d3a34343320485454502f312e310d0a0d0a"
tls_generic="160303001001000000000000000000000000000000"
tls_http_alpn="16030300200100000000000008687474702f312e3100000000000000000000000000000000"
socks5="050100"
socks4="040100500a51000200"

sleep 0.2
write_state 1 false false false false
apply_state
probe "baseline HTTP" "${http_get}" allowed

write_state 2 true false false false
apply_state
probe "HTTP" "${http_get}" blocked
probe "AES with HTTP block" "${random_aes}" allowed

write_state 3 false true false false
apply_state
probe "HTTPS CONNECT" "${https_connect}" blocked
probe "HTTPS ALPN" "${tls_http_alpn}" blocked
probe "non-HTTP TLS" "${tls_generic}" allowed
probe "AES with HTTPS block" "${random_aes}" allowed

write_state 4 false false true false
apply_state
probe "SOCKS4" "${socks4}" blocked
probe "SOCKS5" "${socks5}" blocked
probe "AES with SOCKS block" "${random_aes}" allowed

write_state 5 false false false true
apply_state
probe "TLS" "${tls_generic}" blocked
probe "AES with TLS block" "${random_aes}" allowed

echo "protocol block netns checks passed"
