#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "tc-netns-test.sh must run as root" >&2
  exit 1
fi

for command in ip nft tc iperf3 jq modprobe readlink; do
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
duration=${FLUX_TC_DURATION_SECONDS:-8}
if [[ ! ${duration} =~ ^[1-9][0-9]*$ ]]; then
  echo "FLUX_TC_DURATION_SECONDS must be a positive integer" >&2
  exit 1
fi

suffix=$$
client_ns="flux-tc-client-${suffix}"
ingress_ns="flux-tc-ingress-${suffix}"
target_ns="flux-tc-target-${suffix}"
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

modprobe ifb
ip netns add "${client_ns}"
ip netns add "${ingress_ns}"
ip netns add "${target_ns}"
client_if="tc${suffix}"
ingress_public_if="tp${suffix}"
ingress_target_if="tt${suffix}"
target_if="tx${suffix}"
ip link add "${client_if}" type veth peer name "${ingress_public_if}"
ip link add "${ingress_target_if}" type veth peer name "${target_if}"
ip link set "${client_if}" netns "${client_ns}"
ip link set "${ingress_public_if}" netns "${ingress_ns}"
ip link set "${ingress_target_if}" netns "${ingress_ns}"
ip link set "${target_if}" netns "${target_ns}"
ip -n "${client_ns}" link set "${client_if}" name flux-client
ip -n "${ingress_ns}" link set "${ingress_public_if}" name flux-public
ip -n "${ingress_ns}" link set "${ingress_target_if}" name flux-target
ip -n "${target_ns}" link set "${target_if}" name flux-server

ip -n "${client_ns}" address add 10.70.0.2/24 dev flux-client
ip -n "${ingress_ns}" address add 10.70.0.1/24 dev flux-public
ip -n "${ingress_ns}" address add 10.71.0.1/24 dev flux-target
ip -n "${target_ns}" address add 10.71.0.2/24 dev flux-server
for namespace in "${client_ns}" "${ingress_ns}" "${target_ns}"; do
  ip -n "${namespace}" link set lo up
done
ip -n "${client_ns}" link set flux-client up
ip -n "${ingress_ns}" link set flux-public up
ip -n "${ingress_ns}" link set flux-target up
ip -n "${target_ns}" link set flux-server up
ip -n "${client_ns}" route add default via 10.70.0.1
ip -n "${target_ns}" route add default via 10.71.0.1
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "${ingress_ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null

ip netns exec "${target_ns}" iperf3 -s >"${work_dir}/iperf-server.log" 2>&1 &
server_pid=$!
sleep 0.5

cat >"${work_dir}/desired.json" <<JSON
{
  "schema_version": 2,
  "node_id": "node-tc",
  "generation": 1,
  "forwards": [{
    "id": "tc-forward",
    "user_id": "tc-user",
    "protocols": ["tcp", "udp"],
    "ingress_node_id": "node-tc",
    "listen": {"address": "10.70.0.1", "port": 18081},
    "target": {"address": "10.71.0.2", "port": 5201},
    "path_mode": "direct",
    "snat": {"mode": "masquerade"},
    "rate_limit": {
      "ingress_bits_per_second": 2000000,
      "egress_bits_per_second": 3000000,
      "burst_bytes": 32768
    },
    "traffic_class_id": 10,
    "lifecycle": "active",
    "resource_version": 1
  }]
}
JSON

apply_state() {
  ip netns exec "${ingress_ns}" "${agent_bin}" apply \
    --file "${work_dir}/desired.json" \
    --state-dir "${work_dir}/state" \
    --nft nft --tc tc --ip ip \
    --public-interface flux-public \
    --ifb-interface flux-ifb0 \
    --upload-link-bps 100000000 \
    --download-link-bps 100000000 \
    --allow-tc-root-replace >/dev/null
}

apply_state
ip netns exec "${ingress_ns}" tc class show dev flux-public | grep -Eq '^class [^ ]+ 1:a( |$)'
ip netns exec "${ingress_ns}" tc class show dev flux-ifb0 | grep -Eq '^class [^ ]+ 1:a( |$)'

ip netns exec "${client_ns}" iperf3 -c 10.70.0.1 -p 18081 -t "${duration}" -J >"${work_dir}/tcp-upload.json"
ip netns exec "${client_ns}" iperf3 -c 10.70.0.1 -p 18081 -t "${duration}" -R -J >"${work_dir}/tcp-download.json"
ip netns exec "${client_ns}" iperf3 -c 10.70.0.1 -p 18081 -u -b 10000000 -t "${duration}" -J >"${work_dir}/udp-upload.json"

tcp_upload=$(jq -r '.end.sum_received.bits_per_second // .end.sum.bits_per_second' "${work_dir}/tcp-upload.json")
tcp_download=$(jq -r '.end.sum_received.bits_per_second // .end.sum.bits_per_second' "${work_dir}/tcp-download.json")
udp_upload=$(jq -r '
  .end.sum as $sum
  | if ($sum.packets // 0) > 0
    then $sum.bits_per_second * (($sum.packets - ($sum.lost_packets // 0)) / $sum.packets)
    else 0
    end
' "${work_dir}/udp-upload.json")

printf 'measured: duration_seconds=%s tcp_upload_bps=%.0f tcp_download_bps=%.0f udp_upload_bps=%.0f\n' \
  "${duration}" "${tcp_upload}" "${tcp_download}" "${udp_upload}"
if ! awk -v value="${udp_upload}" 'BEGIN { exit !(value > 3200000) }'; then
  :
else
  echo 'iperf3 UDP end summary:' >&2
  jq '.end' "${work_dir}/udp-upload.json" >&2
  echo 'flux-public tc statistics:' >&2
  ip netns exec "${ingress_ns}" tc -s class show dev flux-public >&2
  echo 'flux-ifb0 tc statistics:' >&2
  ip netns exec "${ingress_ns}" tc -s class show dev flux-ifb0 >&2
  echo 'flux-public ingress filters:' >&2
  ip netns exec "${ingress_ns}" tc -s filter show dev flux-public ingress >&2
  echo 'flux-ifb0 class filters:' >&2
  ip netns exec "${ingress_ns}" tc -s filter show dev flux-ifb0 parent 1: >&2
fi

within_range() {
  awk -v value="$1" -v minimum="$2" -v maximum="$3" 'BEGIN { exit !(value >= minimum && value <= maximum) }'
}
within_range "${tcp_upload}" 1200000 3200000 || { echo "TCP upload rate out of range: ${tcp_upload}" >&2; exit 1; }
within_range "${tcp_download}" 1800000 4800000 || { echo "TCP download rate out of range: ${tcp_download}" >&2; exit 1; }
within_range "${udp_upload}" 1000000 3200000 || { echo "UDP upload rate out of range: ${udp_upload}" >&2; exit 1; }

cat >"${work_dir}/desired.json" <<JSON
{"schema_version":2,"node_id":"node-tc","generation":2,"forwards":[]}
JSON
apply_state
if ip netns exec "${ingress_ns}" tc qdisc show dev flux-public | grep -Eq 'htb|clsact'; then
  echo "public tc state remained after policy deletion" >&2
  exit 1
fi
if ip netns exec "${ingress_ns}" tc qdisc show dev flux-ifb0 | grep -q htb; then
  echo "IFB tc state remained after policy deletion" >&2
  exit 1
fi

printf 'tc netns checks passed: duration_seconds=%s tcp_upload_bps=%.0f tcp_download_bps=%.0f udp_upload_bps=%.0f\n' \
  "${duration}" "${tcp_upload}" "${tcp_download}" "${udp_upload}"
