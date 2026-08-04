#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROGRAM_NAME="Flux 一键安装器"
TEMP_DIR=""
COMMITTED=0
ROLLBACK_PATHS=()
ROLLBACK_EXISTED=()
SERVICE_WAS_ACTIVE=""
SERVICE_WAS_ENABLED=""
SERVICE_NAME=""
IP_FORWARD_PREVIOUS=""
CONTROLLER_USER_CREATED=0

MODE=""
RELEASE_URL="${FLUX_RELEASE_URL:-}"
CHECKSUM_URL="${FLUX_CHECKSUM_URL:-}"
ARCHIVE_PATH=""
CHECKSUM_FILE=""
SKIP_PACKAGES=0
NON_INTERACTIVE=0
PURGE=0
ASSUME_YES=0

BUNDLE_BASE64=""
ENABLE_FABRIC=0
PUBLIC_INTERFACE=""
ALLOW_TC_ROOT_REPLACE=0

PUBLIC_HOST=""
OWNER_USERNAME="owner"
OWNER_DISPLAY_NAME="Owner"
OWNER_PASSWORD_FILE=""
PLAN_ID="default"
INITIAL_NODE_ID="node-a"
INITIAL_NODE_IP=""
COOKIE_SECURE="false"
NODE_INSTALLER_URL="${FLUX_NODE_INSTALLER_URL:-}"
NODE_RELEASE_URL="${FLUX_NODE_RELEASE_URL:-}"

log() {
  printf '[flux] %s\n' "$*"
}

warn() {
  printf '[flux] 警告：%s\n' "$*" >&2
}

die() {
  printf '[flux] 错误：%s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Flux 一键安装器

用法：
  sudo bash install.sh controller [选项]
  sudo bash install.sh agent [选项]
  bash install.sh verify [选项]
  bash install.sh doctor
  sudo bash install.sh uninstall --component controller|agent [--purge --yes]

通用选项：
  --release-url URL       发行包直链；同时下载 URL.sha256 校验
  --checksum-url URL      自定义发行包校验文件地址
  --archive PATH          使用本地发行包
  --checksum-file PATH    本地发行包的 SHA-256 校验文件
  --skip-packages         不自动安装系统依赖
  --non-interactive       禁止交互，缺少必填项时直接失败

Controller 选项：
  --public-host HOST      Agent 可访问的 Controller 域名或 IPv4
  --owner-username NAME   管理员账号，默认 owner
  --owner-display-name N  管理员显示名称，默认 Owner
  --owner-password-file P 初始密码文件；留空时安全生成并只显示一次
  --plan-id ID            配置名称，默认 default
  --initial-node-id ID    第一台节点名称，默认 node-a
  --initial-node-ip IPv4  第一台节点监听地址
  --cookie-secure BOOL    浏览器 Cookie 是否仅允许 HTTPS，默认 false
  --node-installer-url U  面板生成节点命令时下载本脚本的 HTTPS 地址
  --node-release-url U    面板生成节点命令时下载发行包的 HTTPS 地址

Agent 选项：
  --bundle-base64 VALUE   面板生成的一次性接入码；留空时交互粘贴
  --enable-fabric         允许管理 Flux 自有隧道、路由和策略规则
  --public-interface IF   用于带宽整形的公网网卡
  --allow-tc-root-replace 与 --public-interface 同时使用，授权接管 root qdisc
EOF
}

cleanup() {
  if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
    rm -rf -- "${TEMP_DIR}"
  fi
}

restore_changes() {
  local index path backup
  set +e
  for ((index=${#ROLLBACK_PATHS[@]}-1; index>=0; index--)); do
    path="${ROLLBACK_PATHS[index]}"
    backup="${TEMP_DIR}/rollback/${index}"
    rm -rf -- "${path}"
    if [[ "${ROLLBACK_EXISTED[index]}" == "1" ]]; then
      mkdir -p -- "$(dirname "${path}")"
      cp -a -- "${backup}" "${path}"
    fi
  done
  if command -v systemctl >/dev/null 2>&1; then
    if [[ -n "${SERVICE_NAME}" ]]; then
      systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ -n "${SERVICE_NAME}" ]]; then
      if [[ "${SERVICE_WAS_ENABLED}" == "enabled" ]]; then
        systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
      else
        systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
      fi
    fi
    if [[ -n "${SERVICE_NAME}" && "${SERVICE_WAS_ACTIVE}" == "active" ]]; then
      systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${IP_FORWARD_PREVIOUS}" && -w /proc/sys/net/ipv4/ip_forward ]]; then
    sysctl -q -w "net.ipv4.ip_forward=${IP_FORWARD_PREVIOUS}" >/dev/null 2>&1 || true
  fi
  if [[ ${CONTROLLER_USER_CREATED} -eq 1 ]]; then
    userdel flux-controller >/dev/null 2>&1 || warn "未能移除本次创建的 flux-controller 系统用户"
  fi
}

on_exit() {
  local status=$?
  if [[ ${status} -ne 0 && ${COMMITTED} -eq 0 && ${#ROLLBACK_PATHS[@]} -gt 0 ]]; then
    warn "安装未完成，正在恢复原有程序和配置"
    restore_changes
  fi
  cleanup
  exit "${status}"
}
trap on_exit EXIT

backup_path() {
  local path="$1"
  local index="${#ROLLBACK_PATHS[@]}"
  ROLLBACK_PATHS+=("${path}")
  mkdir -p "${TEMP_DIR}/rollback"
  if [[ -e "${path}" || -L "${path}" ]]; then
    cp -a -- "${path}" "${TEMP_DIR}/rollback/${index}"
    ROLLBACK_EXISTED+=("1")
  else
    ROLLBACK_EXISTED+=("0")
  fi
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "此操作需要 root，请在命令前加 sudo"
}

require_linux_systemd() {
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
  command -v systemctl >/dev/null 2>&1 || die "需要使用 systemd 的 Linux 系统"
}

read_tty() {
  local prompt="$1"
  local default_value="${2:-}"
  local value=""
  [[ -r /dev/tty ]] || die "当前没有可交互终端，请补齐参数并使用 --non-interactive"
  if [[ -n "${default_value}" ]]; then
    printf '%s [%s]：' "${prompt}" "${default_value}" >/dev/tty
  else
    printf '%s：' "${prompt}" >/dev/tty
  fi
  IFS= read -r value </dev/tty
  printf '%s' "${value:-${default_value}}"
}

select_mode() {
  if [[ $# -gt 0 ]]; then
    MODE="$1"
    shift
    REMAINING_ARGS=("$@")
    return
  fi
  [[ -r /dev/tty ]] || {
    usage
    exit 2
  }
  cat >/dev/tty <<'EOF'
请选择操作：
  1) 安装或升级 Controller
  2) 安装 Agent
  3) 检查运行环境
  4) 卸载
EOF
  local choice
  printf '输入序号：' >/dev/tty
  IFS= read -r choice </dev/tty
  case "${choice}" in
    1) MODE="controller" ;;
    2) MODE="agent" ;;
    3) MODE="doctor" ;;
    4) MODE="uninstall" ;;
    *) die "无效选项" ;;
  esac
  REMAINING_ARGS=()
}

need_value() {
  [[ $# -ge 2 ]] || die "$1 缺少参数"
  [[ -n "${2:-}" ]] || die "$1 缺少参数"
}

parse_args() {
  local component=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release-url) need_value "$@"; RELEASE_URL="$2"; shift 2 ;;
      --checksum-url) need_value "$@"; CHECKSUM_URL="$2"; shift 2 ;;
      --archive) need_value "$@"; ARCHIVE_PATH="$2"; shift 2 ;;
      --checksum-file) need_value "$@"; CHECKSUM_FILE="$2"; shift 2 ;;
      --skip-packages) SKIP_PACKAGES=1; shift ;;
      --non-interactive) NON_INTERACTIVE=1; shift ;;
      --bundle-base64) need_value "$@"; BUNDLE_BASE64="$2"; shift 2 ;;
      --enable-fabric) ENABLE_FABRIC=1; shift ;;
      --public-interface) need_value "$@"; PUBLIC_INTERFACE="$2"; shift 2 ;;
      --allow-tc-root-replace) ALLOW_TC_ROOT_REPLACE=1; shift ;;
      --public-host) need_value "$@"; PUBLIC_HOST="$2"; shift 2 ;;
      --owner-username) need_value "$@"; OWNER_USERNAME="$2"; shift 2 ;;
      --owner-display-name) need_value "$@"; OWNER_DISPLAY_NAME="$2"; shift 2 ;;
      --owner-password-file) need_value "$@"; OWNER_PASSWORD_FILE="$2"; shift 2 ;;
      --plan-id) need_value "$@"; PLAN_ID="$2"; shift 2 ;;
      --initial-node-id) need_value "$@"; INITIAL_NODE_ID="$2"; shift 2 ;;
      --initial-node-ip) need_value "$@"; INITIAL_NODE_IP="$2"; shift 2 ;;
      --cookie-secure) need_value "$@"; COOKIE_SECURE="$2"; shift 2 ;;
      --node-installer-url) need_value "$@"; NODE_INSTALLER_URL="$2"; shift 2 ;;
      --node-release-url) need_value "$@"; NODE_RELEASE_URL="$2"; shift 2 ;;
      --component) need_value "$@"; component="$2"; shift 2 ;;
      --purge) PURGE=1; shift ;;
      --yes) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "不支持的参数：$1" ;;
    esac
  done
  UNINSTALL_COMPONENT="${component}"
}

validate_https_url() {
  local value="$1"
  [[ "${value}" == https://* ]] || return 1
  [[ "${value}" != *"'"* && "${value}" != *'"'* ]] || return 1
  [[ "${value}" != *"\\"* ]] || return 1
  [[ "${value}" != *"@"* && "${value}" != *"#"* ]] || return 1
  [[ "${value}" != *$'\r'* && "${value}" != *$'\n'* && "${value}" != *$'\t'* && "${value}" != *" "* ]] || return 1
  [[ "${value#https://}" == */* ]] || return 1
  [[ -n "${value#https://}" ]]
}

validate_identifier() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,119}$ ]]
}

validate_hostname() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] && [[ "$1" != *".."* ]]
}

validate_ipv4() {
  local value="$1"
  local part
  local -a parts
  IFS='.' read -r -a parts <<<"${value}"
  [[ ${#parts[@]} -eq 4 ]] || return 1
  for part in "${parts[@]}"; do
    [[ "${part}" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#${part} >= 0 && 10#${part} <= 255)) || return 1
  done
  [[ "${value}" != "0.0.0.0" && "${value}" != "255.255.255.255" ]]
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) die "不支持的 CPU 架构：$(uname -m)" ;;
  esac
}

detect_primary_ipv4() {
  local detected=""
  if command -v ip >/dev/null 2>&1; then
    detected="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
  fi
  if validate_ipv4 "${detected}"; then
    printf '%s' "${detected}"
  fi
}

install_packages() {
  local role="$1"
  [[ ${SKIP_PACKAGES} -eq 0 ]] || return 0
  if command -v apt-get >/dev/null 2>&1; then
    local -a packages=(ca-certificates curl tar iproute2)
    if [[ "${role}" == "agent" ]]; then
      packages+=(nftables conntrack wireguard-tools)
    fi
    log "安装系统依赖"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends "${packages[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    local -a packages=(ca-certificates curl tar iproute)
    if [[ "${role}" == "agent" ]]; then
      packages+=(nftables conntrack-tools wireguard-tools)
    fi
    log "安装系统依赖"
    dnf install -y "${packages[@]}"
  elif command -v yum >/dev/null 2>&1; then
    local -a packages=(ca-certificates curl tar iproute)
    if [[ "${role}" == "agent" ]]; then
      packages+=(nftables conntrack-tools wireguard-tools)
    fi
    log "安装系统依赖"
    yum install -y "${packages[@]}"
  else
    warn "未识别包管理器，将只检查现有依赖"
  fi
}

require_release_tools() {
  local command
  for command in sha256sum tar awk find; do
    command -v "${command}" >/dev/null 2>&1 || die "缺少命令：${command}"
  done
}

download_file() {
  local url="$1"
  local destination="$2"
  validate_https_url "${url}" || die "下载地址必须是无空格、无凭据的 HTTPS URL：${url}"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "${url}" -o "${destination}"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --secure-protocol=TLSv1_2 -qO "${destination}" "${url}"
  else
    die "需要 curl 或 wget"
  fi
}

verify_archive() {
  local archive="$1"
  local checksum="$2"
  local expected actual entry clean
  expected="$(awk 'NR == 1 {print $1}' "${checksum}")"
  [[ "${expected}" =~ ^[0-9A-Fa-f]{64}$ ]] || die "SHA-256 校验文件格式错误"
  actual="$(sha256sum "${archive}" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "发行包 SHA-256 不匹配，已拒绝安装"
  while IFS= read -r entry; do
    clean="${entry#./}"
    [[ "${clean}" != /* && "${clean}" != ../* && "${clean}" != *"/../"* ]] ||
      die "发行包包含不安全路径"
  done < <(tar -tzf "${archive}")
}

prepare_release() {
  local role="$1"
  local arch="$2"
  local archive checksum binary_name binary release_root expected actual
  TEMP_DIR="${TEMP_DIR:-$(mktemp -d -t flux-install.XXXXXXXX)}"
  archive="${ARCHIVE_PATH}"
  checksum="${CHECKSUM_FILE}"
  if [[ -n "${archive}" ]]; then
    [[ -f "${archive}" ]] || die "找不到本地发行包：${archive}"
    if [[ -z "${checksum}" ]]; then
      checksum="${archive}.sha256"
    fi
    [[ -f "${checksum}" ]] || die "找不到校验文件：${checksum}"
  else
    [[ -n "${RELEASE_URL}" ]] || die "请提供 --release-url 或 --archive"
    validate_https_url "${RELEASE_URL}" || die "--release-url 必须是 HTTPS 直链"
    archive="${TEMP_DIR}/flux-release.tar.gz"
    checksum="${TEMP_DIR}/flux-release.tar.gz.sha256"
    log "下载 Flux 发行包"
    download_file "${RELEASE_URL}" "${archive}"
    download_file "${CHECKSUM_URL:-${RELEASE_URL}.sha256}" "${checksum}"
  fi
  require_release_tools
  verify_archive "${archive}" "${checksum}"
  mkdir -p "${TEMP_DIR}/release"
  tar --extract --gzip --file "${archive}" --directory "${TEMP_DIR}/release" --no-same-owner --no-same-permissions
  binary_name="flux-${role}-linux-${arch}"
  binary="$(find "${TEMP_DIR}/release" -type f -path "*/bin/${binary_name}" -print -quit)"
  [[ -n "${binary}" && -f "${binary}" ]] || die "发行包中缺少 ${binary_name}"
  release_root="$(dirname "$(dirname "${binary}")")"
  [[ -f "${release_root}/SHA256SUMS" ]] || die "发行包缺少内部校验清单"
  expected="$(awk -v name="bin/${binary_name}" '$2 == name || $2 == "*" name {print $1; exit}' "${release_root}/SHA256SUMS")"
  [[ "${expected}" =~ ^[0-9A-Fa-f]{64}$ ]] || die "内部校验清单缺少 ${binary_name}"
  actual="$(sha256sum "${binary}" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "${binary_name} 内部校验失败"
  RELEASE_ROOT="${release_root}"
  RELEASE_BINARY="${binary}"
}

enable_ipv4_forwarding() {
  printf '%s\n' 'net.ipv4.ip_forward=1' >"${TEMP_DIR}/90-flux-forwarding.conf"
  install -m 0644 "${TEMP_DIR}/90-flux-forwarding.conf" /etc/sysctl.d/90-flux-forwarding.conf
  sysctl -q -w net.ipv4.ip_forward=1
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 {
      if (!found) print key "=" value
      found = 1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' "${file}" >"${TEMP_DIR}/env-updated"
  install -m 0600 "${TEMP_DIR}/env-updated" "${file}"
}

run_as_controller() {
  runuser -u flux-controller -- "$@"
}

configure_controller_inputs() {
  local detected_ip
  if [[ -z "${PUBLIC_HOST}" && ${NON_INTERACTIVE} -eq 0 ]]; then
    PUBLIC_HOST="$(read_tty "Controller 对外域名或 IPv4")"
  fi
  [[ -n "${PUBLIC_HOST}" ]] || die "请提供 --public-host"
  validate_hostname "${PUBLIC_HOST}" || die "--public-host 格式错误（当前版本接受域名或 IPv4）"

  detected_ip="$(detect_primary_ipv4)"
  if [[ -z "${INITIAL_NODE_IP}" && ${NON_INTERACTIVE} -eq 0 ]]; then
    INITIAL_NODE_IP="$(read_tty "第一台节点的监听 IPv4" "${detected_ip}")"
  fi
  [[ -n "${INITIAL_NODE_IP}" ]] || die "请提供 --initial-node-ip"
  validate_ipv4 "${INITIAL_NODE_IP}" || die "--initial-node-ip 不是可用 IPv4 地址"
  validate_identifier "${PLAN_ID}" || die "--plan-id 格式错误"
  validate_identifier "${INITIAL_NODE_ID}" || die "--initial-node-id 格式错误"
  validate_identifier "${OWNER_USERNAME}" || die "--owner-username 格式错误"
  [[ "${COOKIE_SECURE}" == "true" || "${COOKIE_SECURE}" == "false" ]] || die "--cookie-secure 只能是 true 或 false"
  if [[ -n "${OWNER_PASSWORD_FILE}" && ! -f "${OWNER_PASSWORD_FILE}" ]]; then
    die "找不到管理员密码文件：${OWNER_PASSWORD_FILE}"
  fi

  if [[ -z "${NODE_RELEASE_URL}" ]]; then
    NODE_RELEASE_URL="${RELEASE_URL}"
  fi
  if [[ -z "${NODE_INSTALLER_URL}" && -n "${NODE_RELEASE_URL}" ]]; then
    NODE_INSTALLER_URL="${NODE_RELEASE_URL%/*}/install.sh"
  fi
  validate_https_url "${NODE_INSTALLER_URL}" ||
    die "请提供可公开下载的 --node-installer-url HTTPS 地址"
  validate_https_url "${NODE_RELEASE_URL}" ||
    die "请提供可公开下载的 --node-release-url HTTPS 地址"
}

write_controller_env() {
  local destination="/etc/flux-controller/flux-controller.env"
  mkdir -p /etc/flux-controller
  if [[ ! -f "${destination}" ]]; then
    cat >"${TEMP_DIR}/flux-controller.env" <<EOF
FLUX_ENROLL_ADDRESS=:8443
FLUX_CONTROL_ADDRESS=:9443
FLUX_PUBLIC_ENROLL_ADDRESS=${PUBLIC_HOST}:8443
FLUX_PUBLIC_CONTROL_ADDRESS=${PUBLIC_HOST}:9443
FLUX_NODE_INSTALLER_URL=${NODE_INSTALLER_URL}
FLUX_NODE_RELEASE_URL=${NODE_RELEASE_URL}
FLUX_MANAGEMENT_COOKIE_SECURE=${COOKIE_SECURE}
FLUX_MANAGEMENT_SESSION_TTL=24h
FLUX_MANAGEMENT_PLAN_ID=${PLAN_ID}
FLUX_WEB_ROOT=/opt/flux/web
FLUX_SNAPSHOT_POLL_INTERVAL=5s
FLUX_PING_INTERVAL=30s
FLUX_AUTH_CHECK_INTERVAL=30s
FLUX_HEARTBEAT_TIMEOUT=95s
EOF
    install -m 0600 "${TEMP_DIR}/flux-controller.env" "${destination}"
  else
    set_env_value "${destination}" FLUX_NODE_INSTALLER_URL "${NODE_INSTALLER_URL}"
    set_env_value "${destination}" FLUX_NODE_RELEASE_URL "${NODE_RELEASE_URL}"
  fi
}

create_initial_plan() {
  local plan_file="/var/lib/flux-controller/.initial-plan.tmp"
  cat >"${TEMP_DIR}/initial-plan.json" <<EOF
{
  "schema_version": 1,
  "id": "${PLAN_ID}",
  "revision": 1,
  "node_offline_after_seconds": 90,
  "nodes": [
    {
      "id": "${INITIAL_NODE_ID}",
      "enabled": true,
      "roles": ["ingress", "exit"],
      "listen_ips": ["${INITIAL_NODE_IP}"],
      "failure_domain": "default",
      "capacity": {"max_forwards": 10000}
    }
  ],
  "backend_pools": [],
  "forwards": []
}
EOF
  /usr/local/bin/flux-controller plan-validate --file "${TEMP_DIR}/initial-plan.json" >/dev/null
  install -m 0600 -o flux-controller -g flux-controller "${TEMP_DIR}/initial-plan.json" "${plan_file}"
  run_as_controller /usr/local/bin/flux-controller plan-apply \
    --database /var/lib/flux-controller/flux.db \
    --file "${plan_file}" \
    --actor installer >/dev/null
  rm -f "${plan_file}"
}

install_controller() {
  require_root
  require_linux_systemd
  configure_controller_inputs
  install_packages controller
  local arch fresh_database=0 generated_password="" password_source="" owner_result=""
  arch="$(detect_arch)"
  prepare_release controller "${arch}"
  [[ -f "${RELEASE_ROOT}/deploy/systemd/flux-controller.service" ]] ||
    die "发行包缺少 Controller systemd 单元"
  [[ -f "${RELEASE_ROOT}/web/index.html" ]] || die "发行包缺少 Web 控制台"
  command -v runuser >/dev/null 2>&1 || die "缺少 runuser"

  if [[ ! -f /var/lib/flux-controller/flux.db ]]; then
    fresh_database=1
  fi
  SERVICE_NAME="flux-controller.service"
  SERVICE_WAS_ACTIVE="$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  SERVICE_WAS_ENABLED="$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || true)"
  TEMP_DIR="${TEMP_DIR:-$(mktemp -d -t flux-install.XXXXXXXX)}"
  backup_path /usr/local/bin/flux-controller
  backup_path /etc/systemd/system/flux-controller.service
  backup_path /etc/flux-controller/flux-controller.env
  backup_path /opt/flux/web
  backup_path /var/lib/flux-controller

  log "安装 Controller 和 Web 控制台"
  if ! getent passwd flux-controller >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/flux-controller --shell /usr/sbin/nologin flux-controller
    CONTROLLER_USER_CREATED=1
  fi
  install -d -m 0750 -o flux-controller -g flux-controller /var/lib/flux-controller
  install -d -m 0750 -o flux-controller -g flux-controller /var/lib/flux-controller/backups
  chown -R flux-controller:flux-controller /var/lib/flux-controller
  if [[ ${fresh_database} -eq 1 ]]; then
    install -m 0600 -o flux-controller -g flux-controller /dev/null /var/lib/flux-controller/.needs-owner-init
    install -m 0600 -o flux-controller -g flux-controller /dev/null /var/lib/flux-controller/.needs-initial-plan
  fi
  install -d -m 0755 /opt/flux
  install -m 0755 "${RELEASE_BINARY}" /usr/local/bin/flux-controller
  rm -rf -- "${TEMP_DIR}/web-new"
  install -d -m 0755 "${TEMP_DIR}/web-new"
  cp -a "${RELEASE_ROOT}/web/." "${TEMP_DIR}/web-new/"
  # The release is extracted under umask 077. The Controller runs as an
  # unprivileged user, so only the public web assets need their normal modes
  # restored before they are installed outside the protected state directory.
  find "${TEMP_DIR}/web-new" -type d -exec chmod 0755 {} +
  find "${TEMP_DIR}/web-new" -type f -exec chmod 0644 {} +
  rm -rf -- /opt/flux/web
  mv "${TEMP_DIR}/web-new" /opt/flux/web
  install -m 0644 "${RELEASE_ROOT}/deploy/systemd/flux-controller.service" /etc/systemd/system/flux-controller.service
  write_controller_env

  if [[ ! -f /var/lib/flux-controller/controller-noise.key ]]; then
    run_as_controller /usr/local/bin/flux-controller key-init --dir /var/lib/flux-controller >/dev/null
  fi
  run_as_controller /usr/local/bin/flux-controller migrate --database /var/lib/flux-controller/flux.db >/dev/null

  if [[ -f /var/lib/flux-controller/.needs-owner-init ]]; then
    if [[ -n "${OWNER_PASSWORD_FILE}" ]]; then
      [[ -f "${OWNER_PASSWORD_FILE}" ]] || die "找不到管理员密码文件"
      password_source="${OWNER_PASSWORD_FILE}"
    else
      generated_password="$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')"
      password_source="${TEMP_DIR}/owner-password"
      printf '%s\n' "${generated_password}" >"${password_source}"
    fi
    install -m 0600 -o flux-controller -g flux-controller "${password_source}" /var/lib/flux-controller/.owner-password.tmp
    if ! owner_result="$(run_as_controller /usr/local/bin/flux-controller owner-init \
      --database /var/lib/flux-controller/flux.db \
      --username "${OWNER_USERNAME}" \
      --display-name "${OWNER_DISPLAY_NAME}" \
      --password-file /var/lib/flux-controller/.owner-password.tmp \
      --if-missing)"; then
      rm -f /var/lib/flux-controller/.owner-password.tmp
      die "管理员账号初始化失败"
    fi
    rm -f /var/lib/flux-controller/.owner-password.tmp
    rm -f /var/lib/flux-controller/.needs-owner-init
    if [[ -n "${generated_password}" && "${owner_result}" == *'"created": true'* ]]; then
      printf '\n管理员账号：%s\n管理员初始密码：%s\n' "${OWNER_USERNAME}" "${generated_password}"
      printf '此密码只显示一次，请立即保存并在首次登录后修改。\n\n'
    elif [[ "${owner_result}" == *'"created": false'* ]]; then
      warn "管理员账号已存在，保留原密码"
    fi
  fi
  if [[ -f /var/lib/flux-controller/.needs-initial-plan ]]; then
    if ! run_as_controller /usr/local/bin/flux-controller plan-status \
      --database /var/lib/flux-controller/flux.db \
      --plan-id "${PLAN_ID}" >/dev/null 2>&1; then
      run_as_controller /usr/local/bin/flux-controller ensure-node \
        --database /var/lib/flux-controller/flux.db \
        --node-id "${INITIAL_NODE_ID}" >/dev/null
      create_initial_plan
    fi
    rm -f /var/lib/flux-controller/.needs-initial-plan
  fi

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
  systemctl is-active --quiet "${SERVICE_NAME}" || {
    systemctl status "${SERVICE_NAME}" --no-pager >&2 || true
    die "Controller 启动失败"
  }
  COMMITTED=1
  log "Controller 安装完成"
  printf '\n面板仅监听本机。请在电脑上建立 SSH 隧道：\n'
  printf '  ssh -L 18080:127.0.0.1:8080 <服务器用户>@%s\n' "${PUBLIC_HOST}"
  printf '然后打开：http://127.0.0.1:18080\n'
  printf '需要在云防火墙放行：TCP 8443、9443；使用隧道转发时再放行 WireGuard UDP 端口。\n'
  printf '第一台节点名称：%s\n' "${INITIAL_NODE_ID}"
}

install_agent() {
  require_root
  require_linux_systemd
  local arch
  arch="$(detect_arch)"
  if [[ -z "${BUNDLE_BASE64}" ]]; then
    [[ ${NON_INTERACTIVE} -eq 0 ]] || die "请提供 --bundle-base64"
    BUNDLE_BASE64="$(read_tty "粘贴面板生成的一次性接入码")"
  fi
  [[ "${BUNDLE_BASE64}" =~ ^[A-Za-z0-9_-]+={0,2}$ ]] || die "一次性接入码格式错误"
  if [[ -n "${PUBLIC_INTERFACE}" || ${ALLOW_TC_ROOT_REPLACE} -eq 1 ]]; then
    [[ -n "${PUBLIC_INTERFACE}" && ${ALLOW_TC_ROOT_REPLACE} -eq 1 ]] ||
      die "--public-interface 与 --allow-tc-root-replace 必须同时使用"
    [[ "${PUBLIC_INTERFACE}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "公网网卡名称格式错误"
  fi
  install_packages agent
  prepare_release agent "${arch}"
  backup_path /etc/sysctl.d/90-flux-forwarding.conf
  if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    IP_FORWARD_PREVIOUS="$(< /proc/sys/net/ipv4/ip_forward)"
  fi
  enable_ipv4_forwarding

  SERVICE_NAME="flux-agent.service"
  SERVICE_WAS_ACTIVE="$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  SERVICE_WAS_ENABLED="$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || true)"
  backup_path /usr/local/bin/flux-agent
  backup_path /etc/systemd/system/flux-agent.service
  backup_path /etc/systemd/system/flux-agent-maintenance.service
  # `flux-agent install` creates its durable state before contacting the
  # Controller. Keep that directory in the rollback set so a failed initial
  # enrollment leaves no incomplete local identity or state behind.
  backup_path /var/lib/flux-agent
  local -a arguments=(install --bundle-base64 "${BUNDLE_BASE64}")
  if [[ ${ENABLE_FABRIC} -eq 1 ]]; then
    arguments+=(--enable-fabric)
  fi
  if [[ -n "${PUBLIC_INTERFACE}" ]]; then
    arguments+=(--public-interface "${PUBLIC_INTERFACE}" --allow-tc-root-replace)
  fi
  chmod 0755 "${RELEASE_BINARY}"
  log "安装并接入 Agent"
  if ! "${RELEASE_BINARY}" "${arguments[@]}"; then
    if [[ -s /var/lib/flux-agent/identity/identity.json ]]; then
      COMMITTED=1
      die "节点身份已接入，但 systemd 启动失败；已保留程序和身份，请查看 systemctl status flux-agent"
    fi
    die "Agent 安装或接入失败"
  fi
  systemctl is-active --quiet "${SERVICE_NAME}" || {
    systemctl status "${SERVICE_NAME}" --no-pager >&2 || true
    die "Agent 启动失败"
  }
  COMMITTED=1
  log "Agent 安装完成"
  systemctl status "${SERVICE_NAME}" --no-pager --lines=5 || true
}

doctor() {
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
  local failures=0 command service
  printf 'Flux 环境检查\n'
  printf '  系统：%s %s\n' "$(uname -s)" "$(uname -r)"
  printf '  架构：%s\n' "$(uname -m)"
  for command in systemctl ip nft tc conntrack sha256sum tar; do
    if command -v "${command}" >/dev/null 2>&1; then
      printf '  [正常] %s\n' "${command}"
    else
      printf '  [缺少] %s\n' "${command}"
      failures=$((failures + 1))
    fi
  done
  if [[ -r /proc/sys/net/ipv4/ip_forward && "$(< /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
    printf '  [正常] IPv4 转发已开启\n'
  else
    printf '  [提醒] IPv4 转发未开启\n'
  fi
  for service in flux-controller.service flux-agent.service; do
    if systemctl list-unit-files "${service}" --no-legend 2>/dev/null | grep -q "${service}"; then
      printf '  [%s] %s\n' "$(systemctl is-active "${service}" 2>/dev/null || true)" "${service}"
    fi
  done
  if [[ ${failures} -gt 0 ]]; then
    die "发现 ${failures} 个缺失依赖"
  fi
  log "基础环境正常"
}

verify_release() {
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
  local arch
  arch="$(detect_arch)"
  prepare_release controller "${arch}"
  [[ -f "${RELEASE_ROOT}/deploy/systemd/flux-controller.service" ]] ||
    die "发行包缺少 Controller systemd 单元"
  [[ -f "${RELEASE_ROOT}/web/index.html" ]] || die "发行包缺少 Web 控制台"
  prepare_release agent "${arch}"
  log "发行包外层校验、内部二进制校验和安装文件检查均通过"
  COMMITTED=1
}

confirm_purge() {
  [[ ${PURGE} -eq 1 ]] || return 0
  if [[ ${ASSUME_YES} -eq 1 ]]; then
    return 0
  fi
  local answer
  answer="$(read_tty "将永久删除数据库或节点身份，输入 DELETE 确认")"
  [[ "${answer}" == "DELETE" ]] || die "已取消"
}

uninstall_flux() {
  require_root
  require_linux_systemd
  local component="${UNINSTALL_COMPONENT}"
  if [[ -z "${component}" && ${NON_INTERACTIVE} -eq 0 ]]; then
    component="$(read_tty "卸载 controller 还是 agent")"
  fi
  [[ "${component}" == "controller" || "${component}" == "agent" ]] ||
    die "请使用 --component controller 或 --component agent"
  confirm_purge
  if [[ "${component}" == "controller" ]]; then
    systemctl disable --now flux-controller.service 2>/dev/null || true
    rm -f /etc/systemd/system/flux-controller.service /usr/local/bin/flux-controller
    if [[ ${PURGE} -eq 1 ]]; then
      rm -rf -- /var/lib/flux-controller /etc/flux-controller /opt/flux/web
    fi
  else
    warn "停止 Agent 不会主动清空 last-known-good 转发；请先在面板移除转发并等待节点同步"
    systemctl disable --now flux-agent.service 2>/dev/null || true
    rm -f /etc/systemd/system/flux-agent.service /etc/systemd/system/flux-agent-maintenance.service /usr/local/bin/flux-agent
    if [[ ${PURGE} -eq 1 ]]; then
      rm -rf -- /var/lib/flux-agent
      rm -f /etc/sysctl.d/90-flux-forwarding.conf
    fi
  fi
  systemctl daemon-reload
  COMMITTED=1
  if [[ ${PURGE} -eq 1 ]]; then
    log "${component} 已卸载，数据已清除"
  else
    log "${component} 已卸载，数据与身份仍保留"
  fi
}

main() {
  select_mode "$@"
  parse_args "${REMAINING_ARGS[@]}"
  case "${MODE}" in
    controller) install_controller ;;
    agent) install_agent ;;
    verify) verify_release ;;
    doctor) doctor ;;
    uninstall) uninstall_flux ;;
    help|-h|--help) usage ;;
    *) usage; die "不支持的操作：${MODE}" ;;
  esac
}

main "$@"
