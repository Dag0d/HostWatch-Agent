#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=${HOSTWATCH_INSTALL_DIR:-/opt/hostwatch}
CONFIG_DIR=${HOSTWATCH_CONFIG_DIR:-/etc/hostwatch}
STATE_DIR=${HOSTWATCH_STATE_DIR:-/var/lib/hostwatch}
BIN_PATH=${HOSTWATCH_BIN_PATH:-/usr/local/bin/hostwatch-agent}
SERVICE_PATH=${HOSTWATCH_SERVICE_PATH:-/etc/systemd/system/hostwatch-agent.service}
CONFIG_PATH=${HOSTWATCH_CONFIG_PATH:-"$CONFIG_DIR/agent.json"}
STATE_PATH=${HOSTWATCH_STATE_PATH:-"$STATE_DIR/agent.state.json"}
SERVICE_NAME=${HOSTWATCH_SERVICE_NAME:-hostwatch-agent.service}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AGENT_SOURCE=${HOSTWATCH_AGENT_SOURCE:-"$SCRIPT_DIR/hostwatch_agent.py"}
RELEASE_PUBLIC_KEY_SOURCE=${HOSTWATCH_RELEASE_PUBLIC_KEY_SOURCE:-"$SCRIPT_DIR/release_signing_public.pem"}

REMOTE_HOST=""
REMOTE_SSH_KEY=""
REMOTE_SSH_PORT="22"
REMOTE_SSH_USER=""
REMOTE_DIR=""
RUN_CONFIG=1
RUN_PAIR=1
ENABLE_SERVICE=1
LOCAL_MODE=1
UPDATE_MODE=0
REMOVE_MODE=0

usage() {
  cat <<EOF
HostWatch agent installer

Local install on the target host:
  sudo ./install.sh
  sudo ./install.sh --update
  sudo ./install.sh --remove
  sudo ./install.sh --no-pair

Remote install from macOS/Linux to a Linux systemd host:
  ./install.sh --remote user@host
  ./install.sh --remote user@host --update
  ./install.sh --remote user@host --remove
  ./install.sh --remote user@host:2020
  ./install.sh --remote user@host --ssh-key ~/.ssh/id_ed25519

Options:
  --update                Update agent/service files, preserve config/pairing, restart service
  --remove                Remove service, agent, wrapper, config and state from the target host
  --remote USER@HOST       Copy installer and agent to a remote Linux host and install there
  --ssh-key PATH           SSH private key for remote mode
  --ssh-port PORT          SSH port for remote mode (default: 22)
  --remote-dir PATH        Temporary remote install dir (default: /tmp/hostwatch-install-\$PID)
  --install-dir PATH       Agent install directory (default: /opt/hostwatch)
  --config-dir PATH        Config directory (default: /etc/hostwatch)
  --state-dir PATH         State directory (default: /var/lib/hostwatch)
  --bin-path PATH          Wrapper path (default: /usr/local/bin/hostwatch-agent)
  --no-config              Skip interactive agent configuration
  --no-pair                Skip pairing mode during install
  --no-enable              Do not enable/start the systemd service
  -h, --help               Show this help
EOF
}

log() {
  printf '[hostwatch-install] %s\n' "$*"
}

die() {
  printf '[hostwatch-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

quote_args() {
  local quoted=()
  local arg
  for arg in "$@"; do
    quoted+=("$(printf '%q' "$arg")")
  done
  printf '%s ' "${quoted[@]}"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --remote)
        REMOTE_HOST=${2:-}
        [ -n "$REMOTE_HOST" ] || die "--remote requires USER@HOST"
        LOCAL_MODE=0
        shift 2
        ;;
      --ssh-key)
        REMOTE_SSH_KEY=${2:-}
        [ -n "$REMOTE_SSH_KEY" ] || die "--ssh-key requires PATH"
        shift 2
        ;;
      --ssh-port)
        REMOTE_SSH_PORT=${2:-}
        [ -n "$REMOTE_SSH_PORT" ] || die "--ssh-port requires PORT"
        shift 2
        ;;
      --remote-dir)
        REMOTE_DIR=${2:-}
        [ -n "$REMOTE_DIR" ] || die "--remote-dir requires PATH"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR=${2:-}
        [ -n "$INSTALL_DIR" ] || die "--install-dir requires PATH"
        shift 2
        ;;
      --config-dir)
        CONFIG_DIR=${2:-}
        [ -n "$CONFIG_DIR" ] || die "--config-dir requires PATH"
        CONFIG_PATH="$CONFIG_DIR/agent.json"
        shift 2
        ;;
      --state-dir)
        STATE_DIR=${2:-}
        [ -n "$STATE_DIR" ] || die "--state-dir requires PATH"
        STATE_PATH="$STATE_DIR/agent.state.json"
        shift 2
        ;;
      --bin-path)
        BIN_PATH=${2:-}
        [ -n "$BIN_PATH" ] || die "--bin-path requires PATH"
        shift 2
        ;;
      --no-config)
        RUN_CONFIG=0
        shift
        ;;
      --no-pair)
        RUN_PAIR=0
        shift
        ;;
      --no-enable)
        ENABLE_SERVICE=0
        shift
        ;;
      --update)
        UPDATE_MODE=1
        RUN_CONFIG=0
        RUN_PAIR=0
        shift
        ;;
      --remove)
        REMOVE_MODE=1
        RUN_CONFIG=0
        RUN_PAIR=0
        ENABLE_SERVICE=0
        shift
        ;;
      --local)
        LOCAL_MODE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

normalize_remote_host() {
  if [ -z "$REMOTE_HOST" ]; then
    return
  fi
  case "$REMOTE_HOST" in
    *:*)
      local host_part=${REMOTE_HOST%:*}
      local port_part=${REMOTE_HOST##*:}
      if [ -n "$host_part" ] && [ -n "$port_part" ] && [ "$port_part" != "$REMOTE_HOST" ]; then
        case "$port_part" in
          *[!0-9]*)
            die "Remote port must be numeric: $port_part"
            ;;
          *)
            REMOTE_HOST=$host_part
            REMOTE_SSH_PORT=$port_part
            ;;
        esac
      fi
      ;;
  esac
}

remote_install() {
  require_command ssh
  require_command scp
  [ -f "$AGENT_SOURCE" ] || die "Agent source not found: $AGENT_SOURCE"
  [ -f "$RELEASE_PUBLIC_KEY_SOURCE" ] || die "Release signing public key not found: $RELEASE_PUBLIC_KEY_SOURCE"
  normalize_remote_host

  local ssh_args=(-p "$REMOTE_SSH_PORT")
  local scp_args=(-P "$REMOTE_SSH_PORT")
  if [ -n "$REMOTE_SSH_KEY" ]; then
    ssh_args+=(-i "$REMOTE_SSH_KEY")
    scp_args+=(-i "$REMOTE_SSH_KEY")
  fi

  if [ -z "$REMOTE_DIR" ]; then
    REMOTE_DIR="/tmp/hostwatch-install-$(date +%s)-$$"
  fi

  log "Creating remote install directory $REMOTE_DIR on $REMOTE_HOST"
  ssh "${ssh_args[@]}" "$REMOTE_HOST" "mkdir -p $(printf '%q' "$REMOTE_DIR")"

  log "Copying installer, agent, and signing key to $REMOTE_HOST"
  scp "${scp_args[@]}" "$0" "$REMOTE_HOST:$REMOTE_DIR/install.sh"
  scp "${scp_args[@]}" "$AGENT_SOURCE" "$REMOTE_HOST:$REMOTE_DIR/hostwatch_agent.py"
  scp "${scp_args[@]}" "$RELEASE_PUBLIC_KEY_SOURCE" "$REMOTE_HOST:$REMOTE_DIR/release_signing_public.pem"

  local remote_args=(
    --local
    --install-dir "$INSTALL_DIR"
    --config-dir "$CONFIG_DIR"
    --state-dir "$STATE_DIR"
    --bin-path "$BIN_PATH"
  )
  [ "$REMOVE_MODE" -eq 1 ] && remote_args+=(--remove)
  [ "$UPDATE_MODE" -eq 1 ] && remote_args+=(--update)
  [ "$RUN_CONFIG" -eq 1 ] || remote_args+=(--no-config)
  [ "$RUN_PAIR" -eq 1 ] || remote_args+=(--no-pair)
  [ "$ENABLE_SERVICE" -eq 1 ] || remote_args+=(--no-enable)

  log "Running remote installer. Pairing/config prompts will appear below."
  ssh -t "${ssh_args[@]}" "$REMOTE_HOST" \
    "cd $(printf '%q' "$REMOTE_DIR") && if [ \"\$(id -u)\" -eq 0 ]; then bash ./install.sh $(quote_args "${remote_args[@]}"); elif command -v sudo >/dev/null 2>&1; then sudo bash ./install.sh $(quote_args "${remote_args[@]}"); else echo '[hostwatch-install] ERROR: remote install needs root or sudo' >&2; exit 1; fi"
}

ensure_root() {
  if [ "$(id -u)" -eq 0 ]; then
    return
  fi
  require_command sudo
  log "Re-running installer with sudo"
  exec sudo -E bash "$0" "$@"
}

check_local_prerequisites() {
  require_command python3
  require_command openssl
  require_command systemctl
  [ -d /run/systemd/system ] || die "This installer target needs Linux with systemd"
  [ -f "$AGENT_SOURCE" ] || die "Agent source not found: $AGENT_SOURCE"
  [ -f "$RELEASE_PUBLIC_KEY_SOURCE" ] || die "Release signing public key not found: $RELEASE_PUBLIC_KEY_SOURCE"
}

check_remove_prerequisites() {
  require_command systemctl
  [ -d /run/systemd/system ] || die "This remove target needs Linux with systemd"
}

stop_service_if_running() {
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Stopping running $SERVICE_NAME before replacing files"
    systemctl stop "$SERVICE_NAME"
  fi
}

remove_installation() {
  log "Removing HostWatch agent installation"
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Stopping $SERVICE_NAME"
    systemctl stop "$SERVICE_NAME"
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    log "Disabling $SERVICE_NAME"
    systemctl disable "$SERVICE_NAME"
  fi

  log "Removing systemd service $SERVICE_PATH"
  rm -f "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

  log "Removing wrapper $BIN_PATH"
  rm -f "$BIN_PATH"

  log "Removing install directory $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"

  log "Removing config directory $CONFIG_DIR"
  rm -rf "$CONFIG_DIR"

  log "Removing state directory $STATE_DIR"
  rm -rf "$STATE_DIR"

  log "Removal complete"
}

install_files() {
  log "Installing agent to $INSTALL_DIR"
  install -d -m 0755 "$INSTALL_DIR"
  install -m 0755 "$AGENT_SOURCE" "$INSTALL_DIR/hostwatch_agent.py"
  install -m 0644 "$0" "$INSTALL_DIR/install.sh"
  install -m 0644 "$RELEASE_PUBLIC_KEY_SOURCE" "$INSTALL_DIR/release_signing_public.pem"

  log "Creating config/state directories"
  install -d -m 0700 "$CONFIG_DIR"
  install -d -m 0700 "$STATE_DIR"

  log "Installing wrapper to $BIN_PATH"
  install -d -m 0755 "$(dirname "$BIN_PATH")"
  cat >"$BIN_PATH" <<EOF
#!/usr/bin/env sh
export HOSTWATCH_CONFIG_PATH="$CONFIG_PATH"
export HOSTWATCH_STATE_PATH="$STATE_PATH"
exec python3 "$INSTALL_DIR/hostwatch_agent.py" "\$@"
EOF
  chmod 0755 "$BIN_PATH"

  log "Installing systemd service to $SERVICE_PATH"
  cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=HostWatch Agent
Documentation=https://github.com/Dag0d/HostWatch-Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=HOSTWATCH_CONFIG_PATH=$CONFIG_PATH
Environment=HOSTWATCH_STATE_PATH=$STATE_PATH
Environment=HOSTWATCH_LOG_LEVEL=INFO
Environment=HOSTWATCH_SERVICE_NAME=$SERVICE_NAME
ExecStart=$BIN_PATH run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
}

configure_and_pair() {
  if [ "$RUN_CONFIG" -eq 1 ]; then
    log "Starting interactive agent configuration"
    "$BIN_PATH" config
  fi

  if [ "$RUN_PAIR" -eq 1 ]; then
    log "Starting pairing mode. Add the discovered HostWatch node in Home Assistant, then approve here."
    "$BIN_PATH" pair
  fi
}

enable_service() {
  if [ "$ENABLE_SERVICE" -ne 1 ]; then
    log "Skipping systemd enable/start"
    return
  fi
  log "Enabling and starting $SERVICE_NAME"
  systemctl enable --now "$SERVICE_NAME"
  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

local_install() {
  ensure_root "$@"
  if [ "$REMOVE_MODE" -eq 1 ]; then
    check_remove_prerequisites
    remove_installation
    return
  fi
  check_local_prerequisites
  if [ "$UPDATE_MODE" -eq 1 ]; then
    log "Update mode: preserving existing config and skipping pairing"
  fi
  stop_service_if_running
  install_files
  configure_and_pair
  enable_service
  log "Installation complete"
  log "View logs with: journalctl -u $SERVICE_NAME -f"
}

parse_args "$@"
if [ "$LOCAL_MODE" -eq 0 ]; then
  remote_install
else
  local_install "$@"
fi
