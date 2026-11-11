#!/usr/bin/env bash
# One-command local GuardFil: approval service, with or without the web UI.
#
#   deployments/local/guardfil-local.sh init [--ui none|inactive|active]   create $GF_HOME (once)
#   deployments/local/guardfil-local.sh up                                 build and start
#   deployments/local/guardfil-local.sh ui none|inactive|active           change the UI switch and restart
#   deployments/local/guardfil-local.sh catalog FILE                      install an app's tool catalog (kept with the agents' tools) and restart
#   deployments/local/guardfil-local.sh credential NAME < SECRET          store an app credential for the gateway (from stdin)
#   deployments/local/guardfil-local.sh gateway FILE | --remove           install the API gateway's upstream apps and restart
#   deployments/local/guardfil-local.sh status | down | logs
#   deployments/local/guardfil-local.sh check                             verify the host can serve a mediated workspace
#   deployments/local/guardfil-local.sh run-codex --workspace DIR [--prompt TEXT] [--once] [--max-requests N] [--mcp NAME=CMD]
#                                       native Codex in a networkless container; GuardFil decides its calls
#   deployments/local/guardfil-local.sh run-agent --runtime codex --workspace DIR [...]
#                                       any supported agent runtime in the same executor
#
# GF_HOME (default ~/.guardfil-local) holds config/, credentials/, state/ and run/.
# The agent harness asks GuardFil on $GF_HOME/run/approval.sock.
set -euo pipefail

GF_HOME=${GF_HOME:-$HOME/.guardfil-local}
HERE=$(cd "$(dirname "$0")" && pwd)
# GF_PROJECT names the Compose project; give each GF_HOME on one machine its own.
COMPOSE=(docker compose -f "$HERE/compose.yaml" -p "${GF_PROJECT:-guardfil-local}")
DATA_ADDR=${GF_DATA_ADDR:-127.0.0.1:18080}
MGMT_ADDR=${GF_MGMT_ADDR:-127.0.0.1:19090}
UI_ADDR=${GF_UI_ADDR:-127.0.0.1:8088}
export GF_HOME GF_UID=$(id -u) GF_GID=$(id -g)

die() { echo "guardfil-local: $*" >&2; exit 1; }

random_token() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

ensure_image() {
  docker image inspect guardfil-local:dev >/dev/null 2>&1 || {
    echo "guardfil-local: build the validator first with '$0 up' (guardfil-local:dev missing)" >&2
    return 1
  }
}

CONFIG_STAGE=""
trap '[ -z "$CONFIG_STAGE" ] || rm -rf -- "$CONFIG_STAGE"' EXIT

validate_candidate_stage() { # $1 = stage dir
  local stage="$1"
  ensure_image || return 1
  docker run --rm \
    --network none \
    --user "$GF_UID:$GF_GID" \
    --read-only \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    -v "$stage:/etc/guardfil:ro" \
    -v "$GF_HOME/credentials:/etc/guardfil/credentials.d:ro" \
    -v "$GF_HOME/state:/var/lib/guardfil:ro" \
    -v "$GF_HOME/run:/run/guardfil:ro" \
    -v "$GF_HOME/owner:/run/guardfil-owner:ro" \
    guardfil-local:dev \
    -validate-config -config /etc/guardfil/guardfil.yaml
}

stage_config() {
  CONFIG_STAGE=$(mktemp -d "$GF_HOME/.config-stage.XXXXXX")
  cp -a "$GF_HOME/config/." "$CONFIG_STAGE/"
}

install_config_files() { # Copy only files managed by this command, including UI mode.
  local source="$1" name tmp
  for name in guardfil.yaml tool-catalog.yaml app-catalog.yaml gateway.yaml .ui-mode; do
    if [ -f "$source/$name" ]; then
      tmp="$GF_HOME/config/.install-$name"
      cp -p "$source/$name" "$tmp" && mv "$tmp" "$GF_HOME/config/$name" || return 1
    else
      rm -f "$GF_HOME/config/$name" || return 1
    fi
  done
}

apply_staged_config() { # $1 = validated candidate directory
  local stage="$1" backup
  backup=$(mktemp -d "$GF_HOME/.config-backup.XXXXXX")
  cp -a "$GF_HOME/config/." "$backup/"
  if install_config_files "$stage" && restart_if_running; then
    rm -rf "$backup" "$stage"
    CONFIG_STAGE=""
    return 0
  fi
  echo "guardfil-local: install or restart failed; restoring previous configuration" >&2
  if ! install_config_files "$backup"; then
    die "could not restore configuration; backup retained at $backup"
  fi
  rm -rf "$backup"
  if ! restart_if_running; then
    die "configuration restored, but GuardFil could not restart; inspect '$0 logs'"
  fi
  die "change rejected; previous configuration restored"
}

generate_config_dir() { # $1 = config dir, $2 = ui_mode
  local dir="$1"
  local ui="$2"
  case "$ui" in none|inactive|active) ;; *) die "ui must be none, inactive or active" ;; esac
  local tmp="$dir/.guardfil.yaml.tmp"
  (umask 077; {
    echo 'config_root: /etc/guardfil'
    echo 'credentials_root: /etc/guardfil/credentials.d'
    echo "data: {address: \"$DATA_ADDR\"}"
    echo "management: {address: \"$MGMT_ADDR\", metrics_token_file: /etc/guardfil/credentials.d/metrics-token}"
    echo 'state_dir: /var/lib/guardfil'
    echo 'approval:'
    echo '  socket: /run/guardfil/approval.sock'
    echo '  policy_file: /etc/guardfil/policy.yaml'
    echo '  decision_log: /var/lib/guardfil/decisions.jsonl'
    echo '  filter_socket: /run/guardfil/filter.sock'
    echo '  approver_socket: /run/guardfil-owner/owner.sock'
    [ -f "$dir/tool-catalog.yaml" ] && echo '  tool_catalog: /etc/guardfil/tool-catalog.yaml'
    if [ "$ui" != none ]; then
      echo 'ui:'
      echo "  active: $([ "$ui" = active ] && echo true || echo false)"
      echo "  address: \"$UI_ADDR\""
      echo '  token_file: /etc/guardfil/credentials.d/ui-token'
    fi
    # The API gateway, if the owner installed its upstreams (guardfil-local.sh gateway FILE).
    # It listens only on a Unix socket in run/, which run-agent mounts into the executor.
    if [ -f "$dir/gateway.yaml" ]; then
      echo 'gateway:'
      echo '  socket: /run/guardfil/gateway.sock'
      echo '  agent_token_file: /etc/guardfil/credentials.d/gateway-agent-token'
      sed 's/^/  /' "$dir/gateway.yaml"
    fi
  } > "$tmp")
  mv "$tmp" "$dir/guardfil.yaml"
  echo "$ui" > "$dir/.ui-mode"
}

write_config() { # $1 = none|inactive|active
  generate_config_dir "$GF_HOME/config" "$1"
}

ui_mode() { cat "$GF_HOME/config/.ui-mode" 2>/dev/null || echo none; }

# The tool catalog GuardFil loads: the agents' tools (executor-catalog.yaml)
# followed by the app's catalog, if one was installed, as a second document.
build_catalog_dir() { # $1 = config dir
  local dir="$1"
  local tmp="$dir/.tool-catalog.yaml.tmp"
  (umask 077; {
    cat "$HERE/executor-catalog.yaml"
    if [ -f "$dir/app-catalog.yaml" ]; then
      printf '\n---\n'
      cat "$dir/app-catalog.yaml"
    fi
  } > "$tmp")
  mv "$tmp" "$dir/tool-catalog.yaml"
}

build_catalog() {
  build_catalog_dir "$GF_HOME/config"
}

restart_if_running() {
  # Also restarts a GuardFil that stopped on a bad config, once the config is fixed.
  local containers running
  containers=$("${COMPOSE[@]}" ps -aq) || return 1
  if [ -n "$containers" ]; then
    "${COMPOSE[@]}" restart >/dev/null 2>&1 || return 1
    # GuardFil refuses a bad config at startup and exits; give it a moment to do so.
    sleep 2
    running=$("${COMPOSE[@]}" ps -q --status running) || return 1
    if [ -z "$running" ]; then
      "${COMPOSE[@]}" logs --tail 5
      return 1
    fi
  fi
  return 0
}

# The mediated workspace needs host FUSE setup that only an administrator can
# change. Say so at setup time rather than at the first agent run.
workspace_check() { (cd "$HERE/../.." && python3 -I -c 'import sys; sys.path.insert(0, "."); from deployments.local.workspace import host_problem; p = host_problem(); sys.exit(p)' 2>&1); }
workspace_warn() {
  local problem
  problem=$(workspace_check) || echo "warning: agents cannot run yet: $problem" >&2
}

cmd_init() {
  local ui=none
  while [ $# -gt 0 ]; do
    case "$1" in
      --ui) ui=${2:-}; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -e "$GF_HOME" ] && die "$GF_HOME exists; remove it or set GF_HOME"
  umask 077
  # config/credentials.d is the mount point for credentials/ inside the (read-only) config mount.
  # owner/ holds the owner socket (answers held calls, opens agent sessions); it is never mounted into agents.
  mkdir -p "$GF_HOME"/{config,credentials,state,run,owner} "$GF_HOME/config/credentials.d"
  chmod 700 "$GF_HOME" "$GF_HOME"/{config,credentials,state,run} "$GF_HOME/config/credentials.d"
  cp "$HERE/starter-policy.yaml" "$GF_HOME/config/policy.yaml"
  # The tool catalog for the supported agents (Claude Code's tools, the notes demo).
  build_catalog
  chmod 600 "$GF_HOME/config/policy.yaml" "$GF_HOME/config/tool-catalog.yaml"
  random_token > "$GF_HOME/credentials/metrics-token"
  random_token > "$GF_HOME/credentials/ui-token"
  random_token > "$GF_HOME/credentials/gateway-agent-token"
  chmod 600 "$GF_HOME"/credentials/*
  write_config "$ui"
  echo "Created $GF_HOME (ui: $ui). Next: $0 up"
  workspace_warn
}

cmd_up() {
  [ -f "$GF_HOME/config/guardfil.yaml" ] || die "run '$0 init' first"
  # Homes made before the owner socket existed get it now.
  if [ ! -d "$GF_HOME/owner" ] || ! grep -q approver_socket "$GF_HOME/config/guardfil.yaml"; then
    (umask 077; mkdir -p "$GF_HOME/owner")
    write_config "$(cat "$GF_HOME/config/.ui-mode" 2>/dev/null || echo none)"
  fi
  "${COMPOSE[@]}" up --build -d
  local i
  for i in $(seq 1 50); do
    [ -S "$GF_HOME/run/approval.sock" ] && break
    sleep 0.2
  done
  [ -S "$GF_HOME/run/approval.sock" ] || { "${COMPOSE[@]}" logs --tail 20; die "approval socket did not appear"; }
  # The runtimes' Go binaries: guardfil-broker (host-side model brokers and the
  # in-executor relay) and guardfil-mcp-proxy (inside agent containers).
  local cid b
  mkdir -p -m 700 "$GF_HOME/bin"
  cid=$(docker create guardfil-local:dev) || die "could not read the GuardFil image"
  for b in guardfil-broker guardfil-mcp-proxy guardfil-workspace; do
    docker cp -q "$cid:/$b" "$GF_HOME/bin/$b" || { docker rm -f "$cid" >/dev/null; die "could not copy $b out of the image"; }
  done
  docker rm -f "$cid" >/dev/null 2>&1 || true
  cmd_status
  workspace_warn
}

cmd_status() {
  local mode; mode=$(cat "$GF_HOME/config/.ui-mode" 2>/dev/null || echo "?")
  echo "approval socket: $GF_HOME/run/approval.sock $([ -S "$GF_HOME/run/approval.sock" ] && echo '(up)' || echo '(down)')"
  case "$mode" in
    active) echo "web UI: http://$UI_ADDR/ (log in with the token in $GF_HOME/credentials/ui-token)" ;;
    inactive) echo "web UI: installed but inactive (no listener)" ;;
    none) echo "web UI: not deployed" ;;
  esac
  if [ -f "$GF_HOME/config/gateway.yaml" ]; then
    echo "API gateway: $GF_HOME/run/gateway.sock $([ -S "$GF_HOME/run/gateway.sock" ] && echo '(up)' || echo '(down)')"
  fi
  echo "decision log: $GF_HOME/state/decisions.jsonl"
}

cmd_catalog() {
  [ -f "$GF_HOME/config/guardfil.yaml" ] || die "run '$0 init' first"
  [ -f "${1:-}" ] || die "usage: $0 catalog FILE"

  local stage
  stage_config
  stage="$CONFIG_STAGE"
  (umask 077; cp "$1" "$stage/app-catalog.yaml")
  build_catalog_dir "$stage"
  generate_config_dir "$stage" "$(ui_mode)"

  if ! validate_candidate_stage "$stage"; then
    rm -rf "$stage"
    die "$1: catalog produces invalid GuardFil configuration"
  fi

  apply_staged_config "$stage"
  echo "tool catalog installed: $GF_HOME/config/tool-catalog.yaml (the agents' tools and $1)"
}

cmd_credential() {
  [ -f "$GF_HOME/config/guardfil.yaml" ] || die "run '$0 init' first"
  local name=${1:-}
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]] || die "usage: $0 credential NAME < SECRET  (NAME: lower-case letters, digits and -)"
  case "$name" in metrics-token|ui-token|gateway-agent-token) die "$name is GuardFil's own token" ;; esac
  local tmp="$GF_HOME/credentials/.$name.tmp" secret
  if [ -t 0 ]; then
    read -rs -p "secret for $name: " secret; echo >&2
  else
    secret=$(cat)
  fi
  [ -n "$secret" ] || die "empty secret"
  (umask 077; printf '%s' "$secret" > "$tmp")
  mv "$tmp" "$GF_HOME/credentials/$name"
  echo "stored $GF_HOME/credentials/$name; refer to it as credential_file: /etc/guardfil/credentials.d/$name"
  if [ -f "$GF_HOME/config/gateway.yaml" ]; then
    restart_if_running || die "GuardFil restart failed after storing credential"
  fi
}

cmd_gateway() {
  [ -f "$GF_HOME/config/guardfil.yaml" ] || die "run '$0 init' first"
  if [ "${1:-}" = --remove ]; then
    if [ ! -f "$GF_HOME/config/gateway.yaml" ]; then
      rm -f "$GF_HOME/run/gateway.sock"
      echo "gateway not installed"
      return 0
    fi
    local stage
    stage_config
    stage="$CONFIG_STAGE"
    rm -f "$stage/gateway.yaml"
    generate_config_dir "$stage" "$(ui_mode)"

    if ! validate_candidate_stage "$stage"; then
      rm -rf "$stage"
      die "removing gateway produces invalid GuardFil configuration"
    fi

    apply_staged_config "$stage"
    rm -f "$GF_HOME/run/gateway.sock"
    echo "gateway removed"
    return 0
  fi

  local f=${1:-}
  [ -f "$f" ] || die "usage: $0 gateway FILE | --remove"
  local other
  other=$(grep -vE '^[[:space:]]|^#|^$|^upstreams:' "$f" || true)
  [ -z "$other" ] || die "$f: only an 'upstreams:' list is allowed at the top level (found: ${other%%$'\n'*})"

  [ -f "$GF_HOME/credentials/gateway-agent-token" ] || (umask 077; random_token > "$GF_HOME/credentials/gateway-agent-token")

  local stage
  stage_config
  stage="$CONFIG_STAGE"
  (umask 077; cp "$f" "$stage/gateway.yaml")
  generate_config_dir "$stage" "$(ui_mode)"

  if ! validate_candidate_stage "$stage"; then
    rm -rf "$stage"
    die "$f: gateway configuration is invalid"
  fi

  apply_staged_config "$stage"
  echo "gateway installed: agents reach it at /run/guardfil/gateway.sock (run-agent mounts it)"
}

cmd_ui() {
  [ -f "$GF_HOME/config/guardfil.yaml" ] || die "run '$0 init' first"
  local stage
  stage_config
  stage="$CONFIG_STAGE"
  generate_config_dir "$stage" "${1:-}"

  if ! validate_candidate_stage "$stage"; then
    rm -rf "$stage"
    die "ui change produces invalid GuardFil configuration"
  fi

  apply_staged_config "$stage"
  cmd_status
}

case "${1:-}" in
  init) shift; cmd_init "$@" ;;
  up) cmd_up ;;
  down) "${COMPOSE[@]}" down ;;
  logs) "${COMPOSE[@]}" logs --tail 50 ;;
  status) cmd_status ;;
  check) problem=$(workspace_check) && echo "workspace host setup: ok" || die "$problem" ;;
  ui) shift; cmd_ui "$@" ;;
  catalog) shift; cmd_catalog "$@" ;;
  credential) shift; cmd_credential "$@" ;;
  gateway) shift; cmd_gateway "$@" ;;
  run-codex) shift; cd "$HERE/../.." && exec python3 -I deployments/local/run_agent.py --runtime codex "$@" ;;
  run-agent) shift; cd "$HERE/../.." && exec python3 -I deployments/local/run_agent.py "$@" ;;
  *) sed -n '2,18p' "$0"; exit 2 ;;
esac
