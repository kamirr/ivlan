#!/usr/bin/env bash
set -euo pipefail

REPO="YOUR_GITHUB_USER/YOUR_REPO"   # <-- CHANGE THIS
BINARIES=("ivlan" "ivland")
INSTALL_DIR_DEFAULT="/usr/local/bin"
INSTALL_DIR_USER="$HOME/.local/bin"

MARKER_FILE="$HOME/.ivlan_install"

API_URL="https://api.github.com/repos/$REPO/releases"

# -------------------------
# Helpers
# -------------------------

log() { echo "[ivlan] $*"; }

detect_platform() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
      log "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  if [[ "$OS" == "darwin" ]]; then
    PLATFORM="macos-$ARCH"
  elif [[ "$OS" == "linux" ]]; then
    PLATFORM="linux-$ARCH"
  else
    log "Unsupported OS: $OS"
    exit 1
  fi
}

get_latest_tag() {
  curl -sL "$API_URL" | grep -m1 '"tag_name"' | cut -d '"' -f4
}

get_download_url() {
  local tag="$1"
  curl -sL "https://api.github.com/repos/$REPO/releases/tags/$tag" \
    | grep -o "https://[^ ]*${PLATFORM}.tar.gz" \
    | head -n1 \
    | tr -d '" ,'
}

install_bin() {
  local dir="$1"

  mkdir -p "$dir"

  for bin in "${BINARIES[@]}"; do
    if [[ -f "$bin" ]]; then
      cp "$bin" "$dir/"
      chmod +x "$dir/$bin"
      log "Installed $bin -> $dir"
    fi
  done
}

ensure_path() {
  if ! echo "$PATH" | grep -q "$INSTALL_DIR_USER"; then
    log "Add this to your shell profile:"
    echo "export PATH=\"$INSTALL_DIR_USER:\$PATH\""
  fi
}

# -------------------------
# Install / Upgrade
# -------------------------

do_install() {
  detect_platform

  TAG="${1:-}"
  if [[ -z "$TAG" ]]; then
    TAG=$(get_latest_tag)
  fi

  log "Installing version: $TAG"
  log "Platform: $PLATFORM"

  URL=$(get_download_url "$TAG")

  if [[ -z "$URL" ]]; then
    log "Failed to find release asset for $PLATFORM"
    exit 1
  fi

  TMP=$(mktemp -d)
  cd "$TMP"

  log "Downloading $URL"
  curl -L -o release.tar.gz "$URL"

  tar -xzf release.tar.gz

  # choose install dir
  if [[ -w "$INSTALL_DIR_DEFAULT" ]]; then
    INSTALL_DIR="$INSTALL_DIR_DEFAULT"
  else
    INSTALL_DIR="$INSTALL_DIR_USER"
  fi

  install_bin "$INSTALL_DIR"
  ensure_path

  echo "$TAG" > "$MARKER_FILE"

  rm -rf "$TMP"

  log "Installed successfully ($TAG)"
}

# -------------------------
# Upgrade
# -------------------------

do_upgrade() {
  if [[ ! -f "$MARKER_FILE" ]]; then
    log "Not installed. Run: install"
    exit 1
  fi

  CURRENT=$(cat "$MARKER_FILE")
  LATEST=$(get_latest_tag)

  log "Current: $CURRENT"
  log "Latest:  $LATEST"

  if [[ "$CURRENT" == "$LATEST" ]]; then
    log "Already up to date"
    exit 0
  fi

  do_install "$LATEST"
}

# -------------------------
# Uninstall
# -------------------------

do_uninstall() {
  log "Uninstalling..."

  for dir in "$INSTALL_DIR_DEFAULT" "$INSTALL_DIR_USER"; do
    for bin in "${BINARIES[@]}"; do
      if [[ -f "$dir/$bin" ]]; then
        rm -f "$dir/$bin"
        log "Removed $dir/$bin"
      fi
    done
  done

  rm -f "$MARKER_FILE"

  log "Uninstall complete"
}

# -------------------------
# CLI
# -------------------------

case "${1:-install}" in
  install)
    do_install "${2:-}"
    ;;
  upgrade)
    do_upgrade
    ;;
  uninstall)
    do_uninstall
    ;;
  *)
    echo "Usage:"
    echo "  $0 install [version]"
    echo "  $0 upgrade"
    echo "  $0 uninstall"
    exit 1
    ;;
esac