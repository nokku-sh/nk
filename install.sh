#!/usr/bin/env bash

set -euo pipefail

REPO="nokku-sh/nk"
BINARY_NAME="nk"

DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_INSTALL_DIR="/usr/local/bin"
INSTALL_DIR="$DEFAULT_INSTALL_DIR"

# Allow system-wide install with flag
if [[ "${1:-}" == "--system" ]]; then
   INSTALL_DIR="$SYSTEM_INSTALL_DIR"
fi

# Detect OS
OS=$(uname -s)
case "$OS" in
Linux*) GOOS="linux" ;;
Darwin*) GOOS="darwin" ;;
FreeBSD*) GOOS="freebsd" ;;
MINGW* | MSYS* | CYGWIN*)
   echo "Detected Windows environment."
   echo
   echo "⚠️  This install script is for Unix-like systems."
   echo "If you're using PowerShell or CMD, please download manually from:"
   echo "  https://github.com/${REPO}/releases/latest"
   echo
   echo "If you're using Git Bash or WSL, rerun this script there."
   exit 0
   ;;
*)
   echo "Unsupported OS: $OS" >&2
   exit 1
   ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
x86_64 | amd64) ARCH="amd64" ;;
arm64 | aarch64) ARCH="arm64" ;;
*)
   echo "Unsupported architecture: $ARCH" >&2
   exit 1
   ;;
esac

# Determine version
if [ -z "${NK_VERSION:-}" ]; then
   echo "Fetching latest version of $BINARY_NAME..."
   NK_VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -oP '"tag_name":\s*"\K(.*)(?=")')
fi
if [ -z "$NK_VERSION" ]; then
   echo "Failed to determine latest version." >&2
   exit 1
fi

echo "Installing ${BINARY_NAME} ${NK_VERSION} for ${GOOS}/${ARCH}"

# Construct download URL
ASSET_URL="https://github.com/${REPO}/releases/download/${NK_VERSION}/${BINARY_NAME}_${GOOS}_${ARCH}.tar.gz"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading from ${ASSET_URL}..."
curl -fsSL -o "${TMP_DIR}/${BINARY_NAME}" "$ASSET_URL"

chmod +x "${TMP_DIR}/${BINARY_NAME}"

mkdir -p "$INSTALL_DIR"

# Always overwrite old binary
if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
   echo "Replacing existing ${BINARY_NAME} in ${INSTALL_DIR}..."
   if [ "$INSTALL_DIR" = "$SYSTEM_INSTALL_DIR" ]; then
      sudo mv -f "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
   else
      mv -f "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
   fi
else
   if [ "$INSTALL_DIR" = "$SYSTEM_INSTALL_DIR" ]; then
      echo "Installing to ${INSTALL_DIR} (requires sudo)..."
      sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
   else
      mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/"
   fi
fi

# PATH check
if ! command -v "${BINARY_NAME}" >/dev/null 2>&1; then
   echo
   echo "⚠️  ${BINARY_NAME} is not in your PATH."
   echo "Add this line to your shell config (e.g. ~/.bashrc or ~/.zshrc):"
   echo "    export PATH=\"\$PATH:${DEFAULT_INSTALL_DIR}\""
fi

echo
echo "Installed ${BINARY_NAME} ${NK_VERSION} to ${INSTALL_DIR}"
echo "Run '${BINARY_NAME} --help' to get started."
