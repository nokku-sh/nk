#!/bin/sh
set -eu

# nk — Nokku CLI installer
#
# Preferred: sets up the Cloudsmith repository for your distro's package
# manager and installs the nk package (deb/rpm/apk).
# Fallback: downloads the release binary from GitHub for macOS, unsupported
# Linux distros, pinned versions, or while the Cloudsmith repo is not live.

BINARY_NAME="nk"
GH_REPO="nokku-sh/nk"
CS_OWNER="nokku"
CS_REPO="nk"

DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_INSTALL_DIR="/usr/local/bin"

SYSTEM=false
VERSION="${NK_VERSION:-}"

usage() {
	cat <<EOF
Usage: $0 [--system] [--version <x.y.z>]

  --system          Install system-wide (binary fallback only)
  --version <ver>   Pin a specific version; forces the binary fallback
  -h, --help        Show this help

Equivalent environment variable: NK_VERSION
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--system)
		SYSTEM=true
		;;
	--version)
		[ "$#" -ge 2 ] || {
			echo "error: --version requires a value" >&2
			exit 1
		}
		VERSION="$2"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
	shift
done

have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		command sudo -E "$@"
	fi
}

# Install via the distro package manager from Cloudsmith.
# Returns 0 only if the binary is found on PATH afterwards.
install_package() {
	[ -z "$VERSION" ] || return 1

	case " $(command -v apt-get dnf yum zypper apk) " in
	*apt-get*) PM=deb ;;
	*dnf* | *yum* | *zypper*) PM=rpm ;;
	*apk*) PM=alpine ;;
	*) return 1 ;;
	esac

	TMP_DIR=$(mktemp -d)

	if ! curl -fsSL "https://dl.cloudsmith.io/public/${CS_OWNER}/${CS_REPO}/setup.${PM}.sh" -o "${TMP_DIR}/setup.sh"; then
		echo "warning: Cloudsmith repository is not available yet; falling back to the GitHub binary." >&2
		rm -rf "$TMP_DIR"
		return 1
	fi

	if have bash; then
		if ! as_root bash "${TMP_DIR}/setup.sh"; then
			echo "warning: could not configure the Cloudsmith repository; falling back to the GitHub binary." >&2
			rm -rf "$TMP_DIR"
			return 1
		fi
	else
		if ! as_root sh "${TMP_DIR}/setup.sh"; then
			echo "warning: could not configure the Cloudsmith repository; falling back to the GitHub binary." >&2
			rm -rf "$TMP_DIR"
			return 1
		fi
	fi

	case "$PM" in
	deb)
		as_root apt-get install -y "$BINARY_NAME"
		;;
	rpm)
		if have dnf; then
			as_root dnf install -y "$BINARY_NAME"
		elif have yum; then
			as_root yum install -y "$BINARY_NAME"
		else
			as_root zypper install -y "$BINARY_NAME"
		fi
		;;
	alpine)
		as_root apk add "$BINARY_NAME"
		;;
	esac

	if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
		echo "warning: package install did not put '${BINARY_NAME}' on PATH; falling back to the GitHub binary." >&2
		rm -rf "$TMP_DIR"
		return 1
	fi

	rm -rf "$TMP_DIR"
	echo "Installed ${BINARY_NAME} from the Cloudsmith repository."
	return 0
}

# Download the release binary from GitHub.
install_binary() {
	OS=$(uname -s)
	case "$OS" in
	Linux) GOOS=linux ;;
	Darwin) GOOS=darwin ;;
	MINGW* | MSYS* | CYGWIN*)
		echo "This installer targets Unix-like systems."
		echo "On Windows, download the binary from https://github.com/${GH_REPO}/releases/latest"
		exit 0
		;;
	*)
		echo "error: unsupported OS: $OS" >&2
		exit 1
		;;
	esac

	ARCH=$(uname -m)
	case "$ARCH" in
	x86_64 | amd64) GOARCH=amd64 ;;
	arm64 | aarch64) GOARCH=arm64 ;;
	riscv64) GOARCH=riscv64 ;;
	*)
		echo "error: unsupported architecture: $ARCH" >&2
		exit 1
		;;
	esac

	if [ "$SYSTEM" = true ]; then
		INSTALL_DIR="$SYSTEM_INSTALL_DIR"
	else
		INSTALL_DIR="$DEFAULT_INSTALL_DIR"
	fi

	if [ -n "$VERSION" ]; then
		URL="https://github.com/${GH_REPO}/releases/download/v${VERSION}/${BINARY_NAME}_${GOOS}_${GOARCH}"
	else
		URL="https://github.com/${GH_REPO}/releases/latest/download/${BINARY_NAME}_${GOOS}_${GOARCH}"
	fi

	TMP_DIR=$(mktemp -d)
	trap 'rm -rf "$TMP_DIR"' EXIT

	echo "Downloading ${BINARY_NAME} (${GOOS}/${GOARCH}) from GitHub..."
	curl -fsSL -o "${TMP_DIR}/${BINARY_NAME}" "$URL"
	chmod +x "${TMP_DIR}/${BINARY_NAME}"

	mkdir -p "$INSTALL_DIR"
	if [ "$INSTALL_DIR" = "$SYSTEM_INSTALL_DIR" ]; then
		as_root mv -f "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
	else
		mv -f "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
	fi

	echo "Installed ${BINARY_NAME} to ${INSTALL_DIR}"
	if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
		echo "Add ${INSTALL_DIR} to your PATH."
	fi
}

if [ "$(uname -s)" = "Linux" ] && install_package; then
	exit 0
fi

install_binary
