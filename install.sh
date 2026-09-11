#!/bin/sh
set -eu

# nk: Nokku CLI installer
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

# Accept both v1.2.3 and 1.2.3.
VERSION="${VERSION#v}"

have() { command -v "$1" >/dev/null 2>&1; }

if ! have curl; then
	echo "error: curl is required but was not found on PATH" >&2
	exit 1
fi

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

	# Cloudsmith's repo config pins sslcacert=/etc/pki/tls/certs/ca-bundle.crt,
	# which Fedora 44+ no longer ships; drop it so dnf uses its default CA store.
	if [ "$PM" = rpm ]; then
		for repo in /etc/yum.repos.d/nokku-*.repo; do
			[ -f "$repo" ] || continue
			ssl_ca=$(sed -n 's/^sslcacert=//p' "$repo" | head -n 1)
			if [ -n "$ssl_ca" ] && [ ! -e "$ssl_ca" ]; then
				echo "note: $repo pins a CA bundle that does not exist; removing sslcacert."
				as_root sed -i '/^sslcacert=/d' "$repo"
			fi
		done
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

	pkg_installed=false
	case "$PM" in
	deb) dpkg -s "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	rpm) rpm -q "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	alpine) apk info -e "$BINARY_NAME" >/dev/null 2>&1 && pkg_installed=true ;;
	esac

	if [ "$pkg_installed" != true ] || ! have "$BINARY_NAME"; then
		echo "warning: '${BINARY_NAME}' is not on PATH after the package install; falling back to the GitHub binary." >&2
		rm -rf "$TMP_DIR"
		return 1
	fi

	rm -rf "$TMP_DIR"
	echo "Installed ${BINARY_NAME} from the Cloudsmith repository."
	return 0
}

# sha256 prints the SHA-256 of a file using whichever tool is available.
sha256() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		echo "error: no SHA-256 tool found (need sha256sum, shasum, or openssl)" >&2
		return 1
	fi
}

# verify_binary checks a downloaded file against the release checksum manifest.
# The manifest is the artifact GoReleaser signs with cosign, so a mismatch means
# the download is not what was published.
verify_binary() {
	FILE="$1"
	ASSET="$2"

	if ! curl -fsSL -o "${TMP_DIR}/nk_checksums.txt" "$CHECKSUM_URL"; then
		echo "error: cannot download ${CHECKSUM_URL}" >&2
		return 1
	fi

	WANT=$(awk -v name="$ASSET" '$2 == name { print $1 }' "${TMP_DIR}/nk_checksums.txt")
	if [ -z "$WANT" ]; then
		echo "error: ${ASSET} is not listed in nk_checksums.txt" >&2
		return 1
	fi

	GOT=$(sha256 "$FILE") || return 1
	if [ "$WANT" != "$GOT" ]; then
		echo "error: checksum mismatch for ${ASSET}" >&2
		echo "  expected ${WANT}" >&2
		echo "  got      ${GOT}" >&2
		return 1
	fi
	echo "Verified ${ASSET}."
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
	riscv64)
		if [ "$GOOS" != linux ]; then
			echo "error: no ${GOOS}/riscv64 build is published" >&2
			exit 1
		fi
		GOARCH=riscv64
		;;
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

	ASSET="${BINARY_NAME}_${GOOS}_${GOARCH}"
	if [ -n "$VERSION" ]; then
		BASE="https://github.com/${GH_REPO}/releases/download/v${VERSION}"
	else
		BASE="https://github.com/${GH_REPO}/releases/latest/download"
	fi
	URL="${BASE}/${ASSET}"
	CHECKSUM_URL="${BASE}/nk_checksums.txt"

	TMP_DIR=$(mktemp -d) || {
		echo "error: cannot create a temporary directory (check TMPDIR)" >&2
		exit 1
	}
	STAGE=""
	trap 'rm -rf "$TMP_DIR"; [ -n "$STAGE" ] && rm -f "$STAGE"' EXIT

	echo "Downloading ${BINARY_NAME} (${GOOS}/${GOARCH}) from GitHub..."
	curl -fsSL -o "${TMP_DIR}/${BINARY_NAME}" "$URL"
	verify_binary "${TMP_DIR}/${BINARY_NAME}" "$ASSET"
	chmod 0755 "${TMP_DIR}/${BINARY_NAME}"

	if [ "$INSTALL_DIR" = "$SYSTEM_INSTALL_DIR" ]; then
		as_root mkdir -p "$INSTALL_DIR"
	else
		mkdir -p "$INSTALL_DIR"
	fi

	# Stage inside the destination directory, so the final step is a rename on
	# one filesystem and an interrupted copy cannot leave a partial binary in
	# place.
	STAGE="${INSTALL_DIR}/.${BINARY_NAME}.tmp.$$"
	if [ "$INSTALL_DIR" = "$SYSTEM_INSTALL_DIR" ]; then
		as_root cp -f "${TMP_DIR}/${BINARY_NAME}" "$STAGE"
		as_root mv -f "$STAGE" "${INSTALL_DIR}/${BINARY_NAME}"
	else
		cp -f "${TMP_DIR}/${BINARY_NAME}" "$STAGE"
		mv -f "$STAGE" "${INSTALL_DIR}/${BINARY_NAME}"
	fi
	STAGE=""

	echo "Installed ${BINARY_NAME} to ${INSTALL_DIR}"
	if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
		echo "Add ${INSTALL_DIR} to your PATH."
	fi
}

if [ "$(uname -s)" = "Linux" ] && install_package; then
	exit 0
fi

install_binary
