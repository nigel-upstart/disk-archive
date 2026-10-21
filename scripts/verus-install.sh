#!/usr/bin/env bash
# Install only into a dedicated development-tools directory; never modify shell profiles.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# LINT-JUSTIFICATION: Runtime-relative pin data is tested by the verifier, not statically sourced.
# shellcheck source=/dev/null
source "$root/tools/verus.env"
tools="${DISK_ARCHIVE_TOOLS_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/disk-archive/tools}"
case "$(uname -s)/$(uname -m)" in
Darwin/arm64)
	platform=arm64-macos
	triple=aarch64-apple-darwin
	verus_sha="$VERUS_MAC_ARM_SHA256"
	rustup_sha="$RUSTUP_MAC_ARM_SHA256"
	;;
Linux/x86_64)
	platform=x86-linux
	triple=x86_64-unknown-linux-gnu
	verus_sha="$VERUS_LINUX_X86_SHA256"
	rustup_sha="$RUSTUP_LINUX_X86_SHA256"
	;;
*)
	echo "Unsupported Verus host; supported: macOS arm64, Linux x86_64" >&2
	exit 1
	;;
esac
export RUSTUP_HOME="$tools/rustup" CARGO_HOME="$tools/cargo"
mkdir -p "$tools/downloads" "$RUSTUP_HOME" "$CARGO_HOME"
check_sha() {
	local file="$1" expected="$2" actual
	if command -v sha256sum >/dev/null; then
		actual="$(sha256sum "$file")"
	else
		actual="$(shasum -a 256 "$file")"
	fi
	[[ "${actual%% *}" == "$expected" ]]
}
fetch() {
	local url="$1" destination="$2" expected="$3"
	if [[ ! -f "$destination" ]] || ! check_sha "$destination" "$expected"; then
		curl --proto '=https' --tlsv1.2 --fail --location --retry 3 "$url" -o "$destination.part"
		check_sha "$destination.part" "$expected" || {
			echo "SHA256 mismatch: $destination" >&2
			return 1
		}
		mv "$destination.part" "$destination"
	fi
}
fetch "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$triple/rustup-init" \
	"$tools/downloads/rustup-init-$triple" "$rustup_sha"
chmod +x "$tools/downloads/rustup-init-$triple"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
	"$tools/downloads/rustup-init-$triple" -y --no-modify-path --default-toolchain none
fi
export PATH="$CARGO_HOME/bin:$PATH"
rustup toolchain install "$VERUS_RUST_VERSION" --profile minimal --no-self-update
archive="verus-$VERUS_VERSION-$platform.zip"
fetch "https://github.com/verus-lang/verus/releases/download/release%2F$VERUS_VERSION/$archive" \
	"$tools/downloads/$archive" "$verus_sha"
install="$tools/verus-$VERUS_VERSION"
if [[ ! -x "$install/verus-$platform/verus" ]]; then
	mkdir -p "$install"
	unzip -q "$tools/downloads/$archive" -d "$install"
fi
RUSTUP_TOOLCHAIN="$VERUS_RUST_VERSION" "$install/verus-$platform/verus" --version
echo "Verus installed in $install; global Rust and shell profiles unchanged"
