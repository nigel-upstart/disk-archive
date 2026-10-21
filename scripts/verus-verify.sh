#!/usr/bin/env bash
# Verify the actual production kernels with the separately pinned Verus toolchain.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# LINT-JUSTIFICATION: Runtime-relative pin data is tested by the verifier, not statically sourced.
# shellcheck source=/dev/null
source "$root/tools/verus.env"
tools="${DISK_ARCHIVE_TOOLS_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/disk-archive/tools}"
# Resolve relative overrides before verification changes into its temporary directory.
[[ "$tools" = /* ]] || tools="$PWD/$tools"
case "$(uname -s)/$(uname -m)" in
Darwin/arm64) platform=arm64-macos ;;
Linux/x86_64) platform=x86-linux ;;
*)
	echo "Unsupported Verus host" >&2
	exit 1
	;;
esac
export RUSTUP_HOME="$tools/rustup" CARGO_HOME="$tools/cargo"
export RUSTUP_TOOLCHAIN="$VERUS_RUST_VERSION" PATH="$CARGO_HOME/bin:$PATH"
verus="$tools/verus-$VERUS_VERSION/verus-$platform/verus"
if [[ ! -x "$verus" ]] || [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
	echo "Verus missing: run scripts/verus-install.sh (proofs never silently skipped)" >&2
	exit 1
fi
installed="$("$CARGO_HOME/bin/rustup" --version)"
if [[ "$installed" != "rustup $RUSTUP_VERSION ("* ]]; then
	echo "Dedicated rustup version mismatch; expected $RUSTUP_VERSION" >&2
	exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Prevent compiler/proof output from landing in the source tree.
cd "$work"
python3 -B "$root/scripts/verify-kernels.py" "$verus"
# The same sources compile/test as ordinary Rust, without Cargo dependencies or Verus cfg.
rustup run "$VERUS_RUST_VERSION" rustc --edition=2024 --crate-type lib \
	"$root/crates/verified/src/lib.rs" -o "$work/reference.rlib"
rustup run "$VERUS_RUST_VERSION" rustc --edition=2024 --test \
	"$root/crates/verified/src/lib.rs" -o "$work/reference-tests"
"$work/reference-tests"
echo "Production kernel proofs and semantic negative controls passed; pinned Rust tests passed"
