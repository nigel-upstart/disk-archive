#!/usr/bin/env bash
set -euo pipefail
case ${1:?gate required} in
fmt)
	cargo fmt --all --check
	taplo fmt --check
	shfmt -d scripts/*.sh
	;;
lint)
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	ast-grep scan
	ast-grep test
	python3 scripts/policy.py workspace
	typos
	shellcheck scripts/*.sh
	actionlint
	zizmor --offline --no-progress .github/workflows
	;;
test)
	cargo nextest run --workspace --all-features --locked
	cargo test --workspace --doc --all-features --locked
	python3 -B -m unittest discover -s scripts/tests -v
	;;
coverage)
	cargo llvm-cov --workspace --all-features --locked --fail-under-lines 90 --ignore-filename-regex 'crates/archiver/src/main.rs' --lcov --output-path target/coverage.lcov
	;;
supply-chain)
	python3 scripts/policy.py workspace
	cargo deny check
	cargo machete
	;;
secrets)
	python3 scripts/policy.py staged
	gitleaks git --staged --redact --no-banner
	;;
ci-secrets)
	python3 scripts/policy.py tracked
	gitleaks git --redact --no-banner
	;;
parity)
	# Golden parity is introduced by A/D; absence is not represented as a passing test.
	if [[ -f scripts/golden-parity.sh ]]; then
		bash scripts/golden-parity.sh
	else
		printf 'Golden Rust parity not implemented yet (wave D); synthetic fixtures remain with A.\n'
	fi
	;;
*)
	printf 'unknown gate: %s\n' "$1" >&2
	exit 2
	;;
esac
