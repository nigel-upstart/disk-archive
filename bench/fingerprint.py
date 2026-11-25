"""Public build/runner fingerprint only; never read dotenv, credentials or inputs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tomllib


BUILD_FLAGS = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CFLAGS", "CXXFLAGS", "CC", "CXX", "CARGO_INCREMENTAL", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")
# Every profile override (debug-assertions, overflow-checks, lto, ...), target
# rustflags/linkers and build settings can change generated code. Prefixes, not
# an allowlist, so a new override cannot silently share a fingerprint.
BUILD_PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")
# Scheduling/output locations that never affect generated instructions.
NON_CODEGEN = {"CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_BUILD_TARGET_DIR"}
CONFIG_FILES = (".cargo/config.toml", ".cargo/config")
CACHE_CONFIGURATION = "I1=32768,8,64;D1=32768,8,64;LL=8388608,16,64;cache-sim=yes;separate-threads=no"


def tool(command: list[str], root: Path) -> str:
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def rules_revision(root: Path) -> str:
    manifest = tomllib.loads((root / "crates/scanner/Cargo.toml").read_text())
    revision = manifest["dependencies"]["kingfisher-scanner"]["rev"]
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("scanner revision is not immutable")
    return revision


def build_variable(name: str) -> bool:
    return name not in NON_CODEGEN and (name in BUILD_FLAGS or name.startswith(BUILD_PREFIXES))


def build_configuration(root: Path) -> str:
    """Committed/user Cargo settings that alter codegen: root profiles and config files."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    parts = ["profile=" + json.dumps(manifest.get("profile", {}), sort_keys=True)]
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for path in [root / name for name in CONFIG_FILES] + [home / "config.toml", home / "config"]:
        if path.is_file():
            parts.append(path.name + "=" + hashlib.sha256(path.read_bytes()).hexdigest())
    return "\0".join(parts)


def flag_digest(environment: dict[str, str], configuration: str = "") -> str:
    # Compiler arguments and config can contain local paths. Hash only the
    # build-affecting fields; never persist them or an environment dump.
    fields = sorted((name, value) for name, value in environment.items() if build_variable(name))
    value = "\0".join(name + "=" + item for name, item in fields) + "\0\0" + configuration
    return hashlib.sha256(value.encode()).hexdigest()


def collect(root: Path, *, profile: str = "bench") -> dict[str, object]:
    compiler = tool(["rustc", "-vV"], root)
    fields = dict(line.split(": ", 1) for line in compiler.splitlines() if ": " in line)
    if "LLVM version" not in fields or "host" not in fields:
        raise ValueError("compiler fingerprint incomplete")
    commit = tool(["git", "rev-parse", "HEAD"], root)
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("invalid source revision")
    dirty = bool(tool(["git", "status", "--porcelain", "--untracked-files=normal"], root))
    if platform.system() == "Linux":
        lines = Path("/proc/cpuinfo").read_text().splitlines()
        model = next(line.split(":", 1)[1].strip() for line in lines if line.startswith("model name"))
        memory_line = next(line for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
        memory = int(memory_line.split()[1]) * 1024
        processors = len(os.sched_getaffinity(0))
    elif platform.system() == "Darwin":
        model = tool(["sysctl", "-n", "machdep.cpu.brand_string"], root)
        memory = int(tool(["sysctl", "-n", "hw.memsize"], root))
        processors = os.cpu_count()
    else:
        raise ValueError("unsupported measurement platform")
    target = os.environ.get("CARGO_BUILD_TARGET", fields["host"])
    if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
        raise ValueError("custom target specs need an explicit non-path fingerprint")
    if profile not in ("bench", "release", "profiling"):
        raise ValueError("unknown measurement profile")
    return {
        "source_commit": commit,
        "source_dirty": dirty,
        "runner_image": os.environ.get("ImageOS", platform.system()),
        "runner_image_version": os.environ.get("ImageVersion", "local-advisory"),
        "nproc": processors,
        "memory_bytes": memory,
        "cpu_model": model,
        "kernel": platform.release(),
        "rustc": compiler,
        "llvm": fields["LLVM version"],
        "target": target,
        "flags": flag_digest(dict(os.environ), build_configuration(root)),
        "profile": profile,
        "valgrind": tool(["valgrind", "--version"], root),
        "gungraun": tool(["gungraun-runner", "--version"], root),
        "cache_configuration": CACHE_CONFIGURATION,
        "rules_revision": rules_revision(root),
        "corpus_revision": hashlib.sha256((root / "bench/corpus.py").read_bytes()).hexdigest(),
    }
