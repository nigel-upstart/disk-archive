"""Fail-closed repository and dependency policy; never execute dotenv content."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tomllib

GIT_SOURCES = {
    "https://github.com/awslabs/aws-s3-transfer-manager-rs",
    "https://github.com/mongodb/kingfisher",
}
MAX_FILE_BYTES = 1024 * 1024


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def dotenv_values(content: str) -> list[str]:
    """Accept literal single-line dotenv values, reject ambiguous syntax safely."""
    values = []
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.*)", line)
        if not match:
            raise ValueError(f"unsupported .env syntax at line {number}")
        value = match[1]
        if value.startswith(("'", '"')):
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0 or (value[end + 1 :].strip() and not value[end + 1 :].strip().startswith("#")):
                raise ValueError(f"unsupported .env quoting at line {number}")
            value = value[1:end]
            # Reject interpolation/escapes instead of silently checking the wrong value.
            if quote == '"' and ("\\" in value or "$" in value):
                raise ValueError(f"use literal single quotes in .env at line {number}")
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
            if any(char in value for char in ("$", "\\", "'", '"')):
                raise ValueError(f"use literal single quotes in .env at line {number}")
        if value:
            values.append(value)
    return values


def forbidden_path(name: str) -> bool:
    path = pathlib.PurePosixPath(name)
    return any(part == ".env" or (part.startswith(".env.") and part != ".env.example") for part in path.parts)


def check_content(name: str, content: bytes, values: list[str]) -> None:
    if forbidden_path(name):
        raise ValueError(f"refusing tracked dotenv file: {name}")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds 1 MiB limit: {name}")
    if any(value.encode() in content for value in values):
        # Deliberately never print the value, key, or matching line.
        raise ValueError(f"local .env value found in staged/tracked content: {name}")


def check_files(staged: bool) -> None:
    env = pathlib.Path(".env")
    if env.is_symlink():
        raise ValueError("refusing symlink .env; use a local literal dotenv file")
    values = dotenv_values(env.read_text()) if env.exists() else []
    if staged:
        names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\0")
    else:
        names = git("ls-files", "-z").split(b"\0")
    for raw in filter(None, names):
        name = raw.decode("utf-8", "surrogateescape")
        content = git("show", ":" + name)
        check_content(name, content, values)


def check_manifest(path: pathlib.Path) -> None:
    data = tomllib.loads(path.read_text())
    if path.parent.name == "verified":
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            if data.get(section) or any(target.get(section) for target in data.get("target", {}).values()):
                raise ValueError("verified must have zero dependencies, including target/dev/build dependencies")
    tables = [data, *data.get("target", {}).values(), data.get("workspace", {})]
    for table in tables:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in table.get(section, {}).items():
                if isinstance(spec, dict) and "git" in spec:
                    if spec["git"] not in GIT_SOURCES or not re.fullmatch(r"[a-f0-9]{40}", spec.get("rev", "")):
                        raise ValueError(f"unapproved git source or non-immutable revision: {name}")
                    if "tag" in spec or "branch" in spec:
                        raise ValueError(f"git source cannot specify tag/branch: {name}")
                    notes = pathlib.Path("docs/dependencies.md")
                    if not notes.is_file() or spec["rev"] not in notes.read_text():
                        raise ValueError(f"git dependency needs an upstream-tracking note in docs/dependencies.md: {name}")


def check_workspace() -> None:
    for path in [pathlib.Path("Cargo.toml"), *pathlib.Path("crates").glob("*/Cargo.toml")]:
        check_manifest(path)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked"]))
    for package in metadata["packages"]:
        source = package.get("source") or ""
        if source.startswith("git+"):
            url, _, query = source[4:].partition("?")
            revision = re.fullmatch(r"rev=([a-f0-9]{40})#([a-f0-9]{40})", query)
            if url not in GIT_SOURCES or not revision or revision[1] != revision[2]:
                raise ValueError("resolved git dependency is not an approved immutable revision")
    verified = pathlib.Path("crates/verified/Cargo.toml")
    if verified.exists():
        isolated = json.loads(subprocess.check_output([
            "cargo", "metadata", "--manifest-path", str(verified), "--format-version", "1", "--no-deps",
        ]))
        for package in isolated["packages"]:
            if pathlib.Path(package["manifest_path"]).resolve() == verified.resolve() and package["dependencies"]:
                raise ValueError("verified metadata must contain zero dependencies")
    for node in metadata["resolve"]["nodes"]:
        package = next(package for package in metadata["packages"] if package["id"] == node["id"])
        if package["name"] == "aws-config" and "credentials-process" in node["features"]:
            raise ValueError("aws-config credentials-process must remain disabled, including transitive features")


def check_toolchain() -> None:
    pin = tomllib.loads(pathlib.Path("rust-toolchain.toml").read_text())["toolchain"]["channel"]
    actual = subprocess.check_output(["rustc", "--version"], text=True).split()[1]
    if actual != pin:
        raise ValueError(f"Rust version mismatch: expected {pin}, got {actual}; install pinned toolchain")


def main() -> None:
    mode = sys.argv[1]
    if mode in ("staged", "tracked"):
        check_files(mode == "staged")
    elif mode == "workspace":
        check_workspace()
    elif mode == "toolchain":
        check_toolchain()
    else:
        raise ValueError("unknown policy mode")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"policy: {error}", file=sys.stderr)
        sys.exit(1)
