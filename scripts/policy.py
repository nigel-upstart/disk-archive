"""Fail-closed repository and dependency policy; never execute dotenv content."""

from __future__ import annotations

import hashlib
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
ROOT = pathlib.Path(__file__).resolve().parents[1]
TM_SOURCE = "https://github.com/awslabs/aws-s3-transfer-manager-rs"
TM_REVISION = "dc391970cd36e0d6d6ed044dcb3351b26131e9be"
TM_RECEIPT_SHA256 = "6f80f3b928a2d909c8c2b012920c141961bece253f8449b99e65625d50d21a00"
TM_PATCHES = {
    "aws-sdk-s3-transfer-manager": "vendor/transfer-manager/aws-sdk-s3-transfer-manager",
    "s3-mock-server": "vendor/transfer-manager/s3-mock-server",
}


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
    # Intentionally cover every nonempty literal, including short/common values.
    # False positives are preferable to silently exempting a local configuration value.
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
    # Do not turn a single audited upstream manifest fix into a general path escape.
    for source, declaration in data.get("patch", {}).items():
        for name, spec in declaration.items():
            if isinstance(spec, dict) and "path" in spec:
                if path.resolve() != ROOT / "Cargo.toml" or source != TM_SOURCE or spec != {"path": TM_PATCHES.get(name)}:
                    raise ValueError("unapproved path patch; only the exact audited transfer-manager patch is allowed")
    if any(isinstance(spec, dict) and "path" in spec for spec in data.get("replace", {}).values()):
        raise ValueError("path replacements are not approved")
    if "package" in data and data.get("lints", {}).get("workspace") is not True:
        raise ValueError(f"workspace packages must inherit strict lints: {path}")
    if path.parent.name == "verified":
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            if data.get(section) or any(target.get(section) for target in data.get("target", {}).values()):
                raise ValueError("verified must have zero dependencies, including target/dev/build dependencies")
    tables = [data, *data.get("target", {}).values(), data.get("workspace", {})]
    declarations = [
        table.get(section, {})
        for table in tables
        for section in ("dependencies", "dev-dependencies", "build-dependencies")
    ]
    declarations.extend(data.get("patch", {}).values())
    declarations.append(data.get("replace", {}))
    for declaration in declarations:
        for name, spec in declaration.items():
            if isinstance(spec, dict) and "git" in spec:
                if spec["git"] not in GIT_SOURCES or not re.fullmatch(r"[a-f0-9]{40}", spec.get("rev", "")):
                    raise ValueError(f"unapproved git source or non-immutable revision: {name}")
                if "tag" in spec or "branch" in spec:
                    raise ValueError(f"git source cannot specify tag/branch: {name}")
                notes = pathlib.Path("docs/dependencies.md")
                if not notes.is_file() or spec["rev"] not in notes.read_text():
                    raise ValueError(f"git dependency needs an upstream-tracking note in docs/dependencies.md: {name}")


def check_vendor(root: pathlib.Path = ROOT) -> None:
    """Verify exact upstream bytes and the only admitted manifest transformations."""
    vendor = root / "vendor/transfer-manager"
    receipt_bytes = (vendor / "provenance.json").read_bytes()
    if hashlib.sha256(receipt_bytes).hexdigest() != TM_RECEIPT_SHA256:
        raise ValueError("transfer-manager admission receipt changed; requires a reviewed pin/policy update")
    receipt = json.loads(receipt_bytes)
    if receipt["revision"] != TM_REVISION or receipt["upstream"] != TM_SOURCE:
        raise ValueError("unexpected transfer-manager provenance")
    files = receipt["source_files"]
    expected_paths = set(files) | {"provenance.json", "UPSTREAM-Cargo.toml"}
    actual_paths = set()
    for path in vendor.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("vendor tree must contain only regular files/directories")
        if path.is_file():
            actual_paths.add(path.relative_to(vendor).as_posix())
    if actual_paths != expected_paths:
        raise ValueError("unexpected/missing transfer-manager vendor file")
    original = (vendor / "UPSTREAM-Cargo.toml").read_bytes()
    if hashlib.sha256(original).hexdigest() != files["Cargo.toml"]:
        raise ValueError("upstream workspace manifest provenance mismatch")
    patched = original.decode().replace('    "benches",\n', '').replace('    "integration-tests"\n', '')
    patched = patched.replace('aws-config = "1.12.0"', 'aws-config = { version = "1.12.0", default-features = false, features = ["default-https-client", "rt-tokio", "sso"] }')
    if (vendor / "Cargo.toml").read_bytes() != patched.encode():
        raise ValueError("unapproved transfer-manager manifest patch")
    if hashlib.sha256(patched.encode()).hexdigest() != receipt["patched_workspace_sha256"]:
        raise ValueError("patched workspace receipt mismatch")
    for name, digest in files.items():
        if name != "Cargo.toml" and hashlib.sha256((vendor / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"upstream source changed: {name}")


def check_workspace() -> None:
    if (ROOT / "vendor/transfer-manager").exists():
        check_vendor()
    for path in [pathlib.Path("Cargo.toml"), *pathlib.Path("crates").glob("*/Cargo.toml")]:
        check_manifest(path)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked", "--all-features"]))
    for package in metadata["packages"]:
        source = package.get("source") or ""
        if source.startswith("git+"):
            url, _, query = source[4:].partition("?")
            revision = re.fullmatch(r"rev=([a-f0-9]{40})#([a-f0-9]{40})", query)
            if url not in GIT_SOURCES or not revision or revision[1] != revision[2]:
                raise ValueError("resolved git dependency is not an approved immutable revision")
            notes = pathlib.Path("docs/dependencies.md")
            if not notes.is_file() or revision[1] not in notes.read_text():
                raise ValueError("resolved git dependency needs an upstream-tracking note in docs/dependencies.md")
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
    elif mode == "vendor":
        check_vendor()
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
