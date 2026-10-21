"""Fail if optional exporters/console/heap reach the ordinary application graph."""
from __future__ import annotations

import subprocess

FORBIDDEN = {"tracing-chrome", "tracing-subscriber", "console-subscriber", "console-api", "dhat"}


def main() -> None:
    for package in ("disk-archive", "disk-archive-profiling"):
        output = subprocess.check_output([
            "cargo", "tree", "--locked", "--edges", "normal", "--prefix", "none",
            "--format", "{p}", "-p", package,
        ], text=True)
        names = {line.split()[0] for line in output.splitlines() if line.strip()}
        if names & FORBIDDEN:
            raise ValueError("optional profiling dependency reached the default graph")
    print("Default application and profiling helper graphs contain no optional exporters")


if __name__ == "__main__":
    main()
