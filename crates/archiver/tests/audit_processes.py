#!/usr/bin/env python3
"""Linux-only OS audit of the SYNTHETIC native/HTTP test; never launch real inputs.

The strace/harness launch is outside the measured hot path. Exclude only the first
successful harness exec and CLONE_THREAD calls; count every other process attempt.
This complements, rather than replaces, explicit Rust gateway instrumentation.
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


CALL = re.compile(r"^(\d+)\s+(execveat|execve|clone3|clone|vfork|fork)\(")
RESUMED = re.compile(r"^(\d+)\s+<\.\.\. (\w+) resumed>")


def count_process_attempts(trace):
    """Fail closed on missing initial exec or incomplete process-syscall records."""
    initial = False
    pending = {}
    processes = 0
    threads = 0
    for line in trace.splitlines():
        call = CALL.match(line)
        resumed = RESUMED.match(line)
        if resumed:
            tid, name = resumed.groups()
            prefix = pending.pop((tid, name), None)
            if prefix is None:
                raise ValueError("unmatched resumed syscall")
            line = prefix + line
            call = CALL.match(line)
        if call is None:
            if "resumed>" in line or "<unfinished ...>" in line:
                raise ValueError("unrecognized process syscall")
            continue
        tid, name = call.groups()
        if "<unfinished ...>" in line and not resumed:
            pending[(tid, name)] = line.replace("<unfinished ...>", "")
            continue
        if name in ("execve", "execveat"):
            if not initial:
                if not re.search(r"= 0\s*$", line):
                    raise ValueError("harness exec failed")
                initial = True
            else:
                processes += 1
        elif name in ("clone", "clone3") and "CLONE_THREAD" in line:
            threads += 1
        else:
            processes += 1
    if not initial or pending:
        raise ValueError("incomplete process trace")
    return {"process_attempts": processes, "thread_attempts": threads}


class ParserTests(unittest.TestCase):
    def test_thread_calls_are_not_processes(self):
        trace = '\n'.join([
            '10 execve("test", [], []) = 0',
            '10 clone3({flags=CLONE_VM|CLONE_THREAD}, 88) = -1 ENOSYS',
            '10 clone(child_stack=0, flags=CLONE_VM|CLONE_THREAD) = 11',
        ])
        self.assertEqual(count_process_attempts(trace), {
            "process_attempts": 0, "thread_attempts": 2,
        })

    def test_spawn_exec_and_failed_attempts_are_counted(self):
        trace = '\n'.join([
            '10 execve("test", [], []) = 0',
            '10 clone(flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 12',
            '12 execve("child", [], []) = 0',
            '10 fork() = -1 EAGAIN',
        ])
        self.assertEqual(count_process_attempts(trace)["process_attempts"], 3)

    def test_resumed_thread_is_excluded(self):
        trace = '\n'.join([
            '10 execve("test", [], []) = 0',
            '10 clone(flags=CLONE_VM|CLONE_THREAD <unfinished ...>',
            '10 <... clone resumed>) = 11',
        ])
        self.assertEqual(count_process_attempts(trace)["process_attempts"], 0)

    def test_incomplete_trace_is_rejected(self):
        for trace in ['', '10 execve("test", [], []) = -1 ENOENT',
                      '10 execve("test", [], []) = 0\n10 fork(<unfinished ...>']:
            with self.assertRaises(ValueError):
                count_process_attempts(trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner().run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ParserTests))
        return 0 if result.wasSuccessful() else 1
    if args.binary is None or sys.platform != "linux":
        parser.error("--binary and Linux/strace are required; no skipped-pass path")
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="synthetic-process-audit-") as directory:
        trace = pathlib.Path(directory) / "trace"
        prefix = [
            "strace", "-f", "-qq", "-v", "-s", "0",
            "-e", "trace=clone,clone3,fork,vfork,execve,execveat",
            "-o", str(trace),
        ]
        # Prove the REAL tracer/parser sees a successful process clone and a subsequent exec.
        # This isolated synthetic canary is outside the Rust hot-path measurement.
        canary = (
            "import os,sys; pid=os.fork(); "
            "os.execv(sys.executable,[sys.executable,'-I','-S','-c','pass']) "
            "if pid==0 else sys.exit(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]))"
        )
        positive = subprocess.run(prefix + [sys.executable, "-I", "-S", "-c", canary],
            check=True, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        if positive.stdout or positive.stderr:
            raise ValueError("unexpected synthetic canary diagnostics")
        canary_count = count_process_attempts(trace.read_text())["process_attempts"]
        if canary_count != 2:
            raise ValueError("real process canary did not observe fork plus exec")
        completed = subprocess.run(prefix + [str(binary),
            "--exact", "native_catalog_real_http_s3_end_to_end",
        ], check=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=600)
        if completed.returncode:
            return completed.returncode
        if "test result: ok. 1 passed;" not in completed.stdout:
            raise ValueError("the exact synthetic test did not run")
        observations = count_process_attempts(trace.read_text())
        observations["canary_process_attempts"] = canary_count
    print(json.dumps(observations, sort_keys=True))
    return 0 if observations["process_attempts"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
