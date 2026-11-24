"""Injected orchestration/metadata controls; NOT hosted measurements or a noise study."""
from copy import deepcopy
from contextlib import ExitStack
import json
import os
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from assemble import CACHE_EVENTS, assemble
from audit import binary_digest
import build
import check
import kernels
import run
from test_assemble import inputs


class BuildTests(unittest.TestCase):
    def messages(self, root):
        rows = []
        for index, name in enumerate(sorted(build.TARGETS)):
            path = root / name
            path.write_bytes(f"synthetic stand-in executable {index}".encode())
            path.chmod(0o700)
            rows.append(dict(reason="compiler-artifact", target=dict(name=name), executable=str(path)))
        return rows

    def test_cargo_paths_are_exact_not_unsuffixed_guesses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = self.messages(root)
            result = build.artifacts("\n".join(map(json.dumps, rows)))
            self.assertEqual(set(result), build.TARGETS)
            for value in result.values():
                self.assertEqual(value["sha256"], binary_digest(Path(value["path"])))
            for invalid in [rows[:-1], rows + [rows[0]]]:
                with self.assertRaises(ValueError):
                    build.artifacts("\n".join(map(json.dumps, invalid)))

    def test_stale_source_or_replaced_binary_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = build.artifacts("\n".join(map(json.dumps, self.messages(root))))
            receipt = root / "build.json"
            environment = dict(source_dirty=False, source_commit="a" * 40)
            receipt.write_text(json.dumps(dict(schema=1, fingerprint=environment, executables=entries)))
            self.assertEqual(set(build.load(receipt, environment)), build.TARGETS)
            with self.assertRaises(ValueError):
                build.load(receipt, dict(environment, source_commit="b" * 40))
            Path(entries["perf-pipeline"]["path"]).write_bytes(b"changed executable")
            with self.assertRaises(ValueError):
                build.load(receipt, environment)


class FunctionalCollectorTests(unittest.TestCase):
    def test_failure_diagnostics_are_only_allowlisted_phase_and_numbers(self):
        text = check.diagnostic("collector-execution", 700 * 1024 * 1024, 1)
        self.assertEqual(json.loads(text.partition(": ")[2]), dict(stage="collector-execution", binary_bytes=700 * 1024 * 1024, exit_status=1))
        self.assertEqual(json.loads(check.diagnostic("cargo-build", None, None).partition(": ")[2]), dict(stage="cargo-build", binary_bytes=None, exit_status=None))
        for args in [("synthetic-secret-must-not-escape", None, None), ("cargo-build", "sensitive-argv", None), ("cargo-build", None, "sensitive-output")]:
            with self.assertRaises(ValueError):
                check.diagnostic(*args)

    def test_test_harness_cannot_impersonate_actual_collector(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "collector-exact-hash"
            binary.write_bytes(b"synthetic stand-in executable")
            message = dict(reason="compiler-artifact", target=dict(name="perf-pipeline"),
                           executable=str(binary), profile=dict(test=False))
            self.assertEqual(check.executable(json.dumps(message)), binary.resolve())
            message["profile"]["test"] = True
            with self.assertRaises(ValueError):
                check.executable(json.dumps(message))

    def test_complete_independent_outputs_required(self):
        receipt = inputs()[2][0]
        receipt["advisory"].update(verified_archives=89, verified_retained=1, history_rows=90)
        check.validate(receipt)
        for field, value in [("bytes_uploaded", 0), ("peak_temp_bytes", 0), ("process_spawns", 1)]:
            broken = deepcopy(receipt)
            broken["exact"][field] = value
            with self.assertRaises(ValueError):
                check.validate(broken)
        receipt["advisory"]["verified_archives"] = 88
        with self.assertRaises(ValueError):
            check.validate(receipt)


class KernelTests(unittest.TestCase):
    def test_collect_invokes_the_built_runner_in_bench_mode(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            binary = root / "callgrind-exact-hash"
            binary.write_bytes(b"synthetic stand-in executable")
            build_receipt, output = root / "build.json", root / "kernels.json"
            environment = dict(source_commit="a" * 40)
            stack.enter_context(patch.object(kernels.sys, "platform", "linux"))
            stack.enter_context(patch.object(kernels, "fingerprint", return_value=environment))
            load_build = stack.enter_context(patch.object(kernels, "load_build", return_value={"callgrind": binary}))
            runner = stack.enter_context(patch.object(kernels.subprocess, "run"))

            def simulate_gungraun(argv, **kwargs):
                # Test mode succeeds but leaves stdout empty, just as the failed CI job did.
                stdout = self.stdout(self.complete()) if "--bench" in argv and "--test" not in argv else b""
                return CompletedProcess(argv, 0, stdout, b"")

            runner.side_effect = simulate_gungraun
            kernels.collect(build_receipt, output)

            load_build.assert_called_once_with(build_receipt, environment)
            runner.assert_called_once()
            self.assertEqual(runner.call_args.args[0], [str(binary), "--bench", "--output-format=json"])
            self.assertEqual(kernels.load(output, environment)["kernels"], kernels.counts(self.stdout(self.complete())))

    def test_tool_failure_classification_never_returns_raw_output(self):
        for payload, expected in [(b"unexpected argument private-value", "runner-arguments"),
                                  (b"unrecognised instruction private-value", "unsupported-instruction"),
                                  (b"panicked with private-value", "benchmark-panic"),
                                  (b"private-value", "tool-failed")]:
            self.assertEqual(kernels.failure_category(payload), expected)
            self.assertNotIn("private-value", kernels.failure_category(payload))

    def summary(self, function, value=100, **changes):
        """Synthetic Gungraun v7 summary line; NOT a measured Callgrind observation."""
        metrics = {event: dict(values=dict(new=value)) for event in CACHE_EVENTS}
        # Derived/extra metrics present in real summaries are ignored, never required.
        metrics["EstimatedCycles"] = dict(values=dict(new=value))
        metrics["L1HitRate"] = dict(values=dict(new=99.5))
        summary = dict(version="7", kind="LibraryBenchmark", baselines=[None, None], function_name=function,
                       module_path=f"callgrind::actual_components::{function}",
                       profiles=[dict(tool="Callgrind", data=dict(parts=[dict(metrics=metrics, tool_run=dict(new=dict(command="synthetic", pid=1)))],
                                                               total=dict(metrics=metrics, regressions=[])))])
        summary.update(changes)
        return summary

    def stdout(self, summaries):
        return ("\n".join(json.dumps(item) for item in summaries) + "\n").encode()

    def complete(self):
        return [self.summary(function) for function in kernels.FUNCTIONS.values()]

    def test_only_complete_unambiguous_summaries_pass(self):
        result = kernels.counts(self.stdout(self.complete()))
        self.assertEqual(set(result), set(kernels.FUNCTIONS))
        self.assertEqual(result["scanner"], [dict.fromkeys(CACHE_EVENTS, 100)])
        complete = self.complete()
        for broken in (complete[:2], [*complete, complete[0]], [*complete, self.summary("unregistered")],
                       [*complete[:2], self.summary("unregistered")]):
            with self.subTest(count=len(broken)), self.assertRaises(ValueError):
                kernels.counts(self.stdout(broken))

    def test_summary_format_and_freshness_are_required(self):
        mutations = [
            dict(version="6"), dict(kind="BinaryBenchmark"), dict(baselines=["saved", None]),
            dict(function_name=["core_needle_build_and_rewrite"]),
        ]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                kernels.counts(self.stdout([self.summary(kernels.FUNCTIONS["redaction"], **change),
                                            *self.complete()[1:]]))
        for alter in ("tool", "profiles", "parts"):
            item = self.summary(kernels.FUNCTIONS["redaction"])
            profile = item["profiles"][0]
            if alter == "tool":
                profile["tool"] = "Cachegrind"
            elif alter == "profiles":
                item["profiles"].append(deepcopy(profile))
            else:
                profile["data"]["parts"].append(deepcopy(profile["data"]["parts"][0]))
            with self.subTest(alter=alter), self.assertRaises(ValueError):
                kernels.counts(self.stdout([item, *self.complete()[1:]]))

    def test_missing_or_non_integer_events_never_become_zero(self):
        def broken(edit):
            item = self.summary(kernels.FUNCTIONS["scanner"])
            edit(item["profiles"][0]["data"]["total"]["metrics"])
            return [self.complete()[0], item, self.complete()[2]]

        edits = [
            lambda metrics: metrics.pop("DLmw"),
            lambda metrics: metrics["I1mr"].update(values=dict(new=1.5)),
            lambda metrics: metrics["I1mr"].update(values=dict(new=True)),
            lambda metrics: metrics["I1mr"].update(values=dict(new=-1)),
            lambda metrics: metrics["D1mr"].update(values=dict(new=1, old=1)),
            lambda metrics: metrics["D1mr"].update(values=dict(old=1)),
            lambda metrics: metrics["Ir"].update(values=dict(new=0)),
        ]
        for index, edit in enumerate(edits):
            with self.subTest(edit=index), self.assertRaises(ValueError):
                kernels.counts(self.stdout(broken(edit)))

    def test_malformed_or_oversized_output_fails(self):
        for payload in (b"", b"not json\n", b"[]\n", b"\xff\n", b" " * (kernels.MAX_SUMMARY_BYTES + 1)):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                kernels.counts(payload)

    def test_diagnostic_counts_contain_no_output_values(self):
        payload = self.stdout(self.complete()) + b"private-value\n"
        matches = kernels.summary_matches(payload)
        self.assertEqual(matches, dict.fromkeys(kernels.FUNCTIONS, 1))
        self.assertNotIn("private-value", json.dumps(matches))

    def test_kernel_source_and_tools_cannot_be_mixed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "kernels.json"
            environment = dict(source_commit="a" * 40)
            data = dict(schema=1, fingerprint=environment, binary_sha256="b" * 64, kernels=kernels.counts(self.stdout(self.complete())))
            receipt.write_text(json.dumps(data))
            self.assertEqual(kernels.load(receipt, environment), data)
            with self.assertRaises(ValueError):
                kernels.load(receipt, dict(source_commit="c" * 40))
            data["kernels"]["scanner"][0]["Ir"] = 0
            receipt.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                kernels.load(receipt, environment)


class CollectionTests(unittest.TestCase):
    def prepared(self, root):
        args = inputs()
        rows = BuildTests().messages(root)
        entries = build.artifacts("\n".join(map(json.dumps, rows)))
        digest = entries["perf-pipeline"]["sha256"]
        args[0]["worker_binary_sha256"] = digest
        for app in args[2]:
            app["binary_sha256"] = digest
        args[4]["binary_sha256"] = digest
        extra = {"workers", "cpu_jobs", "queue_capacity", "max_file_bytes", "worker_binary_sha256"}
        environment = {key: value for key, value in args[0].items() if key not in extra}
        compiled = root / "build.json"
        compiled.write_text(json.dumps(dict(schema=1, fingerprint=environment, executables=entries)))
        kernel_receipt = root / "kernels.json"
        kernel_receipt.write_text(json.dumps(dict(schema=1, fingerprint=environment, binary_sha256=entries["callgrind"]["sha256"], kernels=args[3])))
        return args, environment, compiled, kernel_receipt

    def injected(self, root, *, public=False, baseline_kind=None, summary_alias=False):
        args, environment, compiled, kernel_receipt = self.prepared(root)
        baseline = None
        if baseline_kind is not None:
            reference = assemble(*args)
            if baseline_kind == "timing":
                reference["samples"]["wall"] = [0.001] * 10
            else:
                reference["samples"]["redaction.Ir"] = [1]
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps(reference))
            before = baseline.read_bytes()
        with ExitStack() as stack:
            # These injected local receipts must not inherit the hosted baseline trust path.
            stack.enter_context(patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}))
            stack.enter_context(patch("run.sys.platform", "linux"))
            stack.enter_context(patch("run.fingerprint", side_effect=lambda *a, **kw: deepcopy(environment)))
            stack.enter_context(patch("run.effective_public", return_value=public))
            stack.enter_context(patch("run.baseline_path", return_value=None))
            stack.enter_context(patch("run.write_corpus"))
            audit = stack.enter_context(patch("run.audit", return_value=args[4]))
            population = stack.enter_context(patch("run.population", side_effect=lambda *a: deepcopy((args[1], args[2]))))
            kernel_load = stack.enter_context(patch("run.load_kernels", wraps=kernels.load))
            status = run.run(compiled, kernel_receipt, root / "report", baseline=baseline,
                             summary_path=compiled if summary_alias else None)
        if baseline is not None:
            self.assertEqual(baseline.read_bytes(), before)
        return status, json.loads((root / "report/decision.json").read_text()), population.call_count, audit.call_count, kernel_load.call_count

    def test_injected_receipts_isolate_and_restore_hosted_environment(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with tempfile.TemporaryDirectory() as temporary:
                status, _, populations, audits, kernel_reads = self.injected(Path(temporary), public=True, baseline_kind="timing")
            self.assertEqual(status, 1)
            self.assertEqual((populations, audits, kernel_reads), (2, 1, 1))
            self.assertEqual(os.environ["GITHUB_ACTIONS"], "true")

    def test_private_record_only_and_public_missing_baseline(self):
        for public, expected in [(False, 0), (True, 1)]:
            with tempfile.TemporaryDirectory() as temporary:
                status, decision, populations, audits, kernel_reads = self.injected(Path(temporary), public=public)
                self.assertEqual(status, expected)
                self.assertEqual(decision["mode"], "blocked-missing-baseline" if public else "record-only")
                self.assertEqual((populations, audits, kernel_reads), (1, 1, 1))

    def test_one_timing_confirmation_without_rerunning_deterministic_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            status, decision, populations, audits, kernel_reads = self.injected(Path(temporary), public=True, baseline_kind="timing")
            self.assertEqual(status, 1)
            self.assertEqual(decision["rerun_metrics"], ["wall"])
            self.assertEqual((populations, audits, kernel_reads), (2, 1, 1))

    def test_deterministic_failure_never_reruns(self):
        with tempfile.TemporaryDirectory() as temporary:
            status, decision, populations, audits, kernel_reads = self.injected(Path(temporary), public=True, baseline_kind="instructions")
            self.assertEqual(status, 1)
            self.assertEqual(decision["rerun_metrics"], [])
            self.assertEqual((populations, audits, kernel_reads), (1, 1, 1))

    def test_summary_cannot_overwrite_build_input(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            self.injected(Path(temporary), summary_alias=True)

    def test_hosted_pr_uses_reviewed_base_not_its_own_raised_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            event.write_text(json.dumps(dict(pull_request=dict(base=dict(sha="a" * 40)))))
            environment = dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=str(event))
            names = "bench/baseline/reviewed.json\n"
            baseline = root / "bench/baseline/reviewed.json"
            baseline.parent.mkdir(parents=True)
            baseline.write_text('{"reviewed":true}')
            with patch.dict(os.environ, environment), patch("run.subprocess.check_output", side_effect=[names, "", '{"reviewed":true}']) as git:
                data, selected = run.reviewed_baseline(root, None)
                self.assertEqual(data, dict(reviewed=True))
                self.assertEqual(git.call_args_list[0].args[0][4], "a" * 40)
                self.assertEqual(selected, root / "bench/baseline/reviewed.json")
            with patch.dict(os.environ, environment), self.assertRaises(ValueError):
                run.reviewed_baseline(root, root / "unreviewed.json")
            baseline.unlink()
            with patch.dict(os.environ, environment), patch("run.subprocess.check_output", return_value=""):
                self.assertEqual(run.reviewed_baseline(root, None), (None, None))

    def test_hosted_pr_cannot_delete_edit_alias_or_add_its_own_ceiling(self):
        for mutation in ("delete", "edit", "rename", "add", "symlink", "directory-symlink", "create"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                event = root / "event.json"
                event.write_text(json.dumps(dict(repository=dict(private=False), pull_request=dict(base=dict(sha="a" * 40)))))
                environment = dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=str(event))
                baseline = root / "bench/baseline/reviewed.json"
                baseline.parent.mkdir(parents=True)
                baseline.write_text('{"reviewed":true}')
                names = "bench/baseline/reviewed.json\n"
                if mutation == "delete":
                    baseline.unlink()
                elif mutation == "edit":
                    baseline.write_text('{"reviewed":false}')
                elif mutation == "rename":
                    baseline.rename(baseline.with_name("renamed.json"))
                elif mutation == "add":
                    baseline.with_name("additional.json").write_text('{"reviewed":false}')
                elif mutation == "symlink":
                    other = root / "other.json"
                    other.write_text(baseline.read_text())
                    baseline.unlink()
                    baseline.symlink_to(other)
                elif mutation == "directory-symlink":
                    other = root / "other-baselines"
                    baseline.parent.rename(other)
                    baseline.parent.symlink_to(other, target_is_directory=True)
                elif mutation == "create":
                    names = ""
                with patch.dict(os.environ, environment), patch("run.subprocess.check_output", side_effect=[names, "", '{"reviewed":true}']), self.assertRaises(ValueError):
                    run.reviewed_baseline(root, None)

    def test_worktree_copy_cannot_hide_a_tracked_baseline_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "bench/baseline/reviewed.json"
            baseline.parent.mkdir(parents=True)
            baseline.write_text('{"reviewed":true}')
            event = root / "event.json"
            event.write_text(json.dumps(dict(repository=dict(private=False), pull_request=dict(base=dict(sha="a" * 40)))))
            environment = dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=str(event))

            def git(command, **kwargs):
                if command[1] == "ls-tree":
                    return "bench/baseline/reviewed.json\n"
                if command[1] == "show":
                    return '{"reviewed":true}'
                if command[1] == "diff":
                    self.assertEqual(command[-1], ":(glob)bench/baseline/**/*.json")
                    return "bench/baseline/reviewed.json\n"
                self.fail("unexpected baseline provenance command")

            with patch.dict(os.environ, environment), patch("run.subprocess.check_output", side_effect=git), self.assertRaises(ValueError):
                run.reviewed_baseline(root, None)

    def test_multiple_baselines_have_no_silent_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "bench/baseline"
            directory.mkdir(parents=True)
            self.assertIsNone(run.baseline_path(root))
            (directory / "first.json").write_text("{}")
            self.assertEqual(run.baseline_path(root), directory / "first.json")
            (directory / "second.json").write_text("{}")
            with self.assertRaises(ValueError):
                run.baseline_path(root)


if __name__ == "__main__":
    unittest.main()
