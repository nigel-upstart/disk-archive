"""Injected orchestration/metadata controls; NOT hosted measurements or a noise study."""
from copy import deepcopy
from contextlib import ExitStack
import json
import os
from pathlib import Path
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
    def test_tool_failure_classification_never_returns_raw_output(self):
        for payload, expected in [(b"unexpected argument private-value", "runner-arguments"),
                                  (b"unrecognised instruction private-value", "unsupported-instruction"),
                                  (b"panicked with private-value", "benchmark-panic"),
                                  (b"private-value", "tool-failed")]:
            self.assertEqual(kernels.failure_category(payload), expected)
            self.assertNotIn("private-value", kernels.failure_category(payload))

    def dumps(self, root):
        paths = []
        for function in kernels.FUNCTIONS.values():
            path = root / f"callgrind.{function}.case.out"
            path.write_text("events: " + " ".join(CACHE_EVENTS) + "\ntotals: " + " ".join(["100"] * len(CACHE_EVENTS)) + "\n")
            paths.append(path)
        return paths

    def test_only_complete_fresh_unambiguous_event_sets_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self.dumps(root)
            result = kernels.counts(root)
            self.assertEqual(set(result), set(kernels.FUNCTIONS))
            self.assertEqual(result["scanner"][0]["Ir"], 100)
            (root / "callgrind.scanner_fixed_buffer.old.out").write_text(paths[0].read_text())
            with self.assertRaises(ValueError):
                kernels.counts(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self.dumps(root)
            paths[0].write_text("events: Ir\ntotals: 100\n")
            with self.assertRaises(ValueError):
                kernels.counts(root)

    def test_hardlinked_dumps_cannot_impersonate_different_kernels(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self.dumps(root)
            paths[1].unlink()
            paths[1].hardlink_to(paths[0])
            with self.assertRaises(ValueError):
                kernels.counts(root)

    def test_kernel_source_and_tools_cannot_be_mixed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.dumps(root)
            receipt = root / "kernels.json"
            environment = dict(source_commit="a" * 40)
            data = dict(schema=1, fingerprint=environment, binary_sha256="b" * 64, kernels=kernels.counts(root))
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
