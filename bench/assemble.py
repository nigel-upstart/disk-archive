"""Assemble complete real observations; never estimate counters or create baselines.

Unit tests provide synthetic receipts only to exercise validation. Production
callers must collect SDK/pipeline outputs, strace, getrusage and Callgrind first.
"""
from __future__ import annotations

from copy import deepcopy
import math
import re

from compare import SEMANTIC_EXACT, TOOLCHAIN, HARDWARE, SEMANTICS, policy_options, samples, validate_exact

RESOURCES = ("wall", "cpu_user", "cpu_system", "cpu_total", "peak_rss_bytes", "voluntary_context_switches", "involuntary_context_switches")
CACHE_EVENTS = ("Ir", "I1mr", "D1mr", "D1mw", "ILmr", "DLmr", "DLmw")
KERNELS = ("redaction", "scanner", "gzip_sha256")
ADVISORY = ("manifest_bytes", "control_bytes", "wire_body_bytes", "history_rows", "verified_archives", "verified_retained", "catalog_init_seconds")


def unsigned(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("bounded observed unsigned count required")
    return value


def digest(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("immutable binary digest required")
    return value


def assemble(fingerprint: dict, resources: list[dict], applications: list[dict], kernels: dict[str, list[dict]], audit: dict, policy: dict) -> dict:
    """Reject incomplete, mixed-binary and semantically inconsistent populations.

    Resource peaks vary with actual concurrency and are summarized by their maximum,
    never exact-equality tested. Raw per-run metadata remains in the output artifact.
    Routes must already be independently normalized by the actual HTTP observer.
    """
    _, minimum = policy_options(policy)
    required = TOOLCHAIN + HARDWARE + SEMANTICS + ("source_commit", "source_dirty", "runner_image", "runner_image_version", "memory_bytes", "kernel", "workers", "cpu_jobs", "queue_capacity", "max_file_bytes", "worker_binary_sha256")
    if not isinstance(fingerprint, dict) or set(fingerprint) != set(required):
        raise ValueError("complete workload/build fingerprint required")
    binary = digest(fingerprint["worker_binary_sha256"])
    if type(fingerprint["source_dirty"]) is not bool or not re.fullmatch(r"[a-f0-9]{40}", fingerprint["source_commit"]):
        raise ValueError("source provenance required")
    if any(type(fingerprint[name]) is not int or fingerprint[name] <= 0 for name in ("nproc", "memory_bytes", "workers", "cpu_jobs", "queue_capacity", "max_file_bytes")):
        raise ValueError("positive resource configuration required")
    if not isinstance(resources, list) or not isinstance(applications, list) or len(resources) != len(applications) or not minimum <= len(resources) <= 1000:
        raise ValueError("complete bounded paired sample population required")
    if not isinstance(audit, dict) or set(audit) != {"process_attempts", "thread_attempts", "canary_process_attempts", "binary_sha256"}:
        raise ValueError("complete real process audit required")
    if digest(audit["binary_sha256"]) != binary or unsigned(audit["process_attempts"]) != 0 or unsigned(audit["canary_process_attempts"]) != 2:
        raise ValueError("same-binary zero-process audit with actual fork/exec canary required")
    unsigned(audit["thread_attempts"])
    measured = {name: [] for name in RESOURCES}
    exact = None
    advisory = []
    for usage, app in zip(resources, applications, strict=True):
        if not isinstance(usage, dict) or set(usage) != set(RESOURCES) | {"includes_process_startup", "application_counters"}:
            raise ValueError("complete resource sample required")
        if usage["includes_process_startup"] is not True or usage["application_counters"] is not None:
            raise ValueError("resource sampler cannot fabricate application counters")
        for name in RESOURCES:
            measured[name].append(samples([usage[name]])[0])
        if not math.isclose(usage["cpu_total"], usage["cpu_user"] + usage["cpu_system"], rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError("gated CPU total must equal its observed user + system components")
        if not isinstance(app, dict) or set(app) != {"schema", "complete", "binary_sha256", "exact", "advisory"} or type(app["schema"]) is not int or app["schema"] != 1 or app["complete"] is not True:
            raise ValueError("complete verified application receipt required")
        if digest(app["binary_sha256"]) != binary:
            raise ValueError("samples from different binaries cannot be combined")
        current = validate_exact(app["exact"])
        if current["process_spawns"] != 0 or not current["requests"] or current["bytes_uploaded"] <= 0 or current["peak_temp_bytes"] <= 0:
            raise ValueError("required production observations absent or process invariant broken")
        for name in ("process_spawns", "bytes_uploaded", "peak_temp_bytes"):
            unsigned(current[name])
        for route, count in current["requests"].items():
            if not re.fullmatch(r"(?:single|multipart)/(?:archive|manifest)-[0-9]{6,20}", route) or unsigned(count) == 0:
                raise ValueError("independent normalized observed requests required")
        if exact is None:
            exact = deepcopy(current)
        elif any(exact[name] != current[name] for name in SEMANTIC_EXACT):
            raise ValueError("semantic counter population changed; no median can erase retries")
        exact["peak_temp_bytes"] = max(exact["peak_temp_bytes"], current["peak_temp_bytes"])
        info = app["advisory"]
        if not isinstance(info, dict) or set(info) != set(ADVISORY):
            raise ValueError("complete advisory observation schema required")
        for name in ADVISORY:
            samples([info[name]]) if name == "catalog_init_seconds" else unsigned(info[name])
        if info["verified_archives"] <= 0 or info["history_rows"] < info["verified_archives"] + info["verified_retained"] or info["wire_body_bytes"] < current["bytes_uploaded"] + info["manifest_bytes"] + info["control_bytes"]:
            raise ValueError("independent output verification or actual wire observation missing")
        if advisory and any(info[name] != advisory[0][name] for name in ("history_rows", "verified_archives", "verified_retained")):
            raise ValueError("history/output population changed")
        advisory.append(deepcopy(info))
    if not isinstance(kernels, dict) or set(kernels) != set(KERNELS):
        raise ValueError("every actual production kernel required")
    for kernel in KERNELS:
        if not isinstance(kernels[kernel], list) or not kernels[kernel]:
            raise ValueError("actual Callgrind samples required")
        for event in CACHE_EVENTS:
            measured[f"{kernel}.{event}"] = []
        for events in kernels[kernel]:
            if not isinstance(events, dict) or set(events) != set(CACHE_EVENTS):
                raise ValueError("complete Callgrind cache event set required")
            if unsigned(events["Ir"]) == 0:
                raise ValueError("actual kernel instruction observation required")
            for event in CACHE_EVENTS:
                measured[f"{kernel}.{event}"].append(unsigned(events[event]))
    if set(measured) != set(policy["metrics"]):
        raise ValueError("collected metrics must match reviewed policy")
    return {"schema": 1, "fingerprint": deepcopy(fingerprint), "exact": exact, "samples": measured,
            "observations": {"applications": deepcopy(applications), "resources": deepcopy(resources), "process_audit": deepcopy(audit)},
            "measurement_scope": "fresh-process native pipeline plus fixture setup, cold catalog initialization and independent verification; no production-data distribution claim"}
