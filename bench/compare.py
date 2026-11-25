"""Pure performance comparator. It never writes, captures or raises a baseline."""
from __future__ import annotations

import math
import random
import statistics
from typing import Any

VERSION = 1
SEMANTIC_EXACT = ("process_spawns", "bytes_uploaded", "requests")
RESOURCE_PEAK = "peak_temp_bytes"
TOOLCHAIN = ("rustc", "llvm", "flags", "profile", "target", "valgrind", "gungraun", "cache_configuration")
HARDWARE = ("cpu_model", "nproc")
# "advisory" metrics are sampled and reported like statistical ones but never gate
# (e.g. user/system components whose redistribution is not a CPU regression).
SAMPLED = ("statistical", "advisory")
SEMANTICS = ("corpus_revision", "rules_revision")


def samples(values: list[float]) -> list[float]:
    if not isinstance(values, list) or not values or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("metrics require finite nonnegative samples")
    return values


def median_interval(values: list[float], *, seed: int = 488, rounds: int = 4000) -> tuple[float, float]:
    """Seeded percentile bootstrap of the new median, not a t-test."""
    samples(values)
    if len(values) < 10 or type(rounds) is not int or not 1000 <= rounds <= 100_000:
        raise ValueError("bounded bootstrap with at least ten samples required")
    generator = random.Random(seed)
    medians = sorted(statistics.median(generator.choices(values, k=len(values))) for _ in range(rounds))
    return medians[math.floor(0.025 * rounds)], medians[math.ceil(0.975 * rounds) - 1]


def matching(left: dict[str, Any], right: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(field in left and field in right and left[field] == right[field] for field in fields)


def validate_exact(exact: object) -> dict[str, Any]:
    """Legacy report bundle contains semantic counters AND a resource high-water mark."""
    required = set(SEMANTIC_EXACT) | {RESOURCE_PEAK}
    if not isinstance(exact, dict) or set(exact) != required:
        raise ValueError("complete observed counter schema required")
    for name in required - {"requests"}:
        if type(exact[name]) is not int or exact[name] < 0:
            raise ValueError("observed counters require unsigned integers")
    requests = exact["requests"]
    if not isinstance(requests, dict) or any(not isinstance(key, str) or not key or type(value) is not int or value < 0 for key, value in requests.items()):
        raise ValueError("observed request counts require a normalized named unsigned map")
    return exact


def validate_report(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("schema") != VERSION or not isinstance(report.get("fingerprint"), dict):
        raise ValueError("unsupported or missing measurement schema/fingerprint")
    return validate_exact(report.get("exact"))


def policy_options(policy: dict[str, Any]) -> tuple[int, int]:
    rounds = policy.get("bootstrap_rounds", 4000)
    minimum = policy.get("minimum_samples", 10)
    if type(rounds) is not int or not 1000 <= rounds <= 100_000 or type(minimum) is not int or not 10 <= minimum <= 1000:
        raise ValueError("bounded bootstrap/sample policy required")
    if not policy["metrics"]:
        raise ValueError("measurement policy cannot be empty")
    for configuration in policy["metrics"].values():
        tolerance = configuration["tolerance"]
        if configuration["kind"] not in ("deterministic",) + SAMPLED or isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)) or not math.isfinite(tolerance) or tolerance < 0:
            raise ValueError("invalid metric configuration")
    return rounds, minimum


def observations(report: dict[str, Any], policy: dict[str, Any], rounds: int, minimum: int) -> dict[str, dict[str, Any]]:
    result = {}
    for name, configuration in policy["metrics"].items():
        values = samples(report["samples"][name])
        if configuration["kind"] in SAMPLED and len(values) < minimum:
            raise ValueError("insufficient statistical samples")
        interval = median_interval(values, rounds=rounds) if configuration["kind"] in SAMPLED else (statistics.median(values),) * 2
        result[name] = {"status": "record-only", "gated": False, "new_median": statistics.median(values), "interval": interval, "sample_count": len(values)}
    return result


def counter_value(name: str, value: Any) -> int:
    return sum(value.values()) if name == "requests" else value


def refresh(result: dict[str, Any], reason: str, public: bool) -> None:
    reasons = result.setdefault("refresh_required", [])
    if reason not in reasons:
        reasons.append(reason)
    result["fail"] |= public


def peak_ceiling(baseline: dict[str, Any]) -> int:
    """Only committed/reviewed input defines the envelope; never infer one from current data."""
    ceilings = baseline.get("resource_ceilings", {})
    if not isinstance(ceilings, dict) or set(ceilings) - {RESOURCE_PEAK}:
        raise ValueError("unknown resource ceiling schema")
    ceiling = ceilings.get(RESOURCE_PEAK, baseline["exact"][RESOURCE_PEAK])
    if type(ceiling) is not int or ceiling < baseline["exact"][RESOURCE_PEAK]:
        raise ValueError("reviewed resource ceiling must cover its recorded high-water mark")
    return ceiling


def compare(current: dict[str, Any], baseline: dict[str, Any] | None, policy: dict[str, Any], *, public: bool = False, rerun: dict[str, Any] | None = None, first_public_bootstrap: bool = False) -> dict[str, Any]:
    """Compare semantic counts, reviewed resource ceilings and compatible sample populations.

    Caller must authorize first_public_bootstrap as a one-time MANUAL public-main
    workflow with no baseline history. The CLI enforces that provenance. Public
    missing baselines otherwise fail. CPU mismatch is explicitly NOT a statistical
    gate; compiler/rules mismatch requires reviewed refresh, not silent acceptance.
    """
    if type(public) is not bool or type(first_public_bootstrap) is not bool:
        raise ValueError("explicit boolean visibility/bootstrap required")
    if first_public_bootstrap and (not public or baseline is not None):
        raise ValueError("bootstrap is only for the first public baseline")
    exact = validate_report(current)
    rounds, minimum = policy_options(policy)
    measured = observations(current, policy, rounds, minimum)
    result: dict[str, Any] = {"mode": "enforce" if public and baseline is not None else "record-only", "metrics": measured, "fail": False}
    for name in SEMANTIC_EXACT + (RESOURCE_PEAK,):
        result["metrics"][name] = {"status": "record-only", "gated": False, "observed": counter_value(name, exact[name])}
    # This invariant is always enforced, even private/first-bootstrap runs.
    result["metrics"]["process_spawns"].update(status="fail" if exact["process_spawns"] else "unchanged", gated=True, expected=0)
    result["fail"] = exact["process_spawns"] != 0
    if baseline is None:
        if rerun is not None:
            raise ValueError("confirmation requires an existing baseline")
        if first_public_bootstrap:
            result["mode"] = "bootstrap-record-only"
        elif public:
            result["mode"] = "blocked-missing-baseline"
            refresh(result, "missing-public-baseline", public)
        return result
    previous_exact = validate_report(baseline)
    if previous_exact["process_spawns"] != 0:
        raise ValueError("a baseline cannot waive the zero-process invariant")
    previous = observations(baseline, policy, rounds, minimum)
    rerun_exact = validate_report(rerun) if rerun is not None else None
    if rerun_exact is not None and any(rerun_exact[name] != exact[name] for name in SEMANTIC_EXACT):
        result["fail"] = True
        result["metrics"]["rerun_exact"] = {"status": "fail", "gated": True, "reason": "confirmation changed semantic counters"}
    fingerprint, old_fingerprint = current["fingerprint"], baseline["fingerprint"]
    configuration = tuple(name for name in ("workers", "cpu_jobs", "queue_capacity", "max_file_bytes") if name in fingerprint or name in old_fingerprint)
    semantic_fields = SEMANTICS + configuration
    if not matching(fingerprint, old_fingerprint, semantic_fields):
        refresh(result, "corpus-rules-or-workload-changed", public)
        for name, value in result["metrics"].items():
            if name != "process_spawns":
                value.update(status="refresh-required", gated=False)
        return result
    for name in SEMANTIC_EXACT:
        changed = exact[name] != previous_exact[name]
        if name == "process_spawns":
            continue
        result["metrics"][name].update(status="fail" if changed and public else "advisory-record-only" if changed else "unchanged", gated=public, expected=counter_value(name, previous_exact[name]))
        result["fail"] |= changed and public
    ceiling = peak_ceiling(baseline)
    peak = max(exact[RESOURCE_PEAK], rerun_exact[RESOURCE_PEAK] if rerun_exact is not None else 0)
    exceeded = peak > ceiling
    result["metrics"][RESOURCE_PEAK] = {"status": "fail" if exceeded and public else "advisory-record-only" if exceeded else "below-ceiling" if peak < ceiling else "at-ceiling", "gated": public, "observed": peak, "ceiling": ceiling}
    result["fail"] |= exceeded and public
    for name, configuration in policy["metrics"].items():
        decision = result["metrics"][name]
        kind, tolerance = configuration["kind"], configuration["tolerance"]
        threshold = previous[name]["new_median"] * (1 + tolerance)
        decision["threshold"] = threshold
        if kind == "deterministic" and not matching(fingerprint, old_fingerprint, TOOLCHAIN):
            decision["status"] = "refresh-required-incompatible"
            refresh(result, "compiler-tools-cache-flags-or-profile-changed", public)
            continue
        if kind in SAMPLED and not matching(fingerprint, old_fingerprint, HARDWARE):
            decision.update(status="advisory-incompatible", gated=False, reason="CPU/nproc mismatch; statistical metric NOT gated")
            continue
        regressed = decision["interval"][0] > threshold
        if kind == "advisory":
            decision.update(status="advisory-regressed" if regressed else "unchanged", gated=False, reason="component reported only; its total is the gated metric")
            continue
        decision.update(status="unchanged", gated=public)
        if regressed and not public:
            decision["status"] = "advisory-record-only"
        elif regressed and kind == "deterministic":
            decision["status"] = "fail"
            result["fail"] = True
        elif regressed:
            if rerun is None:
                decision.update(status="rerun-required", gated=False)
            else:
                if not matching(rerun["fingerprint"], fingerprint, semantic_fields + HARDWARE + TOOLCHAIN):
                    raise ValueError("confirmation fingerprint mismatch")
                values = samples(rerun["samples"][name])
                if len(values) < minimum:
                    raise ValueError("insufficient confirmation samples")
                confirmation = median_interval(values, rounds=rounds)
                decision.update(rerun_interval=confirmation, status="fail" if confirmation[0] > threshold else "noise-cleared", gated=True)
                result["fail"] |= decision["status"] == "fail"
        elif decision["interval"][1] < previous[name]["new_median"] * (1 - tolerance):
            decision["status"] = "ratchet-suggested"
    return result
