"""Normalize observed per-object request counts, never infer requests or uploaded bytes."""
from __future__ import annotations

from collections.abc import Mapping


def normalize_requests(observed: Mapping[tuple[str, str], int], objects: Mapping[str, int], manifests: Mapping[str, int]) -> dict[str, int]:
    """Bindings come from independent corpus slots / semantic manifest chunk indices.

    Never use request completion order, UUIDs, upload IDs or manifest nonces as
    stable IDs. Unknown objects, duplicate aliases and class contradictions fail;
    no observed request may disappear during normalization. Transport counts must
    be observed first, including retries. Body bytes are NOT changed or inferred.
    """
    bindings = {}
    for kind, slots in (("archive", objects), ("manifest", manifests)):
        if len(set(slots.values())) != len(slots):
            raise ValueError("request identity slots must be one-to-one")
        for raw, ordinal in slots.items():
            if not isinstance(raw, str) or not raw or type(ordinal) is not int or not 0 <= ordinal < 2**64 or raw in bindings:
                raise ValueError("invalid or ambiguous observed object binding")
            bindings[raw] = f"{kind}-{ordinal:06d}"
    result = {}
    classes = {}
    for identity, count in observed.items():
        if not isinstance(identity, tuple) or len(identity) != 2 or type(count) is not int or not 0 <= count < 2**64:
            raise ValueError("invalid observed request counter")
        size_class, raw = identity
        if size_class not in ("single", "multipart") or raw not in bindings:
            raise ValueError("unknown observed object or size class")
        if (raw in classes and classes[raw] != size_class) or (raw in manifests and size_class != "single"):
            raise ValueError("contradictory observed object classification")
        classes[raw] = size_class
        result[f"{size_class}/{bindings[raw]}"] = count
    return dict(sorted(result.items()))
