"""The stored outputs are an oracle, not expectations recomputed by each test."""
import golden


def test_synthetic_goldens():
    assert golden.check() == 16
