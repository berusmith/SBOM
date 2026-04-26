"""Tests use the unsafe yaml.load to verify legacy fixture parsing.
This file lives under tests/ — analyzer must classify pyyaml use as
test_only, NOT reachable from production."""
import yaml


def test_legacy_fixture_loads():
    legacy = "key: !!python/object/apply:os.system [echo nope]"
    # In real life this would FAIL on yaml.safe_load — that's the point
    # of using the unsafe load() here, to keep the legacy fixture format
    # round-tripping in the test suite.
    result = yaml.load(legacy)
    assert result is None or isinstance(result, dict)
