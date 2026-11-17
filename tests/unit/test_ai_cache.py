"""AI cache: stable keys and version/input invalidation (Phase 1)."""

from ai.cache import AICache, cache_key


def test_cache_key_is_deterministic():
    a = cache_key(model="m", prompt_version="1.0", schema_version="1.0", input_hash="h")
    b = cache_key(model="m", prompt_version="1.0", schema_version="1.0", input_hash="h")
    assert a == b
    assert len(a) == 64


def test_cache_key_changes_with_any_input():
    base = dict(model="m", prompt_version="1.0", schema_version="1.0", input_hash="h")
    for key in base:
        variant = dict(base)
        variant[key] = variant[key] + "x"
        assert cache_key(**variant) != cache_key(**base)


def test_cache_store_get_invalidate_clear():
    cache = AICache()
    assert cache.get("k1") is None
    cache.set("k1", {"schema_version": "1.0"})
    assert cache.get("k1") == {"schema_version": "1.0"}
    cache.invalidate("k1")
    assert cache.get("k1") is None
    cache.set("k2", {"x": 1})
    cache.clear()
    assert cache.get("k2") is None
