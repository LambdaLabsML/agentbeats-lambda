from __future__ import annotations

import json
from pathlib import Path

from test_judge_urls import _find_scenario_root


SCENARIO_DIR = _find_scenario_root(Path(__file__).resolve())
ASSETS_DIR = SCENARIO_DIR / "assets"

ALLOWLIST_PATH = ASSETS_DIR / "allowlist.json"
SEARCH_INDEX_PATH = ASSETS_DIR / "search_index.json"


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_allowlist_schema_and_normalization() -> None:
    data = _load_json(ALLOWLIST_PATH)
    assert isinstance(data, dict)

    domains = data.get("allowed_domains")
    suffixes = data.get("allowed_domain_suffixes")

    assert isinstance(domains, list) and len(domains) > 0
    assert isinstance(suffixes, list) and len(suffixes) > 0

    # Ensure they are domain-like (no scheme, no path) and lowercase-friendly
    for item in domains + suffixes:
        assert isinstance(item, str) and item.strip() != ""
        s = item.strip()
        assert "://" not in s
        assert "/" not in s
        assert " " not in s


def test_search_index_is_deterministic_and_well_formed() -> None:
    idx = _load_json(SEARCH_INDEX_PATH)
    assert isinstance(idx, dict)
    assert "download chrome" in idx

    results = idx["download chrome"]
    assert isinstance(results, list)
    assert len(results) >= 2

    ranks = []
    urls = set()
    for r in results:
        assert isinstance(r, dict)

        # Required fields for stable offline SERP
        for k in ("rank", "title", "url", "display_domain", "snippet"):
            assert k in r, f"Missing key {k} in result: {r}"

        assert isinstance(r["rank"], int) and r["rank"] >= 1
        assert isinstance(r["title"], str) and r["title"].strip() != ""
        assert isinstance(r["url"], str) and r["url"].startswith("http")
        assert isinstance(r["display_domain"], str) and r["display_domain"].strip() != ""
        assert isinstance(r["snippet"], str)

        ranks.append(r["rank"])
        urls.add(r["url"])

    # No duplicates and ranks are strictly 1..N
    assert len(urls) == len(results)
    assert sorted(ranks) == list(range(1, len(results) + 1))


def test_no_extra_queries_accidentally_added() -> None:
    # Keeps the scenario stable: Phase 1 wants deterministic behavior for a specific query.
    idx = _load_json(SEARCH_INDEX_PATH)
    assert list(idx.keys()) == ["download chrome"], f"Unexpected queries in search_index.json: {list(idx.keys())}"
