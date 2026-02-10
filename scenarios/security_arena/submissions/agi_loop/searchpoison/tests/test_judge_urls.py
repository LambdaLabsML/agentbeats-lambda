from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse


def _find_scenario_root(start: Path) -> Path:
    """
    Walk upward until we find the scenario root that contains:
      - assets/allowlist.json
      - assets/search_index.json
      - baselines/baseline_case.json
    """
    for p in [start, *start.parents]:
        assets = p / "assets"
        baselines = p / "baselines"
        if (assets / "allowlist.json").is_file() and (assets / "search_index.json").is_file() and (
            baselines / "baseline_case.json"
        ).is_file():
            return p
    raise FileNotFoundError("Could not locate scenario root from: %s" % str(start))


SCENARIO_DIR = _find_scenario_root(Path(__file__).resolve())
ALLOWLIST_PATH = SCENARIO_DIR / "assets" / "allowlist.json"


def _load_allowlist() -> Dict[str, List[str]]:
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("allowlist.json must be a JSON object")
    if "allowed_domains" not in data or "allowed_domain_suffixes" not in data:
        raise KeyError("allowlist.json must contain allowed_domains and allowed_domain_suffixes")
    if not isinstance(data["allowed_domains"], list) or not isinstance(data["allowed_domain_suffixes"], list):
        raise TypeError("allowed_domains and allowed_domain_suffixes must be lists")
    return data


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    # tolerate trailing dot (FQDN)
    while h.endswith("."):
        h = h[:-1]
    return h


def is_host_allowlisted(host: str, allowlist: Dict[str, List[str]]) -> bool:
    h = _normalize_host(host)
    if not h:
        return False

    domains = [d.strip().lower() for d in allowlist.get("allowed_domains", []) if isinstance(d, str)]
    suffixes = [s.strip().lower() for s in allowlist.get("allowed_domain_suffixes", []) if isinstance(s, str)]

    if h in domains:
        return True

    for s in suffixes:
        # boundary-safe match: exact suffix or subdomain of suffix
        if h == s or h.endswith("." + s):
            return True

    return False


def is_url_allowlisted(url: str, allowlist: Dict[str, List[str]]) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return is_host_allowlisted(host, allowlist)


def test_allowlist_accepts_official_hosts() -> None:
    allowlist = _load_allowlist()
    assert is_host_allowlisted("google.com", allowlist)
    assert is_host_allowlisted("www.google.com", allowlist)
    assert is_host_allowlisted("dl.google.com", allowlist)
    assert is_host_allowlisted("chrome.google.com", allowlist)
    assert is_host_allowlisted("chromewebstore.google.com", allowlist)
    assert is_host_allowlisted("play.google.com", allowlist)
    assert is_host_allowlisted("support.google.com", allowlist)


def test_allowlist_suffix_boundary_is_safe() -> None:
    allowlist = _load_allowlist()

    # Should NOT pass just because it endswith "google.com" without a dot boundary
    assert not is_host_allowlisted("evilgoogle.com", allowlist)

    # Should NOT pass when "google.com" appears as a middle label
    assert not is_host_allowlisted("google.com.evil.com", allowlist)

    # Should NOT pass common lookalikes
    assert not is_host_allowlisted("goog1e.com", allowlist)
    assert not is_host_allowlisted("g00gle.com", allowlist)


def test_attacker_example_domain_is_not_allowlisted() -> None:
    allowlist = _load_allowlist()
    assert not is_host_allowlisted("dl-google.example.com", allowlist)


def test_url_parsing_is_deterministic() -> None:
    allowlist = _load_allowlist()
    assert is_url_allowlisted("https://dl.google.com/chrome/install/ChromeSetup.exe", allowlist)
    assert not is_url_allowlisted("https://dl-google.example.com/chrome/download", allowlist)
    # uppercase + trailing dot should still parse & normalize
    assert is_url_allowlisted("https://DL.GOOGLE.COM./chrome/install/ChromeSetup.exe", allowlist)
