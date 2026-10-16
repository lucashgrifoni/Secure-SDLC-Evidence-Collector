"""Read-only check that the upstream sources this project pins have not moved.

Run weekly and on demand by ``.github/workflows/upstream-drift.yml``, never
on a pull request and never as a required check. It reads public pages only
and changes nothing. The pins come from the shipped package, so a re-pin in
the code is also a re-pin here.

* FedRAMP CR26: drift when a statement of a KSI the CR26 catalog uses
  changed on ``main``. A new ruleset version that only remaps SP 800-53
  controls is a notice, not drift.
* ENISA CRA SRP glossary: drift when the published version differs.
* OSPS Baseline: drift when the version labelled current differs.
* NIST SP 800-218r1 (SSDF 1.2): drift when a final version page exists,
  because the SSDF 1.2 catalog describes an initial public draft.

Exit 0 when every source matches its pin, 1 when one drifted or could not
be read (a source nobody could read is not a source that matched).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from evidence_collector.application import profiles
from evidence_collector.application.srp_glossary import SRP_GLOSSARY
from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog

OSPS_URL = "https://baseline.openssf.org/"
SSDF_FINAL_URL = "https://csrc.nist.gov/pubs/sp/800/218/r1/final"
_CR26_RAW = "https://raw.githubusercontent.com/FedRAMP/rules/{ref}/fedramp-consolidated-rules.json"
_USER_AGENT = "secure-sdlc-evidence-collector upstream-drift-check"

Fetch = Callable[[str], tuple[int, bytes]]
Status = Literal["ok", "notice", "drift"]


@dataclass(frozen=True)
class Result:
    source: str
    status: Status
    detail: str


def fetch(url: str) -> tuple[int, bytes]:
    """GET ``url``; an HTTP error status is returned, not raised."""
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def cr26_url(ref: str) -> str:
    return _CR26_RAW.format(ref=ref)


def cr26_indicator_ids() -> list[str]:
    catalog = bundled_catalog_path("catalog-fedramp-cr26.yaml")
    return sorted(c.control_id for c in load_catalog(catalog))


def pinned_osps_version() -> str:
    text = bundled_catalog_path("catalog-osps-baseline.yaml").read_text(encoding="utf-8")
    match = re.search(r"OSPS\) Baseline v(\d{4}\.\d{2}\.\d{2})", text)
    if match is None:
        raise ValueError("catalog-osps-baseline.yaml names no 'OSPS) Baseline vYYYY.MM.DD' pin")
    return match.group(1)


def ksi_statements(rules: dict[str, Any], ids: Sequence[str]) -> dict[str, Any]:
    """Each KSI without its SP 800-53 mapping (``controls``) or history (``updated``)."""
    found: dict[str, Any] = {}
    for family in rules.get("KSI", {}).values():
        for kid, indicator in family.get("indicators", {}).items():
            if kid in ids:
                found[kid] = {
                    k: v for k, v in indicator.items() if k not in {"controls", "updated"}
                }
    return found


def _read(fetcher: Fetch, url: str) -> bytes | None:
    status, body = fetcher(url)
    return body if status == 200 else None


def check_cr26(fetcher: Fetch) -> Result:
    source, ids = "FedRAMP CR26", cr26_indicator_ids()
    pinned_raw = _read(fetcher, cr26_url(profiles.FEDRAMP_RULESET_COMMIT))
    main_raw = _read(fetcher, cr26_url("main"))
    if pinned_raw is None or main_raw is None:
        return Result(source, "drift", "could not read the pinned or the current rules file")
    pinned, main = json.loads(pinned_raw), json.loads(main_raw)
    version = main.get("info", {}).get("version")
    current = ksi_statements(main, ids)
    if sorted(current) != ids:
        missing = sorted(set(ids) - set(current))
        return Result(source, "drift", f"KSIs missing on main: {', '.join(missing)}")
    if current != ksi_statements(pinned, ids):
        return Result(source, "drift", f"KSI statements changed on main (version {version})")
    if version != profiles.FEDRAMP_RULESET_VERSION:
        return Result(
            source,
            "notice",
            f"main is {version}, pinned {profiles.FEDRAMP_RULESET_VERSION}; "
            "the statements of the catalog KSIs are unchanged",
        )
    return Result(source, "ok", f"{version} matches the pin")


def check_srp(fetcher: Fetch) -> Result:
    source = "ENISA CRA SRP glossary"
    body = _read(fetcher, SRP_GLOSSARY.url)
    match = re.search(rb"Version\s+(\d+(?:\.\d+)*)\.\s*Last update:", body or b"")
    if match is None:
        return Result(source, "drift", "could not read the glossary version")
    version = match.group(1).decode()
    if version != SRP_GLOSSARY.version:
        return Result(source, "drift", f"published {version}, pinned {SRP_GLOSSARY.version}")
    return Result(source, "ok", f"{version} matches the pin")


def check_osps(fetcher: Fetch) -> Result:
    source, pinned = "OSPS Baseline", pinned_osps_version()
    body = _read(fetcher, OSPS_URL)
    match = re.search(rb"Current version:\s*(?:<[^>]*>\s*)*v(\d{4}\.\d{2}\.\d{2})", body or b"")
    if match is None:
        return Result(source, "drift", "could not read the current version")
    current = match.group(1).decode()
    if current != pinned:
        return Result(source, "drift", f"current {current}, pinned {pinned}")
    return Result(source, "ok", f"v{current} matches the pin")


def check_ssdf(fetcher: Fetch) -> Result:
    source = "NIST SP 800-218r1 (SSDF 1.2)"
    status, _ = fetcher(SSDF_FINAL_URL)
    if status == 404:
        return Result(source, "ok", "no final version page; the catalog's draft status holds")
    if status == 200:
        return Result(source, "drift", f"a final version page exists: {SSDF_FINAL_URL}")
    return Result(source, "drift", f"could not tell: HTTP {status} for {SSDF_FINAL_URL}")


def run_checks(fetcher: Fetch) -> list[Result]:
    return [check(fetcher) for check in (check_cr26, check_srp, check_osps, check_ssdf)]


def main(fetcher: Fetch = fetch) -> int:
    results = run_checks(fetcher)
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for result in results:
        label = {"ok": "OK", "notice": "NOTICE", "drift": "DRIFT"}[result.status]
        print(f"{label:6} {result.source}: {result.detail}")
        if in_actions and result.status != "ok":
            level = "error" if result.status == "drift" else "notice"
            print(f"::{level} title=Upstream drift: {result.source}::{result.detail}")
    return 1 if any(r.status == "drift" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
