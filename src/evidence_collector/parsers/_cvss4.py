"""CVSS 4.0 scoring ported from FIRST's BSD-2-Clause reference calculator.

Upstream: FIRSTdotorg/cvss-v4-calculator at
c5b0d409ae9f57c44264c6ce5f27d89298e1d32a.
Full copyright, redistribution terms and disclaimer: THIRD_PARTY_LICENSES.md.
Rounding follows FIRST's JavaScript Math.round, without an epsilon.
"""

# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import annotations

import itertools
import math
from functools import lru_cache

from evidence_collector.parsers._cvss4_data import DEPTHS, LOOKUP, MAX_PARTS

_BASE = {
    "AV": "NALP",
    "AC": "LH",
    "AT": "NP",
    "PR": "NLH",
    "UI": "NPA",
    "VC": "HLN",
    "VI": "HLN",
    "VA": "HLN",
    "SC": "HLN",
    "SI": "HLN",
    "SA": "HLN",
}
_VALUES = {
    **_BASE,
    "E": "XAPU",
    "CR": "XHML",
    "IR": "XHML",
    "AR": "XHML",
    **{"M" + name: "X" + values for name, values in _BASE.items()},
    "MSI": "XSHLN",
    "MSA": "XSHLN",
    "S": "XNP",
    "AU": "XNY",
    "R": "XAUI",
    "V": "XDC",
    "RE": "XLMH",
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
# Exact membership: "NA" in "NALP" would pass as a substring.
_ALLOWED = {name: frozenset(values) for name, values in _VALUES.items()}
_ORDER = {name: index for index, name in enumerate(_ALLOWED)}
_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    **{name: {"H": 0.0, "L": 0.1, "N": 0.2} for name in ("VC", "VI", "VA")},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    **{name: {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3} for name in ("SI", "SA")},
    **{name: {"H": 0.0, "M": 0.1, "L": 0.2} for name in ("CR", "IR", "AR")},
}


def _parse(vector: str) -> dict[str, str] | None:
    parts = vector.split("/")
    if parts[0] != "CVSS:4.0":
        return None
    metrics: dict[str, str] = {}
    previous = -1
    for part in parts[1:]:
        name, delimiter, value = part.partition(":")
        if (
            not delimiter
            or name not in _ALLOWED
            or not value
            or value not in _ALLOWED[name]
            or _ORDER[name] <= previous
        ):
            return None
        metrics[name] = value
        previous = _ORDER[name]
    if not all(name in metrics for name in _BASE):
        return None
    return metrics


def _metric(metrics: dict[str, str], name: str) -> str:
    selected = metrics.get(name, "X")
    if selected == "X":
        if name == "E":
            return "A"
        if name in {"CR", "IR", "AR"}:
            return "H"
    modified = metrics.get("M" + name, "X")
    return selected if modified == "X" else modified


def _macro(metrics: dict[str, str]) -> tuple[int, int, int, int, int, int]:
    av, pr, ui = (_metric(metrics, name) for name in ("AV", "PR", "UI"))
    eq1 = 0 if (av, pr, ui) == ("N", "N", "N") else 1 if "N" in (av, pr, ui) and av != "P" else 2
    eq2 = 0 if (_metric(metrics, "AC"), _metric(metrics, "AT")) == ("L", "N") else 1
    vc, vi, va = (_metric(metrics, name) for name in ("VC", "VI", "VA"))
    eq3 = 0 if (vc, vi) == ("H", "H") else 1 if "H" in (vc, vi, va) else 2
    if _metric(metrics, "MSI") == "S" or _metric(metrics, "MSA") == "S":
        eq4 = 0
    else:
        eq4 = 1 if any(_metric(metrics, name) == "H" for name in ("SC", "SI", "SA")) else 2
    eq5 = {"A": 0, "P": 1, "U": 2}[_metric(metrics, "E")]
    eq6 = (
        0
        if any(
            _metric(metrics, requirement) == "H" and _metric(metrics, impact) == "H"
            for requirement, impact in (("CR", "VC"), ("IR", "VI"), ("AR", "VA"))
        )
        else 1
    )
    return eq1, eq2, eq3, eq4, eq5, eq6


@lru_cache(maxsize=270)
def _max_vectors(macro: tuple[int, int, int, int, int, int]) -> tuple[dict[str, str], ...]:
    eq1, eq2, eq3, eq4, eq5, eq6 = macro
    groups = [
        MAX_PARTS[f"eq1:{eq1}"],
        MAX_PARTS[f"eq2:{eq2}"],
        MAX_PARTS[f"eq3:{eq3}:{eq6}"],
        MAX_PARTS[f"eq4:{eq4}"],
        MAX_PARTS[f"eq5:{eq5}"],
    ]
    return tuple(
        dict(part.split(":", 1) for part in "".join(parts).rstrip("/").split("/"))
        for parts in itertools.product(*groups)
    )


def score_cvss4(vector: str) -> float | None:
    """Score a validated CVSS-B, BT, BE or BTE vector; invalid input returns None."""
    try:
        return _score(vector)
    except (KeyError, ValueError):
        # Third-party advisory data must fall back, never abort a collect run.
        return None


def _score(vector: str) -> float | None:
    metrics = _parse(vector)
    if metrics is None:
        return None
    if all(_metric(metrics, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = _macro(metrics)
    eq1, eq2, eq3, eq4, eq5, eq6 = macro
    key = "".join(str(value) for value in macro)
    value = LOOKUP[key]
    lower1 = LOOKUP.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}", math.nan)
    lower2 = LOOKUP.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}", math.nan)
    if eq3 == 0 and eq6 == 0:
        left = LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", math.nan)
        right = LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", math.nan)
        lower36 = left if left > right else right
    elif eq3 in (0, 1) and eq6 == 1:
        lower36 = LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", math.nan)
    elif eq3 == 1 and eq6 == 0:
        lower36 = LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", math.nan)
    else:
        lower36 = math.nan
    lower4 = LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}", math.nan)
    lower5 = LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}", math.nan)

    distances: dict[str, float] = {}
    for highest in _max_vectors(macro):
        distances = {
            name: levels[_metric(metrics, name)] - levels[highest[name]]
            for name, levels in _LEVELS.items()
        }
        if all(distance >= 0 for distance in distances.values()):
            break
    else:
        return None
    # Left-to-right additions as in cvss_score.js: builtin sum() compensates
    # float rounding since Python 3.12 and can move a score by 0.1.
    groups = [
        (lower1, distances["AV"] + distances["PR"] + distances["UI"], DEPTHS[f"eq1:{eq1}"]),
        (lower2, distances["AC"] + distances["AT"], DEPTHS[f"eq2:{eq2}"]),
        (
            lower36,
            distances["VC"]
            + distances["VI"]
            + distances["VA"]
            + distances["CR"]
            + distances["IR"]
            + distances["AR"],
            DEPTHS[f"eq3eq6:{eq3}:{eq6}"],
        ),
        (lower4, distances["SC"] + distances["SI"] + distances["SA"], DEPTHS[f"eq4:{eq4}"]),
        (lower5, 0.0, 1),
    ]
    proportional = [
        (value - lower) * (distance / (depth * 0.1))
        for lower, distance, depth in groups
        if not math.isnan(lower)
    ]
    total = 0.0
    for item in proportional:
        total += item
    mean = total / len(proportional) if proportional else 0.0
    value = max(0.0, min(10.0, value - mean))
    return math.floor(value * 10 + 0.5) / 10.0
