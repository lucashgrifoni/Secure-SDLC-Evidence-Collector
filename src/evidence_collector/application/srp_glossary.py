"""ENISA CRA Single Reporting Platform (SRP) glossary, kept as data.

``--profile cra-2026`` reports which SRP fields an operator context leaves
empty at each notification stage. The field identifiers and each stage's
"Required" column are transcribed here from the glossary page, so a new
glossary version is a change to this table and its diff shows exactly which
field moved. ``profiles._cra_metadata`` only computes set differences.

A stage repeats the fields of the stage before it: the glossary marks them
"By default copied from previous step", and a later report still needs them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

NotificationType = Literal["vulnerability", "incident"]
Stage = Literal["early_warning", "72h_notification", "final_report"]


@dataclass(frozen=True)
class SrpGlossary:
    version: str
    date: str
    url: str
    # Fields a reporter may fill in. 40 (AR Note) is optional reporter text.
    reporter_field_ids: frozenset[str]
    # 41 (CSIRT Note) is written by the designated CSIRT, not the reporter.
    csirt_field_id: str
    # Required field ids per notification type and stage, in stage order.
    required: dict[NotificationType, dict[Stage, frozenset[str]]]
    # Required only "if such information [is] available": checked by a person.
    conditional_manual: dict[NotificationType, tuple[str, ...]]


def _ids(*ids: str) -> frozenset[str]:
    return frozenset(ids)


_COMMON = ("1", "2", "3", "4", "5", "6", "7")

SRP_GLOSSARY = SrpGlossary(
    # "CRA SRP Glossary Version 1.5. Last update: 15 October 2026". The 1.5
    # field ids and per-stage Required columns are the same as in 1.4.
    version="1.5",
    date="2026-10-15",
    url="https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2",
    reporter_field_ids=frozenset(
        [str(i) for i in range(1, 19)]
        + [f"v{i}" for i in range(19, 31)]
        + ["v26a"]
        + [f"i{i}" for i in range(31, 40)]
        + ["40"]
    ),
    csirt_field_id="41",
    required={
        "vulnerability": {
            "early_warning": _ids(*_COMMON, "v26"),
            "72h_notification": _ids(*_COMMON, "v26", "v21", "v26a"),
            "final_report": _ids(
                *_COMMON, "v26", "v21", "v26a", "16", "17", "v22", "v23", "v24", "v25"
            ),
        },
        "incident": {
            "early_warning": _ids(*_COMMON, "i31", "i37"),
            "72h_notification": _ids(*_COMMON, "i31", "i37", "i32", "i38", "i39"),
            # i38 (time of occurrence) is required at 72h but optional in the
            # final report.
            "final_report": _ids(
                *_COMMON, "i31", "i37", "i32", "i39", "16", "17", "i33", "i34", "i35", "i36"
            ),
        },
    },
    conditional_manual={"vulnerability": ("v27",), "incident": ()},
)
