"""ENISA CRA Single Reporting Platform (SRP) glossary, kept as data.

``--profile cra-2026`` reports which SRP fields an operator context leaves
empty at each notification stage. The field identifiers and each stage's
"Required" column are transcribed here from the glossary page, so a new
glossary version is a change to this table and its diff shows exactly which
field moved. ``profiles._cra_metadata`` only computes set differences.

A stage repeats the fields of the stage before it, because a later report
still needs them. Glossary 1.5 marked them "By default copied from previous
step"; 1.6 shows the common fields as N/A at 72h and in the final report and
keeps that wording only for v26a and i31. The carry-over is this project's
reading of a report that updates the earlier one, not a glossary statement.
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
    # "CRA SRP Glossary Version 1.6. Last update: 21 October 2026". Against 1.5:
    # new optional field 7a (Additional Information); i38 is Optional at 72h
    # (was Required); v26a is Optional in the early warning and "By default
    # copied from previous step" at 72h, so no stage requires it any more.
    version="1.6",
    date="2026-10-21",
    url="https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2",
    reporter_field_ids=frozenset(
        [str(i) for i in range(1, 19)]
        + ["7a"]
        + [f"v{i}" for i in range(19, 31)]
        + ["v26a"]
        + [f"i{i}" for i in range(31, 40)]
        + ["40"]
    ),
    csirt_field_id="41",
    required={
        "vulnerability": {
            "early_warning": _ids(*_COMMON, "v26"),
            "72h_notification": _ids(*_COMMON, "v26", "v21"),
            "final_report": _ids(*_COMMON, "v26", "v21", "16", "17", "v22", "v23", "v24", "v25"),
        },
        "incident": {
            "early_warning": _ids(*_COMMON, "i31", "i37"),
            "72h_notification": _ids(*_COMMON, "i31", "i37", "i32", "i39"),
            "final_report": _ids(
                *_COMMON, "i31", "i37", "i32", "i39", "16", "17", "i33", "i34", "i35", "i36"
            ),
        },
    },
    conditional_manual={"vulnerability": ("v27",), "incident": ()},
)
