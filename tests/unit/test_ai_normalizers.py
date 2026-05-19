"""T6.5 — Unit tests for AI evidence normalizers and collector auto-detect."""

from __future__ import annotations

from pathlib import Path

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import (
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import (
    normalize_garak,
    normalize_lm_eval,
    normalize_model_card,
)
from evidence_collector.parsers import (
    parse_garak,
    parse_lm_eval,
    parse_model_card,
)


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.05.19", commit_sha="abcdef1234567890")


_GARAK_REPORT = "\n".join(
    [
        '{"entry_type":"init","garak_version":"0.10.0","model_name":"hf://x"}',
        '{"entry_type":"digest","probe":"promptinject.A","attempts":10,"hits":2}',
        '{"entry_type":"digest","probe":"promptinject.B","attempts":10,"hits":0}',
    ]
)

_LM_EVAL_REPORT = """
{
  "results": {"truthfulqa_mc1": {"acc": 0.42}},
  "config": {"model_args": "pretrained=meta-llama/Llama-3.1-8B"},
  "versions": {"lm_eval": "0.4.4"}
}
"""

_HF_MODEL_CARD = """
{
  "model_id": "google/flan-t5-small",
  "license": "apache-2.0",
  "datasets": ["c4"],
  "model-index": [{"results": [{"metrics": [{"name": "bleu", "value": 27.5}]}]}]
}
"""


def test_normalize_garak_fails_when_hits_present(tmp_path: Path) -> None:
    report = tmp_path / "run.garak.jsonl"
    report.write_text(_GARAK_REPORT + "\n", encoding="utf-8")
    evidence = normalize_garak(parse_garak(report), _release())
    assert evidence.evidence_type == EvidenceType.PROMPT_INJECTION_TEST_RESULT
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.subject_type == SubjectType.AI_MODEL
    assert evidence.subject_ref == "hf://x"
    assert evidence.metadata["total_hits"] == 2
    assert len(evidence.metadata["probes"]) == 2


def test_normalize_garak_passes_when_no_hits(tmp_path: Path) -> None:
    report = tmp_path / "clean.garak.jsonl"
    report.write_text(
        "\n".join(
            [
                '{"entry_type":"init","garak_version":"0.10.0","model_name":"y"}',
                '{"entry_type":"digest","probe":"promptinject.Z","attempts":10,"hits":0}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    evidence = normalize_garak(parse_garak(report), _release())
    assert evidence.status == EvidenceStatus.PASSED


def test_normalize_lm_eval_produces_ai_safety_eval(tmp_path: Path) -> None:
    report = tmp_path / "model.lm-eval.json"
    report.write_text(_LM_EVAL_REPORT, encoding="utf-8")
    evidence = normalize_lm_eval(parse_lm_eval(report), _release())
    assert evidence.evidence_type == EvidenceType.AI_SAFETY_EVAL
    assert evidence.subject_type == SubjectType.AI_MODEL
    assert evidence.subject_ref == "meta-llama/Llama-3.1-8B"
    assert evidence.status == EvidenceStatus.GENERATED
    assert evidence.metadata["total_tasks"] == 1


def test_normalize_model_card_carries_license_and_datasets(tmp_path: Path) -> None:
    card = tmp_path / "model-card.json"
    card.write_text(_HF_MODEL_CARD, encoding="utf-8")
    evidence = normalize_model_card(parse_model_card(card), _release())
    assert evidence.evidence_type == EvidenceType.MODEL_CARD
    assert evidence.subject_type == SubjectType.AI_MODEL
    assert evidence.metadata["license"] == "apache-2.0"
    assert evidence.metadata["datasets"] == ["c4"]
    assert evidence.metadata["shape"] == "huggingface"


def test_local_collector_auto_detects_ai_artifacts(tmp_path: Path) -> None:
    """Drop the three canonical AI artifacts into one directory and confirm
    the collector routes each to the right parser, with no errors."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "run.garak.jsonl").write_text(_GARAK_REPORT + "\n", encoding="utf-8")
    (artifacts / "model.lm-eval.json").write_text(_LM_EVAL_REPORT, encoding="utf-8")
    (artifacts / "model-card.json").write_text(_HF_MODEL_CARD, encoding="utf-8")

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts])
    report = collector.collect()

    assert report.errors == []
    types = {ev.evidence_type for ev in report.evidence}
    assert EvidenceType.PROMPT_INJECTION_TEST_RESULT in types
    assert EvidenceType.AI_SAFETY_EVAL in types
    assert EvidenceType.MODEL_CARD in types
