"""T6.5 — Unit tests for the AI evidence parsers.

All fixtures live inline as small literal JSON / JSONL payloads. The
shape of each payload is taken from the corresponding tool's
documented output:

* garak: https://reference.garak.ai/en/latest/reporting.html
* lm-eval-harness: https://github.com/EleutherAI/lm-evaluation-harness
* Hugging Face Hub model card: https://huggingface.co/docs/hub/model-cards
* Google Model Card Toolkit: https://github.com/tensorflow/model-card-toolkit

The tests deliberately do NOT instantiate or download any model. The
fixtures are frozen JSON, and a future fixture refresh should be done
with the procedure documented in ``tests/fixtures/ai/README.md``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.parsers._common import ParseError
from evidence_collector.parsers.garak import parse_garak
from evidence_collector.parsers.lm_eval import parse_lm_eval
from evidence_collector.parsers.model_card import parse_model_card

# ---------- garak ----------


def test_parse_garak_aggregates_digest_lines(tmp_path: Path) -> None:
    report = tmp_path / "run.garak.jsonl"
    report.write_text(
        "\n".join(
            [
                '{"entry_type":"init","garak_version":"0.10.0",'
                + '"model_name":"hf://google/flan-t5-small","model_type":"huggingface"}',
                '{"entry_type":"start_run","run":"abc"}',
                '{"entry_type":"digest","probe":"promptinject.HijackHateHumans","attempts":50,"hits":3}',
                '{"entry_type":"digest","probe":"promptinject.HijackKillHumans","attempts":50,"hits":0}',
                '{"entry_type":"end_run","run":"abc"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = parse_garak(report)
    assert parsed.tool_name == "garak"
    assert parsed.tool_version == "0.10.0"
    assert parsed.model_id == "hf://google/flan-t5-small"
    assert parsed.total_attempts == 100
    assert parsed.total_hits == 3
    assert {p.probe for p in parsed.probes} == {
        "promptinject.HijackHateHumans",
        "promptinject.HijackKillHumans",
    }
    # One probe with hits → ``high``; one clean → ``info``.
    assert parsed.findings_count["high"] == 1
    assert parsed.findings_count["info"] == 1


def test_parse_garak_falls_back_to_attempt_lines(tmp_path: Path) -> None:
    """When no ``digest`` line is present, attempt-level data is rolled up."""
    report = tmp_path / "partial.garak.jsonl"
    report.write_text(
        "\n".join(
            [
                '{"entry_type":"init","garak_version":"0.10.0","model_name":"x"}',
                '{"entry_type":"attempt","probe_classname":"injection.Test","passed":true}',
                '{"entry_type":"attempt","probe_classname":"injection.Test","passed":false}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parsed = parse_garak(report)
    assert len(parsed.probes) == 1
    assert parsed.probes[0].attempts == 2
    assert parsed.probes[0].hits == 1


def test_parse_garak_rejects_empty_file(tmp_path: Path) -> None:
    report = tmp_path / "empty.garak.jsonl"
    report.write_text("\n\n   \n", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_garak(report)


# ---------- lm-eval ----------


def test_parse_lm_eval_extracts_per_task_metrics(tmp_path: Path) -> None:
    report = tmp_path / "model.lm-eval.json"
    report.write_text(
        """
        {
          "results": {
            "truthfulqa_mc1": {"acc": 0.42, "acc_stderr": 0.01},
            "hellaswag":      {"acc": 0.71, "acc_norm": 0.78}
          },
          "config": {"model": "hf", "model_args": "pretrained=meta-llama/Llama-3.1-8B"},
          "versions": {"lm_eval": "0.4.4", "truthfulqa_mc1": "v1"}
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_lm_eval(report)
    assert parsed.tool_name == "lm-eval-harness"
    assert parsed.tool_version == "0.4.4"
    assert parsed.model_id == "meta-llama/Llama-3.1-8B"
    assert parsed.total_tasks == 2
    metrics_by_task = {t.task: t.metrics for t in parsed.tasks}
    assert metrics_by_task["truthfulqa_mc1"]["acc"] == pytest.approx(0.42)
    assert metrics_by_task["hellaswag"]["acc_norm"] == pytest.approx(0.78)


def test_parse_lm_eval_skips_non_numeric_metrics(tmp_path: Path) -> None:
    report = tmp_path / "lm-eval.json"
    report.write_text(
        """
        {
          "results": {"task_a": {"acc": "N/A", "perplexity": 12.3}},
          "config": {"model": "gpt2"},
          "versions": {}
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_lm_eval(report)
    assert parsed.tasks[0].metrics == {"perplexity": pytest.approx(12.3)}


def test_parse_lm_eval_rejects_missing_results(tmp_path: Path) -> None:
    report = tmp_path / "bad.lm-eval.json"
    report.write_text('{"config": {"model": "gpt2"}}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_lm_eval(report)


# ---------- model card ----------


def test_parse_model_card_huggingface_shape(tmp_path: Path) -> None:
    card = tmp_path / "model-card.json"
    card.write_text(
        """
        {
          "model_id": "google/flan-t5-small",
          "license": "apache-2.0",
          "datasets": ["c4", "wiki40b"],
          "intended_use": "Instruction-following research",
          "model-index": [
            {"name": "flan-t5-small", "results": [
              {"task": {"type": "text2text"}, "metrics": [
                {"name": "bleu", "value": 27.5},
                {"name": "rouge", "value": 41.2}
              ]}
            ]}
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_model_card(card)
    assert parsed.shape == "huggingface"
    assert parsed.model_id == "google/flan-t5-small"
    assert parsed.license == "apache-2.0"
    assert parsed.datasets == ["c4", "wiki40b"]
    assert parsed.metrics == {"bleu": pytest.approx(27.5), "rouge": pytest.approx(41.2)}
    assert parsed.intended_use == "Instruction-following research"


def test_parse_model_card_google_mct_shape(tmp_path: Path) -> None:
    card = tmp_path / "model-card.json"
    card.write_text(
        """
        {
          "model_details": {
            "name": "internal/fraud-detector-v3",
            "licenses": [{"identifier": "proprietary"}]
          },
          "considerations": {
            "use_cases": [{"description": "Detect card-not-present fraud."}]
          },
          "quantitative_analysis": {
            "performance_metrics": [
              {"type": "auc", "value": 0.94},
              {"type": "false_positive_rate", "value": 0.02}
            ]
          }
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_model_card(card)
    assert parsed.shape == "google-mct"
    assert parsed.model_id == "internal/fraud-detector-v3"
    assert parsed.license == "proprietary"
    assert parsed.metrics == {
        "auc": pytest.approx(0.94),
        "false_positive_rate": pytest.approx(0.02),
    }
    assert parsed.intended_use == "Detect card-not-present fraud."


def test_parse_model_card_rejects_generic_json(tmp_path: Path) -> None:
    card = tmp_path / "card.json"
    card.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_model_card(card)
