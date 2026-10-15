---
type: "quickstart"
title: "Secure SDLC Evidence Collector"
description: "Navigate collection, release decisions and CLI validation in the implemented evidence collector."
tags: ["evidence","sdlc","cli"]
sources:
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-884501b861b7372e2e6b7d8f
    resource: repo://src/evidence_collector/application/orchestrator.py
generated: { by: "codex", at: "2026-10-14T18:37:45.397Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-15T00:04:31.320Z
---

# Secure SDLC Evidence Collector

This repository provides a Python CLI that collects release evidence, evaluates a control catalog and exports a bundle with Markdown and HTML reports. The installed command is `sdlc-evidence`; the package requires Python 3.12 or newer ([package metadata](../pyproject.toml#L5-L12), [entrypoint](../pyproject.toml#L77-L78)).

## Start locally

Install the checkout with `python -m pip install -e ".[dev]"`, then use `sdlc-evidence --help` to select a command. The [README](../README.md) contains the sample-release invocation and full user documentation. Its fixtures demonstrate an example release; they do not establish that another release is ready.

## Choose a task

| Task | Page |
|---|---|
| Trace artifacts into the persisted reports | [Release pipeline](architecture/release-pipeline.md) |
| Interpret scores, gaps and release-anchor drift | [Evidence and readiness](concepts/evidence-and-readiness.md) |
| Integrate CLI outcomes and run repository checks | [CLI and CI](workflows/cli-and-ci.md) |
| Install and maintain the documentation integration | [OpenWiki setup](../docs/openwiki.md) |

## Check the outcome

`run_pipeline` collects local inputs, builds the bundle, applies the requested profile and writes the report set. The end-to-end tests cover a ready sample and missing critical evidence ([orchestrator](../src/evidence_collector/application/orchestrator.py#L219-L280), [tests](../tests/integration/test_end_to_end.py#L16-L62)). Read the bundle's evidence, gaps and collection errors with its verdict; generation or a passing fixture is not a compliance certification.
