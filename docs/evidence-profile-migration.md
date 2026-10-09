# Evidence profile migration and limits

These changes are in the development branch. PyPI 3.2.0 remains the published
collector until a separate release completes. The GitLab component has its own
version and installs the published collector.

## Bundle pins and CLI

The planned collector release is a major version because existing profile
semantics and newly generated digest pins change. The bundle schema stays at
2.1.0. New SBOM metadata and catalog descriptions
intentionally change newly generated structural digests. The sample moves from
`861b285dd8cb8427484e4ac64317675e48588b050e405916a90e18e5b04e3007` to
`6c9664455ca5bd2c0536d62417175e4305d105f808daffc33b55fc130873620e`.
Previously generated bundles retain their own pins: verification does not
re-run parsers or load a new catalog. Review and pin a new digest when
regenerating evidence.

`verify` checks the bundle schema before computing a digest. Invalid input or a
pin other than 64 hexadecimal characters exits 3; a different valid pin exits 2;
a match exits 0. Uppercase hexadecimal, surrounding whitespace and a
case-insensitive `sha256:` prefix are accepted.

With `--json-logs` or `SDLC_JSON_LOGS=1`, every stdout line is one JSON event,
including usage errors. `--version` prints `{"event": "version", "version": ...}`.
`--help` is exempt and stays plain text. Human errors use stderr.

Commands that print a document or data on stdout now wrap it in an event under
JSON logs. A pipeline that sets `SDLC_JSON_LOGS=1` globally and redirects one of
these commands into a file gets the event line, so read the payload key:

| Command | Event | Payload |
|---|---|---|
| `schema` without `--output` | `schema_emitted` | `.schema` holds the JSON Schema |
| `oscal` without `--output` | `oscal_emitted` | `.document` holds the OSCAL document, `.kind` names it |
| `plugins` | `plugins_listed` | `.plugins` maps each group to its names |
| `controls` | `controls_listed` | `.controls` lists the catalog |
| `doctor`, `doctor --json` | `doctor_checked` | `.checks` and `.failed`, as printed by `--json` |
| `compare`, `compare --format json` | `bundles_compared` | the comparison fields sit at the top level beside `event` |
| `exceptions list` | `exception_listed` per file, then `exceptions_summary` | `.exception` |
| `exceptions validate` | `exception_validated` per file | `.exception` |
| `verify` without `--expected` | `verify_computed` | `.sha256`, unchanged from 3.2.0 |

With `--output`, `schema` and `oscal` write the bare document to the file and
emit only the event naming it. When JSON logs are off, `schema`, `oscal`,
`compare --format json` and `doctor --json` still print the raw document.

Inputs accept UTF-8 with or without a BOM; raw hashes include the original BOM.
UTF-16 remains unsupported. Markdown reports escape untrusted emphasis, code
and strikethrough as well as links, HTML and table separators.

## SBOM minimum element presence

`metadata.cisa_2026_minimum_elements` reports all 17 elements of the final 2026
guidance. Entries have source paths and states `present`, `absent` or
`not_machine_checkable`. Values, authorship, signatures, license correctness
and dependency accuracy are not verified. A signature object alone does not
establish an author's signature. CycloneDX checks include root and child
components; paired hash algorithm and value must exist in the same entry.
An implicit document version is not explicit evidence.

AI-bearing SBOMs get `metadata.g7_2026_ai_minimum_elements`: 50 elements across
seven clusters. This is a project interpretation of CycloneDX/SPDX fields, not
an official format crosswalk or G7 conformance assessment. Unsupported fields
require manual review. G7 derivation links and CISA runtime dependencies use
separate checks. SPDX 3 support remains partial.

Legacy `cisa_2025_*` fields remain for consumers. The old
`cisa_2025_conformant` name denotes a historical presence check, not compliance.
No G7 gate, evidence type or framework enum is added.

## CRA operator context

After installing a release containing this change, use
`run --profile cra-2026 --cra-context cra-context.json`. Example:

```json
{
  "release_id": "release-2026-10",
  "commit_sha": "abcdef1234567890",
  "notification_type": "vulnerability",
  "awareness_at": "2026-10-01T10:00:00Z",
  "corrective_measure_available_at": "2026-10-04T12:00:00Z",
  "euvd_ids": ["EUVD-2026-4893"],
  "srp_fields": {"2": "Operator-supplied notification title"}
}
```

Release ID and SHA must match the CLI release. Choose `vulnerability` or
`incident`; timestamps require time zones. Without awareness evidence, the
profile records relative windows and no absolute early-warning deadline.

Article 14 supplies 24-hour and 72-hour windows from awareness. A vulnerability
final report is due 14 days after a corrective or mitigating measure becomes
available. An incident final report uses one calendar month after actual
72-hour notification submission, supplied as `notification_72h_submitted_at`.
Month-end dates clamp to the last valid day.

KEV and EPSS do not establish exploitation in this product, manufacturer
awareness or legal applicability; those states remain `not_assessed`.
Completeness uses ENISA SRP glossary 1.4, dated 1 October 2026, and records
required field IDs by stage. Narrative adequacy and operator timestamps need
human review. Context is hashed; supplied narratives are not repeated per
evidence. This is release context, not a per-CVE case or SRP submission payload.
Submission stays `not_submitted`.

Operator-derived deadlines participate in the structural hash. Only obsolete
collection-clock deadlines in legacy bundles remain excluded for compatibility.

## FedRAMP and framework references

`run --profile fedramp-20x --fedramp-class A` records operator-selected class
A–D and CR26 version 2026.10.05.01 at commit
`1c33385a06acf4faf50da2b9b4dc31cd826e5b91`. No automatic class or 10-year
retention rule is imposed.

Opt-in `catalog-fedramp-cr26.yaml` requests supporting evidence for six actual
KSI IDs. It does not verify persistent monitoring, validated automation,
cryptography, independent assessment or authorization. A generic test result
does not establish a recovery exercise. The legacy 20x catalog remains a
deprecated internal release-check catalog; its IDs are not official CR26 KSIs.

SP 800-218A references now use actual IDs: documentation PO.1.2 N1, provenance
PW.3.2, risk assessment PW.1.1 and vulnerability testing PW.8.2. Safety and bias
requirements remain project policy. Deployed-agent tool inventory is outside
that publication's model-development scope. No official AI 600-1 crosswalk is
claimed. CSF 2.0 descriptions use the SSDF 1.1 references preserved in ADR 0014;
they are not an AI-specific crosswalk or proof of control effectiveness.

## Scope decisions

B1's automatic BOD/SSVC decision engine is deferred. Supplied EPSS/KEV signals
remain available. The collector does not decide deployed-asset exposure,
agency obligations, missing decision points or SSVC outcomes. A future reader
of published SSVC assertions needs a separate input contract and pinned schemas.

E1's automatic GPAI compliance verdict is dropped from this release. Existing
model cards, lineage, evaluations and attestations support a manual review;
they do not establish provider role, applicable duties, documentation
completeness or delivery to regulators. Do not substitute an SBOM, Croissant
manifest or generic attestation for required regulatory documents.

D3 is limited to corrected official IDs and CSF traceability. Broader AI 600-1
risk mappings require explicit project judgment and are not generated.

## Output locking and recovery

Writers hold exclusive `.sdlc.lock` files in every output directory before
staging or replacing reports. A competing writer fails. Normal completion and
rollback remove owned locks.

A killed process may leave locks and staging files. Stop writers, inspect the
PID in the lock and confirm it has exited before removing that stale lock and
its owned temporary files. Never remove a live writer's lock. Network filesystem
behavior is unverified. Readers can observe the interval between replacements;
this guarantees writer consistency, not a transactional reader snapshot.

## CVSS and publication

OSV CVSS 4.0 scoring ports the FIRST reference at commit
`c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`, with BSD-2-Clause notices in
THIRD_PARTY_LICENSES.md. Mandatory metrics, duplicates and invalid values are
checked; CVSS 3.x behavior stays unchanged.

Source archives normalize timestamps, modes, owners, order and gzip metadata
while preserving payload bytes. Missing or differing wheel/sdist artifacts
block publication. Manual publication requires the requested tag to be the
workflow's selected tag ref; every checkout uses the triggering commit.

## Primary sources

- [CISA/ASD 2026 SBOM elements](https://www.cyber.gov.au/publication/2026-minimum-elements-for-a-software-bill-of-materials-sbom)
- [G7 SBOM for AI](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf?__blob=publicationFile&v=4)
- [CRA Article 14](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R2847)
- [ENISA SRP 1.4](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2)
- [Pinned FedRAMP CR26](https://github.com/FedRAMP/rules/blob/1c33385a06acf4faf50da2b9b4dc31cd826e5b91/fedramp-consolidated-rules.json)
- [NIST SP 800-218A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf)
- [Preserved CSF references](adr/0014-csf-2-crosswalk-for-built-in-catalogs.md)
