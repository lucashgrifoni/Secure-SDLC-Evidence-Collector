# OSCAL JSON schemas (test fixtures)

These files are unmodified copies of the NIST OSCAL v1.1.2 JSON schemas, used
only by `tests/unit/test_oscal_schema_conformance.py` to validate the
assessment results the collector exports and the assessment plan it embeds.

| File | Source | SHA-256 |
|---|---|---|
| `oscal_assessment-results_schema.json` | https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_assessment-results_schema.json | `d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d` |
| `oscal_assessment-plan_schema.json` | https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_assessment-plan_schema.json | `43464ad048b711c735934b66015bcf8239782c6263d377a742c6b205ea796ecb` |

OSCAL is a work of the U.S. National Institute of Standards and Technology.
Works of the U.S. Government are not subject to copyright protection in the
United States (17 U.S.C. 105).

The schemas use Unicode property escapes such as `\p{L}`, which Python's `re`
module does not support, so the test checks the `pattern` keyword with the
`regex` package instead. No schema rule is relaxed.
