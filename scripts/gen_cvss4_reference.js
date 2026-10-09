// Regenerate tests/fixtures/cvss4_reference.json from FIRST's reference calculator.
//
// Usage:
//   node scripts/gen_cvss4_reference.js <first-dir> tests/fixtures/cvss4_reference.json [extra-vectors.txt]
//
// <first-dir> holds cvss_lookup.js, max_composed.js, max_severity.js and
// cvss_score.js from FIRSTdotorg/cvss-v4-calculator at the commit named in the
// fixture (BSD-2-Clause), for example fetched from
// https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/<commit>/<file>.
// The script rescores every case already in the fixture, appends any new
// vectors from the optional file (one per line), and recomputes the
// fingerprint over all 104,976 base vectors. Running it without an extra file
// must leave the fixture byte-identical.
"use strict";

const fs = require("fs");
const vm = require("vm");

const [firstDir, fixturePath, extraPath] = process.argv.slice(2);
if (!firstDir || !fixturePath) {
  console.error("usage: node gen_cvss4_reference.js <first-dir> <fixture.json> [extra.txt]");
  process.exit(2);
}

const context = {};
vm.createContext(context);
for (const name of ["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]) {
  vm.runInContext(fs.readFileSync(`${firstDir}/${name}`, "utf8"), context);
}
const OPTIONAL = ["E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
  "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"];

function score(vector) {
  const selected = Object.fromEntries(OPTIONAL.map((name) => [name, "X"]));
  for (const part of vector.split("/").slice(1)) {
    const [name, value] = part.split(":");
    selected[name] = value;
  }
  context.selected = selected;
  return vm.runInContext(
    "cvss_score(selected, cvssLookup_global, maxSeverity, macroVector(selected))",
    context,
  );
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const vectors = fixture.cases.map((item) => item.vector);
if (extraPath) {
  for (const line of fs.readFileSync(extraPath, "utf8").split(/\r?\n/)) {
    const vector = line.trim();
    if (vector && !vectors.includes(vector)) vectors.push(vector);
  }
}
fixture.cases = vectors.map((vector) => ({ vector, score: score(vector) }));

const BASE = { AV: "NALP", AC: "LH", AT: "NP", PR: "NLH", UI: "NPA", VC: "HLN",
  VI: "HLN", VA: "HLN", SC: "HLN", SI: "HLN", SA: "HLN" };
const names = Object.keys(BASE);
const hash = require("crypto").createHash("sha256");
let count = 0;
(function walk(index, parts) {
  if (index === names.length) {
    const vector = "CVSS:4.0/" + parts.join("/");
    hash.update(`${vector}|${score(vector).toFixed(1)}\n`);
    count += 1;
    return;
  }
  for (const value of BASE[names[index]]) walk(index + 1, [...parts, `${names[index]}:${value}`]);
})(0, []);
fixture.base_count = count;
fixture.base_sha256 = hash.digest("hex");

fs.writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + "\n");
console.log(`${fixture.cases.length} cases, base ${count} ${fixture.base_sha256}`);
