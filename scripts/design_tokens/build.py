"""Write the colour tokens into every surface that shows them, or check for drift.

    python scripts/design_tokens/build.py --write   rewrite the generated blocks
    python scripts/design_tokens/build.py --check   exit 1 when a surface drifted

`tokens.json` is the one place a colour is chosen. Three surfaces read it: the
summary.html template (CSS custom properties per theme), the docs stylesheet
(`--ds-*` per Material scheme) and the CLI theme (`BRAND` in `_theme.py`).
The check also refuses a raw colour in the template outside its token block,
where it would escape the themes and the contrast test.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOKENS = Path(__file__).resolve().parent / "tokens.json"
TEMPLATE = REPO / "src/evidence_collector/exporters/templates/summary.html.j2"
DOCS_CSS = REPO / "docs/stylesheets/extra.css"
CLI_THEME = REPO / "src/evidence_collector/cli/_theme.py"

BEGIN = "/* tokens:begin (generated from tokens.json; edit that file, not this block) */"
END = "/* tokens:end */"
RAW_COLOUR = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\(")


def load() -> dict[str, Any]:
    tokens: dict[str, Any] = json.loads(TOKENS.read_text(encoding="utf-8"))
    return tokens


def declarations(values: dict[str, str], prefix: str, indent: str) -> str:
    return "".join(f"{indent}--{prefix}{name}: {value};\n" for name, value in values.items())


def shared(tokens: dict[str, Any], prefix: str, indent: str) -> str:
    fonts = {"sans": tokens["font"]["sans"], "mono": tokens["font"]["mono"]}
    return declarations(fonts, prefix, indent) + declarations(tokens["radius"], prefix, indent)


def template_block(tokens: dict[str, Any]) -> str:
    theme = tokens["theme"]
    return (
        "  :root {\n"
        "    color-scheme: light dark;\n"
        + shared(tokens, "", "    ")
        + declarations(theme["light"], "", "    ")
        + "  }\n"
        "  @media screen and (prefers-color-scheme: dark) {\n"
        "    :root {\n" + declarations(theme["dark"], "", "      ") + "    }\n"
        "  }\n"
        "  @media print {\n"
        "    :root {\n"
        "      color-scheme: light;\n" + declarations(theme["print"], "", "      ") + "    }\n"
        "  }\n"
    )


def docs_block(tokens: dict[str, Any]) -> str:
    theme = tokens["theme"]
    return (
        ":root {\n" + shared(tokens, "ds-", "  ") + "}\n"
        '[data-md-color-scheme="default"] {\n' + declarations(theme["light"], "ds-", "  ") + "}\n"
        '[data-md-color-scheme="slate"] {\n' + declarations(theme["dark"], "ds-", "  ") + "}\n"
        "@media print {\n"
        "  [data-md-color-scheme] {\n" + declarations(theme["print"], "ds-", "    ") + "  }\n"
        "}\n"
    )


def splice(text: str, block: str, indent: str) -> str:
    start = text.index(BEGIN) + len(BEGIN)
    end = text.index(END)
    return text[:start] + "\n" + block + indent + text[end:]


def raw_colours_outside_block(text: str) -> list[str]:
    outside = text[: text.index(BEGIN)] + text[text.index(END) :]
    style = outside[outside.index("<style>") : outside.index("</style>")]
    return sorted(set(RAW_COLOUR.findall(style)))


def cli_palette() -> dict[str, str]:
    tree = ast.parse(CLI_THEME.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "BRAND":
            palette: dict[str, str] = ast.literal_eval(node.value) if node.value else {}
            return palette
    raise SystemExit(f"BRAND not found in {CLI_THEME}")


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else "--check"
    if mode not in ("--write", "--check"):
        print(__doc__)
        return 2
    tokens = load()
    problems: list[str] = []
    for path, block, indent in (
        (TEMPLATE, template_block(tokens), "  "),
        (DOCS_CSS, docs_block(tokens), ""),
    ):
        current = path.read_text(encoding="utf-8")
        wanted = splice(current, block, indent)
        if mode == "--write":
            path.write_text(wanted, encoding="utf-8", newline="\n")
        elif current != wanted:
            problems.append(f"{path.name}: token block differs from tokens.json")
    stray = raw_colours_outside_block(TEMPLATE.read_text(encoding="utf-8"))
    if stray:
        problems.append(f"{TEMPLATE.name}: raw colour outside the token block: {stray}")
    if cli_palette() != tokens["cli"]:
        problems.append(f"{CLI_THEME.name}: BRAND differs from the 'cli' entry of tokens.json")
    for problem in problems:
        print("DRIFT", problem)
    print("tokens:", "written" if mode == "--write" else ("in sync" if not problems else "drifted"))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
