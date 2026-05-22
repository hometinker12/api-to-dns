"""Debug L729 onsubmit: simulate linter/JS parse and Jinja render."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

LOG = Path(__file__).resolve().parents[1] / "debug-81baf0.log"
TEMPLATE = Path(__file__).resolve().parents[1] / "src" / "templates" / "settings.html"


def log(hypothesis_id: str, message: str, data: dict, run_id: str) -> None:
    entry = {
        "sessionId": "81baf0",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": "scripts/debug_settings_l729.py",
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def main() -> None:
    run_id = "post-fix"
    line = TEMPLATE.read_text(encoding="utf-8").splitlines()[728]

    # H-A: nested double quotes terminate the HTML/JS string early
    attr_match = re.search(r'onsubmit="([^"]*)"', line)
    attr_value = attr_match.group(1) if attr_match else None
    nested_double_in_jinja = '"Regenerate' in line or '"Create a self-signed' in line

    # H-B: Jinja {{ inside onsubmit confuses JS parser even with tojson
    has_jinja_in_onsubmit = "{{" in line and "onsubmit" in line

    # H-C: tojson renders valid JS string
    from jinja2 import Environment

    env = Environment()
    for cert_exists in (True, False):
        rendered = env.from_string(
            "{{ ('Regenerate the self-signed certificate? This overwrites the currently installed key/cert.' "
            "if cert_exists else 'Create a self-signed certificate now?') | tojson }}"
        ).render(cert_exists=cert_exists)
        log(
            "C",
            "tojson render",
            {"cert_exists": cert_exists, "rendered": rendered, "starts_with_quote": rendered[0] in "\"'"},
            run_id,
        )

    log(
        "A",
        "nested double quotes in source line",
        {"nested_double_in_jinja": nested_double_in_jinja, "line_preview": line[:120]},
        run_id,
    )
    log(
        "B",
        "jinja inside onsubmit attribute",
        {"has_jinja_in_onsubmit": has_jinja_in_onsubmit, "attr_value_preview": (attr_value or "")[:80]},
        run_id,
    )

    # H-D: broken attr leaves unterminated JS when parsed naively
    if attr_value:
        naive_js = f"return {attr_value}"
        unterminated = naive_js.count("'") % 2 == 1 or naive_js.count('"') % 2 == 1
        log(
            "D",
            "naive JS string balance in onsubmit value",
            {"unterminated": unterminated, "naive_js_preview": naive_js[:100]},
            run_id,
        )


if __name__ == "__main__":
    main()
