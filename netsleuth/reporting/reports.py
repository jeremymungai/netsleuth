"""Report dispatch: format writers + file output."""

from __future__ import annotations

import json
from pathlib import Path

from netsleuth.reporting import html as html_mod
from netsleuth.reporting import markdown as md_mod


def write_report(result, fmt: str, out_path: str, reveal: bool = False) -> str:
    """Render the report in ``fmt`` (json|md|html) and write to out_path."""
    if fmt == "json":
        data = json.dumps(result.to_dict(reveal_secrets=reveal), indent=2,
                          default=str)
        text = data
    elif fmt == "md":
        text = md_mod.generate_markdown(result)
    elif fmt == "html":
        text = html_mod.generate_html(result)
    else:
        raise ValueError(f"unknown report format: {fmt} (use json|md|html)")
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)
