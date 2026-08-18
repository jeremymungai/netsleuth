"""Rule loading: built-in YAML signatures + user-supplied rule files.

A *rule* is a named regex with metadata (kind, confidence, score).
Built-in rules ship in ``netsleuth/signatures/*.yaml``; users extend or
override them with ``--rules myrules.yaml`` (a file, or a directory of
``*.yaml``). Later files with the same rule id replace earlier ones, so
users can tune built-ins instead of forking them.

Rule file format::

    rules:
      - id: my.flag
        kind: flag
        pattern: 'MYCTF\\{[!-~]{4,}\\}'
        confidence: high
        score: 100
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

BUILTIN_DIR = Path(__file__).parent / "signatures"


class RuleError(Exception):
    """Raised for rule files that cannot be parsed."""


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    pattern: str
    confidence: str = "medium"          # low | medium | high
    score: int = 20
    description: str = ""

    @property
    def regex(self) -> re.Pattern:
        # rules are applied to text extracted from packet bytes; scanning
        # is line-oriented so '.' never spans record separators we care about
        return re.compile(self.pattern, re.MULTILINE)


def parse_rule_file(path: str | Path, namespace: str = "") -> dict[str, Rule]:
    """Load one YAML rule file into {id: Rule}."""
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuleError(f"{p}: invalid YAML: {e}") from e
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not isinstance(raw.get("rules", []), list):
        raise RuleError(f"{p}: expected a top-level 'rules:' list")
    out: dict[str, Rule] = {}
    for i, entry in enumerate(raw["rules"]):
        if not isinstance(entry, dict):
            raise RuleError(f"{p}: rule #{i} is not a mapping")
        rid = entry.get("id") or f"rule{i}"
        if namespace:
            rid = f"{namespace}.{rid}"
        pattern = entry.get("pattern")
        if not pattern:
            raise RuleError(f"{p}: rule '{rid}' has no pattern")
        try:
            re.compile(pattern)
        except re.error as e:
            raise RuleError(f"{p}: rule '{rid}' has an invalid regex: {e}") from e
        out[rid] = Rule(
            id=rid, kind=entry.get("kind", "match"),
            pattern=pattern,
            confidence=str(entry.get("confidence", "medium")).lower(),
            score=int(entry.get("score", 20)),
            description=entry.get("description", ""),
        )
    return out


def load_rules(extra_paths: list[str] | None = None,
               include_builtin: bool = True) -> dict[str, Rule]:
    """Load built-in rules, then merge user rule files on top."""
    rules: dict[str, Rule] = {}
    if include_builtin:
        for f in sorted(BUILTIN_DIR.glob("*.yaml")):
            rules.update(parse_rule_file(f))
    for path in extra_paths or []:
        p = Path(path)
        if p.is_dir():
            files = sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml"))
            if not files:
                raise RuleError(f"{p}: directory contains no .yaml rule files")
            for f in files:
                rules.update(parse_rule_file(f))
        elif p.is_file():
            ns = p.stem if p.stem not in ("rules", "custom") else "custom"
            rules.update(parse_rule_file(p, namespace=ns))
        else:
            raise RuleError(f"rule path not found: {p}")
    return rules


def adhoc_rule(pattern: str, kind: str = "custom", rule_id: str = "cli.custom") -> Rule:
    """Compile a --pattern CLI argument into a Rule (invalid regex → RuleError)."""
    try:
        re.compile(pattern)
    except re.error as e:
        raise RuleError(f"invalid regex '{pattern}': {e}") from e
    return Rule(id=rule_id, kind=kind, pattern=pattern, confidence="high", score=100)
