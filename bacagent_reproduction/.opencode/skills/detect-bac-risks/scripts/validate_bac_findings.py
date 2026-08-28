#!/usr/bin/env python3
"""Validate static BAC candidate output produced by detect-bac-risks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


TUPLE_KEYS = {"D", "O", "R", "AC"}
CLASSIFICATIONS = {
    "BVAC_CANDIDATE",
    "BHAC_CANDIDATE",
    "BVAC_BHAC_CANDIDATE",
}
CONTROLS = {"VAC", "HAC"}


def load_json(path: str) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["root must be an object"]
    if data.get("analysis_kind") != "STATIC_BAC_CANDIDATE_ANALYSIS":
        errors.append("analysis_kind must be STATIC_BAC_CANDIDATE_ANALYSIS")
    if not isinstance(data.get("summary"), dict):
        errors.append("summary must be an object")

    for key in (
        "findings",
        "inconclusive",
        "unmatched_paths",
        "suppressed_paths",
        "limitations",
    ):
        if not isinstance(data.get(key), list):
            errors.append(f"{key} must be an array")

    gaps = data.get("coverage_gaps")
    if not isinstance(gaps, dict):
        errors.append("coverage_gaps must be an object")
    else:
        for key in ("unreferenced_acp", "uncovered_apis", "unknown_api_relevance"):
            if not isinstance(gaps.get(key), list):
                errors.append(f"coverage_gaps.{key} must be an array")

    seen: set[str] = set()
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return errors
    for index, item in enumerate(findings):
        prefix = f"findings[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        finding_id = item.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            errors.append(f"{prefix}.finding_id must be a non-empty string")
        elif finding_id in seen:
            errors.append(f"{prefix}.finding_id duplicates {finding_id}")
        else:
            seen.add(finding_id)
        if item.get("status") != "CANDIDATE":
            errors.append(f"{prefix}.status must be CANDIDATE")
        if item.get("classification") not in CLASSIFICATIONS:
            errors.append(f"{prefix}.classification is invalid")
        tuple_value = item.get("tuple_ref")
        if not isinstance(tuple_value, dict) or set(tuple_value) != TUPLE_KEYS:
            errors.append(f"{prefix}.tuple_ref must contain exactly D,O,R,AC")
        missing = item.get("missing_controls")
        if (
            not isinstance(missing, list)
            or not missing
            or any(value not in CONTROLS for value in missing)
        ):
            errors.append(f"{prefix}.missing_controls must contain VAC and/or HAC")
        if item.get("validation_status") != "NOT_PERFORMED":
            errors.append(f"{prefix}.validation_status must be NOT_PERFORMED")
        confidence = item.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            errors.append(f"{prefix}.confidence must be a number from 0 to 1")

    summary = data.get("summary", {})
    if isinstance(summary, dict) and isinstance(findings, list):
        if summary.get("findings") != len(findings):
            errors.append("summary.findings does not match findings length")
        if summary.get("dynamic_validation_performed") is not False:
            errors.append("summary.dynamic_validation_performed must be false")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate bac-findings.json")
    parser.add_argument("json_file", help="Path to bac-findings.json")
    args = parser.parse_args()
    try:
        data = load_json(args.json_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    errors = validate(data)
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(f"VALID: {len(data['findings'])} static BAC candidate(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
