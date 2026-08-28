#!/usr/bin/env python3
"""Compare intended ACP quadruples with path-level implemented controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable


TUPLE_KEYS = {"D", "O", "R", "AC"}
OPERATIONS = {"CREATE", "READ", "UPDATE", "DELETE"}
ACP_CONTROLS = {"NONE", "VAC", "HAC", "VAC+HAC"}
REACHABILITY = {"REACHABLE", "UNREACHABLE", "UNKNOWN"}
PATH_COVERAGE = {"COMPLETE", "PARTIAL", "UNKNOWN"}
INTERFACE_TYPES = {"EXTERNAL", "INTERNAL", "OTHER"}

CONTROL_FIELDS = {
    "VAC": (
        "observed",
        "trusted_identity",
        "role_match",
        "dominates_sink",
        "fail_closed",
    ),
    "HAC": (
        "observed",
        "trusted_principal",
        "owner_relation_enforced",
        "dominates_sink",
        "fail_closed",
    ),
}


class ContractError(ValueError):
    """Raised when an input violates the Agent3 contract."""


def load_json(path: str) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def normalize_repository(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"root": "unknown", "revision": "unknown"}
    return {
        "root": value.get("root", "unknown"),
        "revision": value.get("revision", "unknown"),
    }


def validate_acp(data: Any) -> tuple[dict[tuple[str, str, str], dict[str, Any]], list[str]]:
    errors: list[str] = []
    policies: dict[tuple[str, str, str], dict[str, Any]] = {}
    if not isinstance(data, dict):
        raise ContractError("ACP root must be an object")
    quadruples = data.get("quadruples")
    if not isinstance(quadruples, list):
        raise ContractError("ACP root.quadruples must be an array")

    for index, item in enumerate(quadruples):
        prefix = f"acp.quadruples[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        value = item.get("tuple")
        if not isinstance(value, dict):
            errors.append(f"{prefix}.tuple must be an object")
            continue
        if set(value) != TUPLE_KEYS:
            errors.append(f"{prefix}.tuple must contain exactly D,O,R,AC")
            continue
        if any(not non_empty_string(value.get(key)) for key in TUPLE_KEYS):
            errors.append(f"{prefix}.tuple values must be non-empty strings")
            continue
        if value["O"] not in OPERATIONS:
            errors.append(f"{prefix}.tuple.O is invalid: {value['O']!r}")
            continue
        if value["AC"] not in ACP_CONTROLS:
            errors.append(f"{prefix}.tuple.AC is invalid: {value['AC']!r}")
            continue
        confidence = item.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            errors.append(f"{prefix}.confidence must be a number from 0 to 1")
            continue
        key = (value["D"], value["O"], value["R"])
        if key in policies:
            errors.append(f"{prefix} duplicates ACP identity {key!r}")
            continue
        policies[key] = item
    return policies, errors


def validate_paths(data: Any) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    valid: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        raise ContractError("access-path root must be an object")
    paths = data.get("paths")
    if not isinstance(paths, list):
        raise ContractError("access-path root.paths must be an array")

    seen: set[str] = set()
    for index, item in enumerate(paths):
        prefix = f"paths.paths[{index}]"
        item_errors: list[str] = []
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        path_id = item.get("path_id")
        if not non_empty_string(path_id):
            item_errors.append(f"{prefix}.path_id must be a non-empty string")
        elif path_id in seen:
            item_errors.append(f"{prefix}.path_id duplicates {path_id!r}")
        else:
            seen.add(path_id)

        role = item.get("effective_role")
        if not non_empty_string(role):
            item_errors.append(f"{prefix}.effective_role must be a non-empty string")

        sink = item.get("sink")
        if not isinstance(sink, dict):
            item_errors.append(f"{prefix}.sink must be an object")
        else:
            if not non_empty_string(sink.get("D")):
                item_errors.append(f"{prefix}.sink.D must be a non-empty string")
            if sink.get("O") not in OPERATIONS:
                item_errors.append(f"{prefix}.sink.O must be one of {sorted(OPERATIONS)}")

        entrypoint = item.get("entrypoint")
        if not isinstance(entrypoint, dict):
            item_errors.append(f"{prefix}.entrypoint must be an object")
        else:
            interface_type = entrypoint.get("interface_type", "OTHER")
            if interface_type not in INTERFACE_TYPES:
                item_errors.append(
                    f"{prefix}.entrypoint.interface_type must be one of "
                    f"{sorted(INTERFACE_TYPES)}"
                )

        reachability = item.get("reachability", {})
        if not isinstance(reachability, dict):
            item_errors.append(f"{prefix}.reachability must be an object")
        elif reachability.get("status", "UNKNOWN") not in REACHABILITY:
            item_errors.append(
                f"{prefix}.reachability.status must be one of {sorted(REACHABILITY)}"
            )

        coverage = item.get("coverage", "UNKNOWN")
        if coverage not in PATH_COVERAGE:
            item_errors.append(f"{prefix}.coverage must be one of {sorted(PATH_COVERAGE)}")

        if item_errors:
            errors.extend(item_errors)
        else:
            valid.append(item)
    return valid, errors


def required_controls(ac: str) -> list[str]:
    if ac == "VAC":
        return ["VAC"]
    if ac == "HAC":
        return ["HAC"]
    if ac == "VAC+HAC":
        return ["VAC", "HAC"]
    return []


def get_control_object(path: dict[str, Any], control: str) -> dict[str, Any] | None:
    controls = path.get("implemented_controls")
    if not isinstance(controls, dict):
        return None
    value = controls.get(control.lower(), controls.get(control))
    return value if isinstance(value, dict) else None


def evaluate_control(path: dict[str, Any], control: str) -> dict[str, Any]:
    value = get_control_object(path, control)
    fields = CONTROL_FIELDS[control]
    if value is None:
        return {
            "control": control,
            "state": "UNKNOWN",
            "reasons": ["control facts are missing"],
            "evidence": [],
        }

    reasons: list[str] = []
    unknown: list[str] = []
    for field in fields:
        fact = value.get(field)
        if fact is False:
            reasons.append(f"{field}=false")
        elif fact is not True:
            unknown.append(field)

    if reasons:
        state = "MISSING"
        detail = reasons
        if unknown:
            detail.append("unknown: " + ", ".join(unknown))
    elif unknown:
        state = "UNKNOWN"
        detail = ["unknown: " + ", ".join(unknown)]
    else:
        state = "EFFECTIVE"
        detail = []

    evidence = value.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    return {
        "control": control,
        "state": state,
        "reasons": detail,
        "evidence": evidence,
    }


def entrypoint_summary(path: dict[str, Any]) -> str:
    entrypoint = path.get("entrypoint", {})
    if not isinstance(entrypoint, dict):
        return "unknown"
    return (
        entrypoint.get("operation")
        or entrypoint.get("symbol")
        or path.get("api_id")
        or "unknown"
    )


def path_interface_type(path: dict[str, Any]) -> str:
    entrypoint = path.get("entrypoint", {})
    if not isinstance(entrypoint, dict):
        return "OTHER"
    return entrypoint.get("interface_type", "OTHER")


def classification(missing: list[str]) -> str:
    values = set(missing)
    if values == {"VAC"}:
        return "BVAC_CANDIDATE"
    if values == {"HAC"}:
        return "BHAC_CANDIDATE"
    return "BVAC_BHAC_CANDIDATE"


def stable_finding_id(
    tuple_value: dict[str, str], path_id: str, missing: Iterable[str]
) -> str:
    raw = "|".join(
        [
            tuple_value["D"],
            tuple_value["O"],
            tuple_value["R"],
            tuple_value["AC"],
            path_id,
            ",".join(sorted(missing)),
        ]
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()
    return f"BAC-{digest}"


def confidence_for(
    policy: dict[str, Any],
    path: dict[str, Any],
    unknown_controls: list[str],
    revision_mismatch: bool,
) -> tuple[float, str, list[str]]:
    score = float(policy.get("confidence", 0.5))
    factors: list[str] = [f"ACP confidence={score:.2f}"]

    if revision_mismatch:
        score -= 0.20
        factors.append("-0.20 revision mismatch")

    coverage = path.get("coverage", "UNKNOWN")
    if coverage == "PARTIAL":
        score -= 0.15
        factors.append("-0.15 partial path coverage")
    elif coverage == "UNKNOWN":
        score -= 0.20
        factors.append("-0.20 unknown path coverage")

    reachability = path.get("reachability", {})
    reachability_status = (
        reachability.get("status", "UNKNOWN")
        if isinstance(reachability, dict)
        else "UNKNOWN"
    )
    if reachability_status == "UNKNOWN":
        score -= 0.10
        factors.append("-0.10 unknown reachability")

    input_flow = path.get("input_flow", {})
    controllable = (
        input_flow.get("attacker_controllable")
        if isinstance(input_flow, dict)
        else None
    )
    if controllable is False:
        score -= 0.20
        factors.append("-0.20 attacker controllability is false")
    elif controllable is not True:
        score -= 0.10
        factors.append("-0.10 attacker controllability is unknown")

    if unknown_controls:
        penalty = min(0.20, 0.10 * len(unknown_controls))
        score -= penalty
        factors.append(f"-{penalty:.2f} required controls remain unknown")

    score = round(max(0.0, min(1.0, score)), 2)
    if score >= 0.85:
        band = "HIGH"
    elif score >= 0.65:
        band = "MEDIUM"
    else:
        band = "LOW"
    return score, band, factors


def unique_values(values: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def analyze(
    acp_data: dict[str, Any],
    path_data: dict[str, Any],
    api_data: dict[str, Any] | None = None,
    input_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    policies, acp_errors = validate_acp(acp_data)
    paths, path_errors = validate_paths(path_data)
    errors = acp_errors + path_errors
    if errors:
        raise ContractError("\n".join(errors))

    acp_repository = normalize_repository(acp_data.get("repository"))
    path_repository = normalize_repository(path_data.get("repository"))
    acp_revision = acp_repository.get("revision")
    path_revision = path_repository.get("revision")
    revision_mismatch = (
        non_empty_string(acp_revision)
        and non_empty_string(path_revision)
        and acp_revision != "unknown"
        and path_revision != "unknown"
        and acp_revision != path_revision
    )

    findings: list[dict[str, Any]] = []
    inconclusive: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    used_policies: set[tuple[str, str, str]] = set()
    covered_api_ids: set[str] = set()

    for path in paths:
        path_id = path["path_id"]
        api_id = path.get("api_id")
        if non_empty_string(api_id):
            covered_api_ids.add(api_id)
        sink = path["sink"]
        role = path["effective_role"]
        key = (sink["D"], sink["O"], role)
        policy = policies.get(key)

        if policy is None:
            candidate_roles = sorted(
                item_key[2]
                for item_key in policies
                if item_key[0] == sink["D"] and item_key[1] == sink["O"]
            )
            unmatched.append(
                {
                    "type": "UNMATCHED_PATH",
                    "path_id": path_id,
                    "api_id": api_id,
                    "entrypoint": entrypoint_summary(path),
                    "interface_type": path_interface_type(path),
                    "sink": sink,
                    "effective_role": role,
                    "candidate_acp_roles": candidate_roles,
                    "reason": "No exact ACP matched sink D/O and effective role.",
                }
            )
            continue

        used_policies.add(key)
        tuple_value = {
            "D": policy["tuple"]["D"],
            "O": policy["tuple"]["O"],
            "R": policy["tuple"]["R"],
            "AC": policy["tuple"]["AC"],
        }
        required = required_controls(tuple_value["AC"])
        evaluations = {
            control: evaluate_control(path, control) for control in ("VAC", "HAC")
        }
        effective = [
            control
            for control, result in evaluations.items()
            if result["state"] == "EFFECTIVE"
        ]
        missing = [
            control
            for control in required
            if evaluations[control]["state"] == "MISSING"
        ]
        unknown = [
            control
            for control in required
            if evaluations[control]["state"] == "UNKNOWN"
        ]

        reachability = path.get("reachability", {})
        reachability_status = (
            reachability.get("status", "UNKNOWN")
            if isinstance(reachability, dict)
            else "UNKNOWN"
        )
        if reachability_status == "UNREACHABLE":
            suppressed.append(
                {
                    "type": "PROVEN_UNREACHABLE",
                    "path_id": path_id,
                    "api_id": api_id,
                    "entrypoint": entrypoint_summary(path),
                    "tuple_ref": tuple_value,
                    "would_be_missing": missing,
                    "unknown_controls": unknown,
                    "reachability": reachability,
                }
            )
            continue

        score, band, factors = confidence_for(
            policy, path, unknown, revision_mismatch
        )
        input_flow = path.get("input_flow", {})
        controllable = (
            input_flow.get("attacker_controllable")
            if isinstance(input_flow, dict)
            else None
        )
        sink_copy = {
            "D": sink.get("D"),
            "O": sink.get("O"),
            "symbol": sink.get("symbol"),
            "location": sink.get("location"),
        }
        control_evidence = unique_values(
            evidence
            for control in required
            for evidence in evaluations[control].get("evidence", [])
        )
        path_evidence = path.get("evidence", [])
        if not isinstance(path_evidence, list):
            path_evidence = []
        evidence = unique_values([*path_evidence, *control_evidence])

        if missing:
            reasons = {
                control: evaluations[control]["reasons"] for control in missing
            }
            root_cause = "; ".join(
                f"{control}: {', '.join(reasons[control])}" for control in missing
            )
            finding = {
                "finding_id": stable_finding_id(tuple_value, path_id, missing),
                "status": "CANDIDATE",
                "classification": classification(missing),
                "tuple_ref": tuple_value,
                "path_id": path_id,
                "api_id": api_id,
                "entrypoint": path.get("entrypoint", {}),
                "interface_type": path_interface_type(path),
                "sink": sink_copy,
                "required_controls": required,
                "effective_controls": effective,
                "missing_controls": missing,
                "unknown_controls": unknown,
                "control_evaluation": evaluations,
                "reachability": reachability,
                "attacker_controllable": controllable,
                "input_flow": input_flow,
                "root_cause": root_cause,
                "evidence": evidence,
                "confidence": score,
                "confidence_band": band,
                "confidence_factors": factors,
                "review_required": bool(
                    unknown
                    or reachability_status == "UNKNOWN"
                    or path.get("coverage", "UNKNOWN") != "COMPLETE"
                    or controllable is not True
                    or revision_mismatch
                ),
                "validation_status": "NOT_PERFORMED",
            }
            findings.append(finding)
        elif unknown:
            inconclusive.append(
                {
                    "type": "REQUIRED_CONTROL_UNKNOWN",
                    "path_id": path_id,
                    "api_id": api_id,
                    "entrypoint": entrypoint_summary(path),
                    "interface_type": path_interface_type(path),
                    "tuple_ref": tuple_value,
                    "sink": sink_copy,
                    "required_controls": required,
                    "effective_controls": effective,
                    "unknown_controls": unknown,
                    "control_evaluation": {
                        control: evaluations[control] for control in unknown
                    },
                    "reachability": reachability,
                    "attacker_controllable": controllable,
                    "confidence": score,
                    "confidence_band": band,
                    "reason": "Required control facts are incomplete; inspect source on demand.",
                }
            )

    unreferenced_acp = [
        {
            "tuple_ref": {
                "D": item["tuple"]["D"],
                "O": item["tuple"]["O"],
                "R": item["tuple"]["R"],
                "AC": item["tuple"]["AC"],
            },
            "confidence": item.get("confidence"),
        }
        for key, item in policies.items()
        if key not in used_policies
    ]

    uncovered_apis: list[dict[str, Any]] = []
    unknown_api_relevance: list[dict[str, Any]] = []
    api_errors: list[str] = []
    if api_data is not None:
        apis = api_data.get("apis") if isinstance(api_data, dict) else None
        if not isinstance(apis, list):
            api_errors.append("api-catalog root.apis must be an array")
        else:
            seen_api_ids: set[str] = set()
            for index, api in enumerate(apis):
                if not isinstance(api, dict) or not non_empty_string(api.get("api_id")):
                    api_errors.append(f"api-catalog.apis[{index}].api_id is invalid")
                    continue
                api_id = api["api_id"]
                if api_id in seen_api_ids:
                    api_errors.append(f"api-catalog.apis[{index}] duplicates {api_id!r}")
                    continue
                seen_api_ids.add(api_id)
                if api_id in covered_api_ids:
                    continue
                record = {
                    "api_id": api_id,
                    "interface_type": api.get("interface_type", "OTHER"),
                    "database_relevant": api.get("database_relevant"),
                }
                if api.get("database_relevant") is True:
                    uncovered_apis.append(record)
                elif api.get("database_relevant") is not False:
                    unknown_api_relevance.append(record)
    if api_errors:
        raise ContractError("\n".join(api_errors))

    limitations = list(acp_data.get("limitations", []))
    limitations.extend(path_data.get("limitations", []))
    acp_coverage = acp_data.get("coverage", {})
    if isinstance(acp_coverage, dict):
        limitations.extend(acp_coverage.get("known_gaps", []))
    path_coverage = path_data.get("coverage", {})
    if isinstance(path_coverage, dict):
        limitations.extend(path_coverage.get("known_gaps", []))
    if revision_mismatch:
        limitations.append(
            {
                "type": "REVISION_MISMATCH",
                "acp_revision": acp_revision,
                "path_revision": path_revision,
            }
        )
    limitations = unique_values(limitations)

    findings.sort(key=lambda item: item["finding_id"])
    inconclusive.sort(key=lambda item: item["path_id"])
    unmatched.sort(key=lambda item: item["path_id"])
    suppressed.sort(key=lambda item: item["path_id"])
    unreferenced_acp.sort(
        key=lambda item: (
            item["tuple_ref"]["D"],
            item["tuple_ref"]["O"],
            item["tuple_ref"]["R"],
        )
    )

    complete = not any(
        [
            inconclusive,
            unmatched,
            unreferenced_acp,
            uncovered_apis,
            unknown_api_relevance,
            limitations,
            revision_mismatch,
        ]
    )

    return {
        "schema_version": "1.0",
        "analysis_kind": "STATIC_BAC_CANDIDATE_ANALYSIS",
        "repository": {
            "root": path_repository.get("root") or acp_repository.get("root"),
            "revision": path_revision,
            "acp_revision": acp_revision,
            "revision_match": not revision_mismatch,
        },
        "inputs": input_paths or {},
        "summary": {
            "acp_quadruples": len(policies),
            "access_paths": len(paths),
            "matched_paths": len(paths) - len(unmatched),
            "findings": len(findings),
            "bvac_candidates": sum(
                1
                for item in findings
                if item["classification"] in {"BVAC_CANDIDATE", "BVAC_BHAC_CANDIDATE"}
            ),
            "bhac_candidates": sum(
                1
                for item in findings
                if item["classification"] in {"BHAC_CANDIDATE", "BVAC_BHAC_CANDIDATE"}
            ),
            "inconclusive_paths": len(inconclusive),
            "unmatched_paths": len(unmatched),
            "suppressed_unreachable_paths": len(suppressed),
            "unreferenced_acp": len(unreferenced_acp),
            "uncovered_database_relevant_apis": len(uncovered_apis),
            "unknown_api_relevance": len(unknown_api_relevance),
            "analysis_complete": complete,
            "dynamic_validation_performed": False,
        },
        "findings": findings,
        "inconclusive": inconclusive,
        "unmatched_paths": unmatched,
        "suppressed_paths": suppressed,
        "coverage_gaps": {
            "unreferenced_acp": unreferenced_acp,
            "uncovered_apis": uncovered_apis,
            "unknown_api_relevance": unknown_api_relevance,
        },
        "limitations": limitations,
    }


def markdown_escape(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def bool_text(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Static BAC candidate report",
        "",
        "> This report contains static candidates only. Dynamic validation was not performed.",
        "",
        "## Summary",
        "",
        "| Metric | Count/value |",
        "|---|---:|",
        f"| ACP quadruples | {summary['acp_quadruples']} |",
        f"| Access paths | {summary['access_paths']} |",
        f"| Candidate findings | {summary['findings']} |",
        f"| BVAC candidates | {summary['bvac_candidates']} |",
        f"| BHAC candidates | {summary['bhac_candidates']} |",
        f"| Inconclusive paths | {summary['inconclusive_paths']} |",
        f"| Unmatched paths | {summary['unmatched_paths']} |",
        f"| Unreferenced ACP | {summary['unreferenced_acp']} |",
        f"| Analysis complete | {str(summary['analysis_complete']).lower()} |",
        "",
        "## Candidates",
        "",
    ]
    findings = result["findings"]
    if findings:
        lines.extend(
            [
                "| ID | Class | Interface | Entry point | ACP | Missing | Controllable | Confidence | Review |",
                "|---|---|---|---|---|---|---|---:|---|",
            ]
        )
        for finding in findings:
            tuple_value = finding["tuple_ref"]
            tuple_text = (
                f"<{tuple_value['D']}, {tuple_value['O']}, "
                f"{tuple_value['R']}, {tuple_value['AC']}>"
            )
            lines.append(
                "| {id} | {classification} | {interface} | {entrypoint} | "
                "{tuple_value} | {missing} | {controllable} | {confidence:.2f} "
                "({band}) | {review} |".format(
                    id=markdown_escape(finding["finding_id"]),
                    classification=markdown_escape(finding["classification"]),
                    interface=markdown_escape(finding["interface_type"]),
                    entrypoint=markdown_escape(entrypoint_summary(finding)),
                    tuple_value=markdown_escape(tuple_text),
                    missing=markdown_escape(",".join(finding["missing_controls"])),
                    controllable=bool_text(finding["attacker_controllable"]),
                    confidence=finding["confidence"],
                    band=finding["confidence_band"],
                    review=str(finding["review_required"]).lower(),
                )
            )
        lines.append("")
        for finding in findings:
            lines.extend(
                [
                    f"### {finding['finding_id']}",
                    "",
                    f"- Path: `{finding['path_id']}`",
                    f"- Sink: `{finding['sink'].get('symbol') or 'unknown'}` at "
                    f"`{finding['sink'].get('location') or 'unknown'}`",
                    f"- Root cause: {finding['root_cause']}",
                    "- Validation: not performed",
                    "",
                ]
            )
    else:
        lines.extend(["No explicit missing-control candidates were produced.", ""])

    lines.extend(["## Inconclusive paths", ""])
    if result["inconclusive"]:
        for item in result["inconclusive"]:
            lines.append(
                f"- `{item['path_id']}`: unknown "
                f"{', '.join(item['unknown_controls'])}"
            )
    else:
        lines.append("None.")
    lines.extend(["", "## Unmatched paths", ""])
    if result["unmatched_paths"]:
        for item in result["unmatched_paths"]:
            lines.append(
                f"- `{item['path_id']}`: "
                f"<{item['sink']['D']}, {item['sink']['O']}, "
                f"{item['effective_role']}>"
            )
    else:
        lines.append("None.")

    gaps = result["coverage_gaps"]
    lines.extend(["", "## Coverage gaps", ""])
    lines.append(f"- Unreferenced ACP: {len(gaps['unreferenced_acp'])}")
    lines.append(f"- Uncovered database-relevant APIs: {len(gaps['uncovered_apis'])}")
    lines.append(f"- APIs with unknown database relevance: {len(gaps['unknown_api_relevance'])}")

    lines.extend(["", "## Limitations", ""])
    if result["limitations"]:
        for item in result["limitations"]:
            if isinstance(item, str):
                lines.append(f"- {item}")
            else:
                lines.append(f"- `{json.dumps(item, ensure_ascii=False, sort_keys=True)}`")
    else:
        lines.append("None reported.")
    lines.append("")
    return "\n".join(lines)


def write_json(path: str, data: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_text(path: str, text: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare ACP quadruples with API access paths for static BAC candidates."
    )
    parser.add_argument("--acp", required=True, help="Agent2 ACP JSON")
    parser.add_argument("--paths", required=True, help="Agent1 access-path JSON")
    parser.add_argument("--api-catalog", help="Optional Agent1 API catalog JSON")
    parser.add_argument("--output", required=True, help="Output bac-findings JSON")
    parser.add_argument("--markdown", help="Optional Markdown report")
    args = parser.parse_args()

    try:
        acp_data = load_json(args.acp)
        path_data = load_json(args.paths)
        api_data = load_json(args.api_catalog) if args.api_catalog else None
        result = analyze(
            acp_data,
            path_data,
            api_data,
            {
                "acp": Path(args.acp).name,
                "access_paths": Path(args.paths).name,
                **(
                    {"api_catalog": Path(args.api_catalog).name}
                    if args.api_catalog
                    else {}
                ),
            },
        )
        write_json(args.output, result)
        if args.markdown:
            write_text(args.markdown, render_markdown(result))
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = result["summary"]
    print(
        "OK: "
        f"{summary['findings']} candidate(s), "
        f"{summary['inconclusive_paths']} inconclusive, "
        f"{summary['unmatched_paths']} unmatched"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
