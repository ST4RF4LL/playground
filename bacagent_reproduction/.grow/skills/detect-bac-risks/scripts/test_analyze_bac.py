#!/usr/bin/env python3
"""Unit tests for Agent3 deterministic BAC pre-analysis."""

from __future__ import annotations

import unittest

from analyze_bac import analyze


def control(effective: bool) -> dict[str, object]:
    if effective:
        return {
            "observed": True,
            "trusted_identity": True,
            "role_match": True,
            "trusted_principal": True,
            "owner_relation_enforced": True,
            "dominates_sink": True,
            "fail_closed": True,
        }
    return {
        "observed": False,
        "trusted_identity": None,
        "role_match": None,
        "trusted_principal": None,
        "owner_relation_enforced": False,
        "dominates_sink": False,
        "fail_closed": False,
    }


class AnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.acp = {
            "repository": {"root": "/repo", "revision": "abc"},
            "quadruples": [
                {
                    "tuple": {
                        "D": "orders",
                        "O": "READ",
                        "R": "MEMBER",
                        "AC": "VAC+HAC",
                    },
                    "confidence": 0.96,
                },
                {
                    "tuple": {
                        "D": "admin_log",
                        "O": "DELETE",
                        "R": "ADMIN",
                        "AC": "VAC",
                    },
                    "confidence": 0.93,
                },
                {
                    "tuple": {
                        "D": "products",
                        "O": "READ",
                        "R": "PUBLIC",
                        "AC": "NONE",
                    },
                    "confidence": 0.99,
                },
            ],
            "limitations": [],
        }

    def path(
        self,
        path_id: str,
        d: str,
        operation: str,
        role: str,
        *,
        interface_type: str = "EXTERNAL",
        vac: dict[str, object] | None = None,
        hac: dict[str, object] | None = None,
        reachability: str = "REACHABLE",
        controllable: bool | None = True,
        coverage: str = "COMPLETE",
    ) -> dict[str, object]:
        return {
            "path_id": path_id,
            "api_id": f"api:{path_id}",
            "entrypoint": {
                "operation": f"OP {path_id}",
                "interface_type": interface_type,
            },
            "effective_role": role,
            "reachability": {
                "status": reachability,
                "external_triggerable": interface_type == "EXTERNAL",
            },
            "sink": {"D": d, "O": operation, "symbol": "mapper.call"},
            "input_flow": {"attacker_controllable": controllable},
            "implemented_controls": {
                **({"vac": vac} if vac is not None else {}),
                **({"hac": hac} if hac is not None else {}),
            },
            "coverage": coverage,
        }

    def test_external_missing_hac(self) -> None:
        paths = {
            "repository": {"root": "/repo", "revision": "abc"},
            "paths": [
                self.path(
                    "p1",
                    "orders",
                    "READ",
                    "MEMBER",
                    vac=control(True),
                    hac=control(False),
                )
            ],
            "limitations": [],
        }
        result = analyze(self.acp, paths)
        self.assertEqual(result["summary"]["findings"], 1)
        self.assertEqual(result["findings"][0]["classification"], "BHAC_CANDIDATE")
        self.assertEqual(result["findings"][0]["missing_controls"], ["HAC"])

    def test_internal_path_is_not_downgraded(self) -> None:
        paths = {
            "repository": {"root": "/repo", "revision": "abc"},
            "paths": [
                self.path(
                    "p2",
                    "admin_log",
                    "DELETE",
                    "ADMIN",
                    interface_type="INTERNAL",
                    vac=control(False),
                )
            ],
            "limitations": [],
        }
        result = analyze(self.acp, paths)
        finding = result["findings"][0]
        self.assertEqual(finding["classification"], "BVAC_CANDIDATE")
        self.assertEqual(finding["interface_type"], "INTERNAL")
        self.assertEqual(finding["confidence"], 0.93)

    def test_missing_facts_are_inconclusive(self) -> None:
        paths = {
            "repository": {"root": "/repo", "revision": "abc"},
            "paths": [
                self.path(
                    "p3",
                    "orders",
                    "READ",
                    "MEMBER",
                    vac=control(True),
                    hac=None,
                )
            ],
            "limitations": [],
        }
        result = analyze(self.acp, paths)
        self.assertEqual(result["summary"]["findings"], 0)
        self.assertEqual(result["summary"]["inconclusive_paths"], 1)
        self.assertEqual(result["inconclusive"][0]["unknown_controls"], ["HAC"])

    def test_unmatched_path_and_api_coverage(self) -> None:
        paths = {
            "repository": {"root": "/repo", "revision": "abc"},
            "paths": [
                self.path(
                    "p4",
                    "orders",
                    "UPDATE",
                    "MEMBER",
                    vac=control(True),
                    hac=control(True),
                )
            ],
            "limitations": [],
        }
        apis = {
            "apis": [
                {
                    "api_id": "api:p4",
                    "interface_type": "EXTERNAL",
                    "database_relevant": True,
                },
                {
                    "api_id": "api:internal-missing",
                    "interface_type": "INTERNAL",
                    "database_relevant": True,
                },
            ]
        }
        result = analyze(self.acp, paths, apis)
        self.assertEqual(result["summary"]["unmatched_paths"], 1)
        self.assertEqual(
            result["summary"]["uncovered_database_relevant_apis"], 1
        )

    def test_unreachable_path_is_suppressed(self) -> None:
        paths = {
            "repository": {"root": "/repo", "revision": "abc"},
            "paths": [
                self.path(
                    "p5",
                    "admin_log",
                    "DELETE",
                    "ADMIN",
                    vac=control(False),
                    reachability="UNREACHABLE",
                )
            ],
            "limitations": [],
        }
        result = analyze(self.acp, paths)
        self.assertEqual(result["summary"]["findings"], 0)
        self.assertEqual(result["summary"]["suppressed_unreachable_paths"], 1)


if __name__ == "__main__":
    unittest.main()
