# Agent3 input and output contract

## Contents

1. ACP input
2. Access-path input
3. Optional API catalog
4. Findings output
5. Coverage semantics

## 1. ACP input

Use the Agent2 envelope:

```json
{
  "schema_version": "1.0",
  "repository": {
    "root": "/repo",
    "revision": "git-sha"
  },
  "quadruples": [
    {
      "tuple": {
        "D": "oms_order",
        "O": "READ",
        "R": "MEMBER",
        "AC": "VAC+HAC"
      },
      "confidence": 0.97,
      "evidence": [
        {
          "kind": "owner-check",
          "location": "OrderService.java:42",
          "detail": "Secure list paths constrain member_id to the current member."
        }
      ]
    }
  ],
  "unresolved": [],
  "out_of_model": [],
  "limitations": []
}
```

The object under `tuple` must contain exactly `D`, `O`, `R`, and `AC`.

## 2. Access-path input

Use one item per entry-point-to-database-operation path. Split an entry point that reaches multiple database operations.

```json
{
  "schema_version": "1.0",
  "repository": {
    "root": "/repo",
    "revision": "git-sha"
  },
  "coverage": {
    "entrypoints_discovered": 1,
    "paths_emitted": 1,
    "known_gaps": []
  },
  "paths": [
    {
      "path_id": "portal:http:GET:/order/detail/{orderId}:oms_order:READ",
      "api_id": "portal:http:GET:/order/detail/{orderId}",
      "entrypoint": {
        "protocol": "HTTP",
        "operation": "GET /order/detail/{orderId}",
        "symbol": "OmsPortalOrderController.detail",
        "location": "OmsPortalOrderController.java:137",
        "interface_type": "EXTERNAL",
        "boundary": "INTERNET",
        "caller_kind": "END_USER"
      },
      "effective_role": "MEMBER",
      "reachability": {
        "status": "REACHABLE",
        "external_triggerable": true,
        "evidence": []
      },
      "sink": {
        "D": "oms_order",
        "O": "READ",
        "symbol": "orderMapper.selectByPrimaryKey",
        "location": "OmsPortalOrderServiceImpl.java:396"
      },
      "input_flow": {
        "attacker_controllable": true,
        "source": "PathVariable orderId",
        "sink_argument": "orderId",
        "evidence": []
      },
      "implemented_controls": {
        "vac": {
          "observed": true,
          "trusted_identity": true,
          "role_match": true,
          "dominates_sink": true,
          "fail_closed": true,
          "evidence": []
        },
        "hac": {
          "observed": false,
          "trusted_principal": null,
          "owner_relation_enforced": false,
          "dominates_sink": false,
          "fail_closed": false,
          "evidence": []
        }
      },
      "call_chain": [],
      "evidence": [],
      "coverage": "COMPLETE",
      "known_gaps": []
    }
  ]
}
```

Allowed values:

- `sink.O`: `CREATE`, `READ`, `UPDATE`, `DELETE`;
- `entrypoint.interface_type`: `EXTERNAL`, `INTERNAL`, or `OTHER`;
- `reachability.status`: `REACHABLE`, `UNREACHABLE`, or `UNKNOWN`;
- `coverage`: `COMPLETE`, `PARTIAL`, or `UNKNOWN`.

Boolean control facts allow `true`, `false`, or JSON `null`. Missing fields mean unknown.

VAC effectiveness requires all of:

- `observed`;
- `trusted_identity`;
- `role_match`;
- `dominates_sink`;
- `fail_closed`.

HAC effectiveness requires all of:

- `observed`;
- `trusted_principal`;
- `owner_relation_enforced`;
- `dominates_sink`;
- `fail_closed`.

For a query restriction, owner assignment, or equivalent excluding mechanism, set `fail_closed: true` when a resource outside the owner relation cannot reach the sink effect.

Internal paths use the same fields and rules. `external_triggerable: false` does not exempt or suppress an internal path.

## 3. Optional API catalog

```json
{
  "schema_version": "1.0",
  "repository": {
    "root": "/repo",
    "revision": "git-sha"
  },
  "apis": [
    {
      "api_id": "portal:http:GET:/order/detail/{orderId}",
      "interface_type": "EXTERNAL",
      "database_relevant": true
    },
    {
      "api_id": "order:rpc:OrderQueryService.get",
      "interface_type": "INTERNAL",
      "database_relevant": true
    }
  ]
}
```

An API with `database_relevant: true` must be represented by at least one access path. Missing or `null` relevance is a coverage question, not permission to ignore the API.

## 4. Findings output

The analyzer writes:

```json
{
  "schema_version": "1.0",
  "analysis_kind": "STATIC_BAC_CANDIDATE_ANALYSIS",
  "repository": {},
  "inputs": {},
  "summary": {},
  "findings": [],
  "inconclusive": [],
  "unmatched_paths": [],
  "suppressed_paths": [],
  "coverage_gaps": {
    "unreferenced_acp": [],
    "uncovered_apis": [],
    "unknown_api_relevance": []
  },
  "limitations": []
}
```

`findings` contains explicit missing or ineffective controls. `inconclusive` contains required controls with incomplete evidence. `unmatched_paths` contains access paths without an exact `(D,O,R)` ACP. `suppressed_paths` contains paths proven unreachable; internal status alone never causes suppression.

Every finding keeps the tuple reference exactly four-dimensional and stores all path metadata outside it.

## 5. Coverage semantics

Analysis is incomplete when any of these is non-empty:

- `inconclusive`;
- `unmatched_paths`;
- `coverage_gaps.unreferenced_acp`;
- `coverage_gaps.uncovered_apis`;
- `coverage_gaps.unknown_api_relevance`;
- input `known_gaps`;
- revision mismatch.

These are workflow outputs, not necessarily vulnerabilities.
