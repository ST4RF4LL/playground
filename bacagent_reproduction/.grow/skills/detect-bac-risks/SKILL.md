---
name: detect-bac-risks
description: Compare intended ACP (D,O,R,AC) policies against API-to-database access-path facts to identify static broken-access-control (BAC) candidates — path-level missing or ineffective VAC/HAC on external HTTP, internal RPC, message, and scheduled entry points. Produces bac-findings.json plus a Markdown report of candidates, inconclusive paths, and coverage gaps; never performs dynamic verification or extends D/O/R/AC. Use when given acp-quadruples.json and access-paths.json and asked to find broken-access-control risks, missing or ineffective authorization checks, or VAC/HAC coverage gaps.
when-to-use: broken access control, BAC candidate detection, VAC/HAC effectiveness, authorization coverage gaps, acp-quadruples.json, access-paths.json
allowed-tools: run_terminal_command, read_file, write, search_replace
compatibility: Requires python3
metadata:
  author: BACAgent paper reproduction
  short-description: Static BAC candidate detection from ACP quadruples and access paths
---

# Detect BAC risks

Compare intended `<D,O,R,AC>` policies with controls effective on each reachable database access path. Treat every result as a static candidate until the user's separate validation process confirms it.

## Load references

Before analysis:

1. Read `references/input-output-contract.md`.
2. Read `references/detection-rules.md`.

Resolve paths relative to this skill directory.

## Inputs

Require:

- Agent2 `acp-quadruples.json`;
- Agent1 `access-paths.json`.

Accept optional Agent1 `api-catalog.json` for coverage reconciliation. Ask for missing inputs only when they cannot be found in the repository or user-provided output directory.

Keep the ACP tuple exactly `{D,O,R,AC}`. Do not add API, path, exposure, caller, condition, confidence, implementation, or finding state to the tuple.

## Workflow

### 1. Establish scope

- Resolve all input paths, repository root, and revisions.
- Read applicable repository instructions.
- Confirm Agent1 and Agent2 describe the same repository revision. If revisions differ, report the mismatch and do not issue high-confidence candidates.
- Keep source repositories read-only.

### 2. Validate facts

- Validate every ACP has a unique exact `(D,O,R)` identity.
- Validate every access path has a unique `path_id`, exact database `D/O`, effective role, reachability, input-flow facts, and structured VAC/HAC facts.
- Interpret an omitted fact as `UNKNOWN`, never as absent.
- Require `observed: false` or an explicitly ineffective condition before marking a control missing.
- Preserve internal and external interface metadata, but apply the same control rules to both.

### 3. Run deterministic pre-analysis

Run:

```bash
python3 "<skill-directory>/scripts/analyze_bac.py" \
  --acp "<path>/acp-quadruples.json" \
  --paths "<path>/access-paths.json" \
  --api-catalog "<path>/api-catalog.json" \
  --output "<path>/bac-findings.json" \
  --markdown "<path>/bac-findings.md"
```

Omit `--api-catalog` when unavailable. Replace placeholders with absolute paths.

The script:

- joins paths to ACP by exact `(D,O,R)`;
- evaluates whether required VAC/HAC is effective before every sink;
- emits explicit candidates, inconclusive paths, unmatched paths, suppressed dead paths, and coverage gaps;
- never suppresses or lowers a path merely because it is internal.

### 4. Review candidates on demand

For every candidate and inconclusive path, inspect only the relevant source slice:

- entry point and framework binding;
- call chain to the database sink;
- identity and role source;
- control ordering and all branches;
- failure behavior;
- ownership predicate;
- request-to-sink data flow;
- synchronous, RPC, message, or scheduled trigger chain.

Update conclusions only from code or configuration evidence. Do not infer a missing check from naming alone.

For VAC, verify trusted identity, required-role match, sink dominance, and fail-closed behavior.

For HAC, verify trusted current-user identity, enforced direct owner relation, sink dominance, and fail-closed/excluding behavior. A request-supplied owner ID, tenant constraint, or mere owner field is not HAC.

### 5. Reconcile gaps

- Send an unmatched database path or role back to Agent2 as missing ACP coverage; do not invent a tuple in Agent3.
- Send an unreferenced ACP or uncovered database-relevant API back to Agent1 as missing path coverage.
- Preserve reflection, dynamic SQL, AOP, generated code, missing platform source, and identity-propagation failures as explicit limitations.
- If the ACP itself conflicts with strong source evidence, mark `ACP_CONFLICT` for Agent2 review instead of silently changing it.

### 6. Write outputs

Write:

- `bac-findings.json`;
- `bac-findings.md`.

Each candidate must identify:

- exact tuple reference;
- `path_id` and entry point;
- sink and source location;
- required, effective, missing, and unknown controls;
- BVAC/BHAC classification;
- reachability and attacker-controllability facts;
- root-cause evidence;
- confidence in the static analysis;
- `validation_status: NOT_PERFORMED`.

Never label a result a confirmed vulnerability. Do not perform runtime requests, account switching, data mutation, or exploit validation.

### 7. Validate outputs

Run:

```bash
python3 "<skill-directory>/scripts/validate_bac_findings.py" "<path>/bac-findings.json"
```

Report candidate counts separately from inconclusive items and coverage gaps. Do not claim complete analysis unless all database-relevant APIs have mapped paths, all paths match ACP, and no required control remains unknown.
