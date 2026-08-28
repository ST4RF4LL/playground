# BAC candidate detection rules

## Contents

1. Join key
2. Effective controls
3. Candidate classes
4. Reachability and interface type
5. Controllability
6. Confidence
7. Review rules

## 1. Join key

Join each database access path to exactly one intended policy using:

`(sink.D, sink.O, effective_role) = (tuple.D, tuple.O, tuple.R)`

Do not fuzzy-match resource names or roles. If no exact match exists, emit `UNMATCHED_PATH`. If several roles exist for the same `D/O`, list them as hints but do not select one.

## 2. Effective controls

Required controls:

| ACP `AC` | Required set |
|---|---|
| `NONE` | empty |
| `VAC` | `VAC` |
| `HAC` | `HAC` |
| `VAC+HAC` | `VAC`, `HAC` |

A required control has one of three states:

- `EFFECTIVE`: every required fact is explicitly true;
- `MISSING`: `observed` is false, or at least one required effectiveness fact is explicitly false;
- `UNKNOWN`: no fact is false, but at least one required fact is missing or null.

Do not convert `UNKNOWN` to `MISSING`.

VAC false conditions include untrusted identity, wrong role, a check that does not dominate the sink, or a failure branch that continues.

HAC false conditions include a request-derived principal, absent owner equality, a check after the sink, or a non-excluding failure branch.

## 3. Candidate classes

| Missing set | Classification |
|---|---|
| `VAC` | `BVAC_CANDIDATE` |
| `HAC` | `BHAC_CANDIDATE` |
| `VAC`, `HAC` | `BVAC_BHAC_CANDIDATE` |

Extra implemented controls are not BAC findings.

If only unknown required controls remain, emit an inconclusive record. If one control is explicitly missing and another is unknown, emit a candidate and preserve the unknown control for review.

## 4. Reachability and interface type

- Analyze `EXTERNAL` and `INTERNAL` paths with identical rules.
- Never reduce confidence solely because a path is internal.
- `external_triggerable: false` means no known external chain; it does not make the path safe.
- Suppress only when `reachability.status` is `UNREACHABLE` and supporting evidence establishes dead or impossible execution.
- Preserve `UNKNOWN` reachability as a review requirement.

## 5. Controllability

Attacker controllability affects exploitability confidence, not whether an access-control mismatch exists.

- `true`: a request, RPC, message, callback, or attacker-influenced stored value reaches the sensitive selector or mutation.
- `false`: evidence establishes that the value is generated and constrained by a trusted source.
- `null` or missing: unknown.

Do not suppress an internal or asynchronous mismatch merely because direct external controllability has not yet been recovered.

## 6. Confidence

Confidence describes static evidence quality, not severity or exploit confirmation.

Start from Agent2 ACP confidence, then reduce it for:

- revision mismatch;
- partial path coverage;
- unknown reachability;
- unknown or false attacker controllability;
- required controls that remain unknown.

Do not reduce it solely for `INTERNAL`.

Use bands:

- `HIGH`: at least `0.85`;
- `MEDIUM`: `0.65` through `0.84`;
- `LOW`: below `0.65`.

Always keep `validation_status: NOT_PERFORMED`.

## 7. Review rules

Before retaining a high-confidence candidate, verify:

1. the entry point is framework-bound and executable;
2. the path reaches the stated database sink;
3. input flow reaches the sensitive object selector or mutation;
4. global, gateway, filter, interceptor, method, and local controls are composed;
5. matcher order, whitelist, branches, and failure behavior are correct;
6. internal service identity and delegated user identity are not confused;
7. HAC uses a trusted current principal and direct owner relation;
8. the missing control is absent or ineffective before every relevant sink;
9. source revision matches the ACP and path facts.

Return ACP conflicts to Agent2 and path-extraction gaps to Agent1. Agent3 does not silently repair upstream truth.
