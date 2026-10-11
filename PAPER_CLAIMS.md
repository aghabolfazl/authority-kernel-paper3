# Paper Claim Ledger

| Claim | Status in this repository | Safe wording |
|---|---|---|
| Authority boundary separates requests from actuation | Architectural intent represented by API boundary; no actuator driver included | “Reference design separates request authorization from actuation integration.” |
| Default-deny, scoped capability checks | Implemented and unit tested in this demo | “The reference implementation tests these configured checks.” |
| Hash-chained audit events | Implemented and unit tested | “The local audit chain detects edits in the stored in-memory event sequence.” |
| K1–K20 fully implemented | Not established | “K1–K20 are the paper's invariant register; this prototype covers only a subset.” |
| TLA+ invariants passed TLC | Not established until a real TLC run is archived | Do not claim verified/passed before inspecting output. |
| 1,000 CARLA scenarios reproduced here | Not established; full runner and raw logs are absent | Do not attribute the paper's scenario metrics to this repository yet. |
| Zero unsafe actions authorized | Not established by unit tests; depends on independent operational unsafe-action definition and raw run logs | Only report if independently measured and reproducible. |
| Reduced collisions versus baseline | No verified baseline results included | Do not claim causal improvement without a controlled baseline. |
| ISO 26262 / ISO 21448 certified | False / not claimed | “Candidate safety-case mapping; no certification is claimed.” |
| Real-world autonomous-driving safety | Not established | “Simulation/reference prototype only.” |
