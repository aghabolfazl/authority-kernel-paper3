# Authority Kernel — Paper 3 Reference Implementation

**Paper:** *An Authority Kernel for Autonomous Transportation Systems: Design, Compliance, and Evaluation*  
**Core principle:** **INTELLIGENCE IS NOT AUTHORITY**  
**Author:** Abolfazl Erfani · Tarbiat Modares University, Tehran, Iran · ORCID: [0009-0001-9393-4974](https://orcid.org/0009-0001-9393-4974)

This repository is a research-oriented reference implementation of a deployment-time authorization boundary between an AI stack and vehicle-actuation interface. It is intentionally a **simulation/demo scaffold**, not an automotive production component, certified safety system, or proof of real-world collision prevention.

## What is included

- A Python standard-library implementation of scoped capabilities, default-deny authorization, expiry/revocation checks, request replay rejection, optional human approval, parameter-schema validation, fail-closed handling, and a hash-chained audit log.
- Unit tests for the implemented behaviours.
- A small TLA+ state-machine model and TLC configuration for a *bounded subset* of the design. No model-checking result is claimed until TLC is run and its output is archived.
- A deterministic demo that exercises allowed and denied requests without connecting to a vehicle or CARLA.
- A CARLA integration boundary sketch. It does not pretend to be a complete CARLA scenario runner.
- CI configuration, citation metadata, security policy, and reproducibility notes.

## Important evidence boundary

The paper draft reports an evaluation of 1,000 CARLA 0.9.15 scenarios, including 928 passes, 52 collision outcomes, and 20 simulator errors, plus request/audit counts. Those figures are **not generated or independently verified by this repository scaffold**. Do not cite them as reproducible repository results unless the actual CARLA scenario generator, raw logs, analysis scripts, environment lockfile, and run instructions are added and the results are regenerated. Similarly, this repository does not claim that TLA+/TLC has passed; run the included specification with TLC and archive the actual output before making such a claim.

**Authorization correctness is not world safety.** A request can comply with the kernel's configured rules while the vehicle still collides because perception, prediction, policy coverage, environment models, or vehicle dynamics are inadequate.

## Quick start

Requires Python 3.10+; no third-party packages are required.

```bash
python -m unittest discover -s tests -v
python examples/demo.py
```

Expected: tests pass and the demo prints an authorized low-impact request followed by denied requests. This is local software-test evidence only, not evidence about CARLA, real vehicles, or formal verification.

## Repository map

```text
authority-kernel-paper3/
├── authority_kernel/
│   ├── __init__.py
│   ├── audit.py
│   ├── kernel.py
│   ├── models.py
│   └── policy.py
├── tests/test_kernel.py
├── examples/demo.py
├── spec/AuthorityKernel.tla
├── spec/AuthorityKernel.cfg
├── docs/THREAT_MODEL.md
├── docs/REPRODUCIBILITY.md
├── docs/PAPER_CLAIMS.md
├── .github/workflows/tests.yml
├── CITATION.cff
├── LICENSE
├── SECURITY.md
└── pyproject.toml
```

## Security and operational warning

- Never connect this demo directly to a real vehicle or safety-critical actuator.
- HMAC capabilities are a teaching/reference mechanism; production key storage, rotation, isolation, replay persistence, authenticated transport, and hardware-backed protection are not implemented.
- The demo's trajectory callback is only a policy hook. It is not a validated collision-avoidance algorithm, reachability analysis, RSS implementation, or safety controller.
- In-memory replay and revocation state are lost on process restart.
- A hash chain makes tampering detectable only under stated assumptions; it does not prevent privileged deletion or prove that all events were logged.
- Human approval is represented by an injected callback, not a production human-factors or authenticated approval service.
- No ISO 26262 or ISO 21448 certification is claimed. The paper's mapping is a candidate safety-case mapping only.

## Reproducibility checklist before journal submission

1. Add the actual source used for the claimed CARLA runs and pin the CARLA/ScenarioRunner versions.
2. Add raw, machine-readable scenario logs and the exact analysis script; verify that totals reconcile (pass + collision + simulator-error = total).
3. Add environment, seed, hardware, OS, Python, simulator settings, and scenario-generation parameters.
4. Run tests in a clean environment and archive CI output.
5. Run TLC against the supplied TLA+ model; archive the exact TLC version, command, configuration, and output. Do not use placeholders or infer results.
6. Add baseline runs if claiming marginal safety benefit. Without baseline data, make no causal collision-reduction claim.
7. Replace repository metadata only after publishing this repository to a real URL; do not invent a GitHub or Zenodo URL.

## License

Apache-2.0. See `LICENSE`.
