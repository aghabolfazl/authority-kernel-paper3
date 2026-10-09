# Authority Kernel — Paper 3 reference repository

**Principle: Intelligence is not authority.**

Research-oriented reference implementation accompanying *An Authority Kernel for Autonomous Transportation Systems: Design, Compliance, and Evaluation*. Demonstrates a default-deny policy engine, scoped HMAC capability tokens, a guarded action gateway, and an in-memory hash-chained audit ledger.

> **Safety/evidence notice:** Not production vehicle software, a safety case, or evidence of ISO certification. No real vehicle, CARLA, hardware-in-the-loop, or real-world collision evaluation is included. Do not infer empirical results from this repository.

## Layout
- `authority_kernel/`: Python implementation
- `tests/`: unit tests
- `examples/demo.py`: local simulated demo
- `spec/`: illustrative TLA+ model and TLC configuration
- `docs/VALIDATION.md`: validation scope and limitations
- `.github/workflows/tests.yml`: CI workflow

## Quick start (Python 3.11+)
```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python examples/demo.py
```

The kernel authorizes requests before a caller-provided gateway is invoked; no actuator driver is included. Missing capabilities, expired/out-of-scope tokens, missing approval for configured high-impact actions, and missing gateways fail closed. In-memory audit data is not durable; key management, approval identity, revocation, timing, vehicle dynamics, and production hardening are not implemented. The formal model does not prove Python code correctness. See `docs/VALIDATION.md` before citing this project.
