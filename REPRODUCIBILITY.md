# Reproducibility Protocol

## Software tests

```bash
python --version
python -m unittest discover -s tests -v
python examples/demo.py
```

Record the OS, Python version, git commit, full test output, and SHA-256 of the archive in any research artifact package.

## TLA+ model checking

Use a documented TLC/TLA+ tools distribution. From the `spec/` directory, run the model checker with `AuthorityKernel.tla` and `AuthorityKernel.cfg`. Save the exact command, TLC version, complete stdout/stderr, runtime, and state counts. The repository does not pre-assert a successful result; if TLC reports an invariant violation, fix the model or narrow the claim rather than suppressing the error.

## CARLA evaluation

This repository currently does not contain a full CARLA runner or raw data supporting the reported 1,000-scenario paper results. To make those claims reproducible, add:

- exact CARLA and ScenarioRunner versions and launch settings;
- scenario source/configuration and random seeds;
- the actual kernel-to-simulator adapter and all dependencies;
- per-scenario raw logs, with status values `pass`, `collision`, or `simulator_error`;
- analysis code that regenerates every table and confidence interval;
- baseline results, if any claim compares the kernel with direct actuation;
- machine, OS, GPU/CPU, simulator timestep, and environment configuration.

For 1,000 scenarios, reconcile counts so pass + collision + simulator_error = 1,000. Avoid mixing “scenario passed” with “kernel authorization succeeded”; these are different outcomes.
