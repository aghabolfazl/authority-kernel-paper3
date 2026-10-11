# Threat Model and Scope

## Protected asset
The integrity of the authorization decision between an AI-generated request and a downstream actuator adapter.

## In-scope threats addressed in this reference implementation
- Request lacks a registered capability.
- Request comes from an unauthenticated or mismatched principal (the caller identity is supplied by an external authenticator; this code does not implement transport authentication).
- Capability is expired, revoked, out of scope, over its use limit, or has an invalid HMAC signature.
- Request identifier is replayed during the current process lifetime.
- Parameters do not match the configured schema.
- Configured trajectory-policy callback rejects the request.
- A high-impact request lacks a successful approval callback.
- Authorization-path exceptions should fail closed where possible.
- Audit-chain edits can be detected by recomputing the chain.

## Out of scope / not established
- Secure boot, process isolation, OS hardening, HSM-backed keys, key rotation, and authenticated RPC.
- Persistent replay prevention or revocation across restarts and distributed replicas.
- Complete mediation unless integrators ensure no actuator bypass exists.
- Correctness of perception, prediction, planning, vehicle dynamics, sensors, or actuators.
- Continuous-time collision avoidance, formal reachability, RSS, or a certified safety controller.
- Availability against denial of service, timing side channels, memory corruption, or compromised host/root.
- Production-grade human approval, operator availability, and human-factors validation.
- ISO 26262 / ISO 21448 compliance or certification.

## Trust assumptions
- The governance issuer and HMAC key are not compromised.
- The caller authentication layer correctly supplies `RequestContext.authenticated_principal`.
- Integrators route all protected actuator commands through a separately hardened gateway.
- The policy callback is reviewed and its limits are understood.
- System clock input is trustworthy enough for the chosen expiry semantics.

## Safe use
Run in simulation or unit tests only. Do not attach this prototype to a physical vehicle or production actuator.
