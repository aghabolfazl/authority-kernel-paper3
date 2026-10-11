import unittest
from authority_kernel import AuthorityKernel, Capability, KernelConfig, Policy, Request, RequestContext

NOW = 1_000.0


def setup_kernel(**kwargs):
    kernel = AuthorityKernel(**kwargs)
    cap = kernel.issue_capability(principal_id="ego-ai", operations={"set_speed"},
        resources={"vehicle.motion"}, max_impact_tier=1, expires_at=NOW + 100, max_uses=10)
    return kernel, cap


def req(request_id="r1", **overrides):
    data = dict(request_id=request_id, principal_id="ego-ai", operation="set_speed",
        resource="vehicle.motion", parameters={"speed_mps": 4.0}, impact_tier=0)
    data.update(overrides)
    return Request(**data)


class AuthorityKernelTests(unittest.TestCase):
    def test_valid_request_is_authorized(self):
        kernel, cap = setup_kernel()
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertTrue(result.allowed)
        self.assertTrue(kernel.audit.verify())

    def test_default_deny_without_capability(self):
        kernel = AuthorityKernel()
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), None)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "missing_or_unknown_capability")

    def test_authentication_mismatch_denied(self):
        kernel, cap = setup_kernel()
        result = kernel.handle(req(), RequestContext("other", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "caller_authentication_failed")

    def test_replay_denied(self):
        kernel, cap = setup_kernel()
        context = RequestContext("ego-ai", NOW)
        self.assertTrue(kernel.handle(req("same"), context, cap.capability_id).allowed)
        second = kernel.handle(req("same"), context, cap.capability_id)
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason, "missing_or_replayed_request_id")

    def test_expired_capability_denied(self):
        kernel = AuthorityKernel()
        cap = kernel.issue_capability(principal_id="ego-ai", operations={"set_speed"}, resources={"vehicle.motion"},
            max_impact_tier=1, expires_at=NOW, max_uses=2)
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "capability_expired")

    def test_scope_mismatch_denied(self):
        kernel, cap = setup_kernel()
        bad = req(operation="set_brake", parameters={"brake_fraction": 0.5})
        result = kernel.handle(bad, RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "capability_scope_mismatch")

    def test_bad_parameter_schema_denied(self):
        kernel, cap = setup_kernel()
        bad = req(parameters={"speed_mps": "fast"})
        result = kernel.handle(bad, RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "parameter_schema_invalid")

    def test_bool_is_not_accepted_as_numeric_parameter(self):
        kernel, cap = setup_kernel()
        bad = req(parameters={"speed_mps": True})
        result = kernel.handle(bad, RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)

    def test_high_impact_requires_approval(self):
        kernel = AuthorityKernel(config=KernelConfig(require_approval_at_or_above_tier=2))
        cap = kernel.issue_capability(principal_id="ego-ai", operations={"set_speed"}, resources={"vehicle.motion"},
            max_impact_tier=3, expires_at=NOW + 100, max_uses=2)
        high = req(impact_tier=2)
        result = kernel.handle(high, RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "high_impact_approval_missing_or_invalid")

    def test_trajectory_rejection(self):
        policy = Policy(trajectory_check=lambda request: False)
        kernel, cap = setup_kernel(policy=policy)
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "trajectory_policy_rejected")

    def test_revocation_denied(self):
        kernel, cap = setup_kernel()
        kernel.revoke(cap.capability_id)
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "capability_revoked")

    def test_delegation_cannot_exceed_parent_scope(self):
        kernel = AuthorityKernel()
        parent = kernel.issue_capability(principal_id="delegate", operations={"set_speed"}, resources={"vehicle.motion"},
            max_impact_tier=1, expires_at=NOW + 100, max_uses=5, allow_delegation=True)
        with self.assertRaises(PermissionError):
            kernel.issue_capability(principal_id="child", operations={"set_brake"}, resources={"vehicle.motion"},
                max_impact_tier=1, expires_at=NOW + 50, max_uses=2, parent_id=parent.capability_id,
                issuer_principal="delegate")

    def test_revocation_cascades_to_child(self):
        kernel = AuthorityKernel()
        parent = kernel.issue_capability(principal_id="delegate", operations={"set_speed"}, resources={"vehicle.motion"},
            max_impact_tier=1, expires_at=NOW + 100, max_uses=5, allow_delegation=True)
        child = kernel.issue_capability(principal_id="ego-ai", operations={"set_speed"}, resources={"vehicle.motion"},
            max_impact_tier=1, expires_at=NOW + 50, max_uses=2, parent_id=parent.capability_id,
            issuer_principal="delegate")
        kernel.revoke(parent.capability_id)
        result = kernel.handle(req(), RequestContext("ego-ai", NOW), child.capability_id)
        self.assertFalse(result.allowed)
        self.assertIn(result.reason, {"capability_revoked", "parent_capability_revoked"})

    def test_audit_chain_detects_tampering(self):
        kernel, cap = setup_kernel()
        kernel.handle(req(), RequestContext("ego-ai", NOW), cap.capability_id)
        self.assertTrue(kernel.audit.verify())
        kernel.audit._events[0]["event"] = "tampered"
        self.assertFalse(kernel.audit.verify())


if __name__ == "__main__":
    unittest.main()
