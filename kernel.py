"""Fail-closed Authority Kernel demo.

This module authorizes abstract requests only. It deliberately has no actuator driver.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from typing import Callable
from .audit import AuditLog
from .models import Capability, Decision, Request, RequestContext
from .policy import Policy


@dataclass(frozen=True)
class KernelConfig:
    hmac_key: bytes = b"DEMO-ONLY-CHANGE-ME-32-BYTES-MINIMUM"
    require_approval_at_or_above_tier: int = 2


class AuthorityKernel:
    def __init__(self, policy: Policy | None = None, config: KernelConfig | None = None,
                 approval_verifier: Callable[[Request], bool] | None = None) -> None:
        self.policy = policy or Policy()
        self.config = config or KernelConfig()
        self.audit = AuditLog()
        self._approval_verifier = approval_verifier or (lambda request: False)
        self._capabilities: dict[str, Capability] = {}
        self._revoked: set[str] = set()
        self._use_count: dict[str, int] = {}
        self._seen_requests: set[str] = set()
        self._lock = threading.RLock()

    def _capability_payload(self, capability: Capability) -> bytes:
        data = {
            "capability_id": capability.capability_id,
            "principal_id": capability.principal_id,
            "operations": sorted(capability.operations),
            "resources": sorted(capability.resources),
            "max_impact_tier": capability.max_impact_tier,
            "expires_at": capability.expires_at,
            "max_uses": capability.max_uses,
            "allow_delegation": capability.allow_delegation,
            "parent_id": capability.parent_id,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def issue_capability(self, *, principal_id: str, operations: set[str], resources: set[str],
                         max_impact_tier: int, expires_at: float, max_uses: int = 1,
                         allow_delegation: bool = False, parent_id: str | None = None,
                         issuer_principal: str = "governance") -> Capability:
        """Issue a bounded capability. Only the governance principal may issue root grants.

        Child grants must be explicitly delegated by a parent that permits delegation and
        cannot exceed the parent's operation/resource/tier/expiry/use bounds.
        """
        with self._lock:
            if max_uses < 1 or max_impact_tier < 0:
                raise ValueError("invalid capability bounds")
            if parent_id is None:
                if issuer_principal != "governance":
                    raise PermissionError("root capabilities require governance issuer")
            else:
                parent = self._capabilities.get(parent_id)
                if parent is None or parent_id in self._revoked or not parent.allow_delegation:
                    raise PermissionError("parent capability does not permit delegation")
                if not set(operations).issubset(parent.operations) or not set(resources).issubset(parent.resources):
                    raise PermissionError("delegated scope exceeds parent")
                if max_impact_tier > parent.max_impact_tier or expires_at > parent.expires_at or max_uses > parent.max_uses:
                    raise PermissionError("delegated bounds exceed parent")
            capability = Capability(
                capability_id=secrets.token_hex(12), principal_id=principal_id,
                operations=frozenset(operations), resources=frozenset(resources),
                max_impact_tier=max_impact_tier, expires_at=expires_at, max_uses=max_uses,
                allow_delegation=allow_delegation, parent_id=parent_id,
            )
            signature = hmac.new(self.config.hmac_key, self._capability_payload(capability), hashlib.sha256).hexdigest()
            capability = Capability(**{**capability.__dict__, "signature": signature})
            self._capabilities[capability.capability_id] = capability
            self._use_count[capability.capability_id] = 0
            self.audit.append({"event": "capability_issued", "capability_id": capability.capability_id,
                               "principal_id": principal_id, "issuer": issuer_principal})
            return capability

    def revoke(self, capability_id: str) -> None:
        """Revoke a capability and all descendants currently registered in this process."""
        with self._lock:
            if capability_id not in self._capabilities:
                return
            to_revoke = {capability_id}
            changed = True
            while changed:
                changed = False
                for cid, cap in self._capabilities.items():
                    if cap.parent_id in to_revoke and cid not in to_revoke:
                        to_revoke.add(cid)
                        changed = True
            self._revoked.update(to_revoke)
            self.audit.append({"event": "capability_revoked", "capability_ids": sorted(to_revoke)})

    def _valid_capability(self, capability: Capability, request: Request, now: float) -> tuple[bool, str]:
        expected = hmac.new(self.config.hmac_key, self._capability_payload(capability), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, capability.signature):
            return False, "invalid_capability_signature"
        registered = self._capabilities.get(capability.capability_id)
        if registered != capability:
            return False, "capability_not_registered"
        if capability.capability_id in self._revoked:
            return False, "capability_revoked"
        if capability.parent_id and capability.parent_id in self._revoked:
            return False, "parent_capability_revoked"
        if now >= capability.expires_at:
            return False, "capability_expired"
        if self._use_count.get(capability.capability_id, 0) >= capability.max_uses:
            return False, "capability_use_limit_reached"
        if capability.principal_id != request.principal_id:
            return False, "principal_mismatch"
        if request.operation not in capability.operations or request.resource not in capability.resources:
            return False, "capability_scope_mismatch"
        if request.impact_tier > capability.max_impact_tier:
            return False, "impact_tier_exceeded"
        return True, "capability_valid"

    def handle(self, request: Request, context: RequestContext, capability_id: str | None) -> Decision:
        """Evaluate and log a request. Any exception fails closed.

        No actuation occurs here; an integration must independently ensure that this
        function is the only path to a protected actuator.
        """
        with self._lock:
            try:
                if not request.request_id or request.request_id in self._seen_requests:
                    return self._deny(request, "missing_or_replayed_request_id")
                self._seen_requests.add(request.request_id)
                if context.authenticated_principal is None or context.authenticated_principal != request.principal_id:
                    return self._deny(request, "caller_authentication_failed")
                if not self.policy.allows_operation(request):
                    return self._deny(request, "operation_not_allowed_by_policy")
                if not self.policy.validate_parameters(request):
                    return self._deny(request, "parameter_schema_invalid")
                if capability_id is None or capability_id not in self._capabilities:
                    return self._deny(request, "missing_or_unknown_capability")
                capability = self._capabilities[capability_id]
                valid, reason = self._valid_capability(capability, request, context.now)
                if not valid:
                    return self._deny(request, reason, capability_id)
                if request.impact_tier >= self.config.require_approval_at_or_above_tier:
                    if not self._approval_verifier(request):
                        return self._deny(request, "high_impact_approval_missing_or_invalid", capability_id)
                if not self.policy.trajectory_check(request):
                    return self._deny(request, "trajectory_policy_rejected", capability_id)
                self._use_count[capability_id] += 1
                digest = self.audit.append({"event": "request_authorized", "request_id": request.request_id,
                    "principal_id": request.principal_id, "operation": request.operation,
                    "resource": request.resource, "capability_id": capability_id, "impact_tier": request.impact_tier})
                return Decision(True, "authorized_by_configured_policy", request.request_id, capability_id, digest)
            except Exception as exc:
                # Avoid returning exception internals to the caller; record a generic fail-closed result.
                try:
                    return self._deny(request, f"internal_error_fail_closed:{type(exc).__name__}", capability_id)
                except Exception:
                    return Decision(False, "internal_error_fail_closed", getattr(request, "request_id", "unknown"), capability_id)

    def _deny(self, request: Request, reason: str, capability_id: str | None = None) -> Decision:
        digest = self.audit.append({"event": "request_denied", "request_id": getattr(request, "request_id", "unknown"),
                                    "principal_id": getattr(request, "principal_id", "unknown"),
                                    "reason": reason, "capability_id": capability_id})
        return Decision(False, reason, getattr(request, "request_id", "unknown"), capability_id, digest)
