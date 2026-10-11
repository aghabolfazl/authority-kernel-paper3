"""Typed data structures for the Authority Kernel reference implementation."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Request:
    request_id: str
    principal_id: str
    operation: str
    resource: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    impact_tier: int = 0
    trajectory_context: Mapping[str, Any] = field(default_factory=dict)
    approval_token: str | None = None


@dataclass(frozen=True)
class Capability:
    capability_id: str
    principal_id: str
    operations: frozenset[str]
    resources: frozenset[str]
    max_impact_tier: int
    expires_at: float
    max_uses: int = 1
    allow_delegation: bool = False
    parent_id: str | None = None
    signature: str = ""


@dataclass(frozen=True)
class RequestContext:
    authenticated_principal: str | None
    now: float
    approval_verified: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    request_id: str
    capability_id: str | None = None
    audit_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "request_id": self.request_id,
            "capability_id": self.capability_id,
            "audit_hash": self.audit_hash,
        }
