"""Default-deny policy rules. These are example rules, not a vehicle safety policy."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from .models import Request


@dataclass
class Policy:
    allowed_operations: set[str] = field(default_factory=lambda: {"set_speed", "set_brake", "set_steering"})
    protected_resources: set[str] = field(default_factory=lambda: {"vehicle.motion"})
    high_impact_tier: int = 2
    required_parameter_types: Mapping[str, Mapping[str, type]] = field(default_factory=lambda: {
        "set_speed": {"speed_mps": (int, float)},
        "set_brake": {"brake_fraction": (int, float)},
        "set_steering": {"steering_radians": (int, float)},
    })
    trajectory_check: Callable[[Request], bool] = lambda request: True

    def validate_parameters(self, request: Request) -> bool:
        schema = self.required_parameter_types.get(request.operation)
        if schema is None:
            return False
        for key, expected_type in schema.items():
            if key not in request.parameters or not isinstance(request.parameters[key], expected_type):
                return False
        # Reject booleans where numeric values are expected (bool subclasses int in Python).
        for key, expected_type in schema.items():
            if (expected_type in (int, float) or (isinstance(expected_type, tuple) and any(t in (int, float) for t in expected_type)) ) and isinstance(request.parameters[key], bool):
                return False
        return True

    def allows_operation(self, request: Request) -> bool:
        return request.operation in self.allowed_operations and request.resource in self.protected_resources
