"""Safe local demonstration; no CARLA or vehicle connection."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from authority_kernel import AuthorityKernel, Request, RequestContext

NOW = 1_800_000_000.0
kernel = AuthorityKernel()
cap = kernel.issue_capability(
    principal_id="ego-ai",
    operations={"set_speed", "set_brake"},
    resources={"vehicle.motion"},
    max_impact_tier=1,
    expires_at=NOW + 60,
    max_uses=2,
)

requests = [
    Request("demo-001", "ego-ai", "set_speed", "vehicle.motion", {"speed_mps": 3.0}, 0),
    Request("demo-002", "ego-ai", "set_speed", "vehicle.motion", {"speed_mps": 5.0}, 0),
    Request("demo-003", "ego-ai", "set_speed", "vehicle.motion", {"speed_mps": 7.0}, 0),
    Request("demo-004", "ego-ai", "open_door", "vehicle.body", {}, 0),
]
for request in requests:
    decision = kernel.handle(request, RequestContext("ego-ai", NOW), cap.capability_id)
    print(decision.as_dict())
print({"audit_chain_valid": kernel.audit.verify(), "audit_events": len(kernel.audit.events())})
