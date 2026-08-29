from dataclasses import dataclass

@dataclass(frozen=True)
class RolePolicy:
    name: str
    permissions: frozenset[str]

ROLE_POLICIES = {
    "owner": RolePolicy("owner", frozenset({"*"})),
    "admin": RolePolicy("admin", frozenset({"clearance:write", "clearance:read", "simulation:run", "impact:run", "webhooks:manage", "keys:manage", "audit:read", "organization:read", "regulatory:manage"})),
    "developer": RolePolicy("developer", frozenset({"clearance:write", "clearance:read", "simulation:run", "impact:run", "webhooks:manage", "audit:read", "organization:read"})),
    "finance": RolePolicy("finance", frozenset({"clearance:write", "clearance:read", "simulation:run", "impact:run", "audit:read", "organization:read", "regulatory:manage"})),
    "auditor": RolePolicy("auditor", frozenset({"clearance:read", "simulation:run", "impact:run", "audit:read", "organization:read"})),
    "readonly": RolePolicy("readonly", frozenset({"clearance:read", "audit:read", "organization:read"})),
}

def has_permission(account: dict, permission: str) -> bool:
    role = ROLE_POLICIES.get(account.get("role", "developer"), ROLE_POLICIES["readonly"])
    return "*" in role.permissions or permission in role.permissions
