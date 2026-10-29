"""Typed policy data and complete permission certificates for NanoAgent v0001."""

from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from slimconfig import Output


class Tool(Enum):
    INSPECT_RESOURCE = "inspect_resource"
    EVALUATE_POLICY = "evaluate_policy"


class Task(Enum):
    EVALUATE_ACCESS = "evaluate-access"
    EVALUATE_POLICY = "evaluate-policy"


class PrincipalType(Enum):
    USER = "user"
    GROUP = "group"


class Effect(Enum):
    ALLOW = "allow"
    DENY = "deny"


class Reason(Enum):
    ALLOW = "allow"
    EXPLICIT_DENY = "explicit-deny"
    DEFAULT_DENY = "default-deny"


@dataclass
class Group(Output):
    group_id: str
    member_users: Annotated[list[str], "Direct user members; every ID must be declared in users"]
    member_groups: Annotated[list[str], "Contained groups; their members also belong to this group, transitively"]


@dataclass
class Resource(Output):
    resource_id: str
    parent_id: Annotated[str | None, "Declared parent, or null for a root; the resource forest must be acyclic"]
    inherit: Annotated[bool, "Whether this resource receives propagating ancestor rules through its parent"]


@dataclass
class Rule(Output):
    rule_id: str
    principal_type: PrincipalType
    principal_id: str
    resource_id: str
    actions: Annotated[list[str], "Nonempty, unique subset of the declared action catalog; no wildcard expansion"]
    effect: Effect
    propagate: Annotated[bool, "Also applies to descendants reached through uninterrupted inherit=true edges"]


@dataclass
class PolicyInput(Output):
    users: list[str]
    actions: list[str]
    groups: list[Group]
    resources: list[Resource]
    rules: list[Rule]


@dataclass
class InspectInput(Output):
    policy: PolicyInput
    resource_id: str


@dataclass
class ResourceOutput(Output):
    resource_id: str
    parent_id: str | None
    inherit: bool
    children: Annotated[list[str], "Immediate children, sorted by resource_id"]
    rule_ids: Annotated[list[str], "Rules attached directly to this resource, sorted by rule_id"]


@dataclass
class Membership(Output):
    user_id: str
    group_ids: Annotated[list[str], "All direct and transitive groups, sorted and deduplicated"]


@dataclass
class Decision(Output):
    user_id: str
    resource_id: str
    action: str
    allowed: bool
    reason: Reason
    allow_rule_ids: Annotated[list[str], "Every matching allow rule, even when overridden; sorted and unique"]
    deny_rule_ids: Annotated[list[str], "Every matching deny rule; sorted and unique"]


@dataclass
class EvaluationOutput(Output):
    memberships: Annotated[list[Membership], "Exactly one row per user, sorted by user_id"]
    decisions: Annotated[list[Decision], "Every user/resource/action triple, sorted by (user_id, resource_id, action)"]


TOOLS = {
    Tool.INSPECT_RESOURCE: (InspectInput, ResourceOutput),
    Tool.EVALUATE_POLICY: (PolicyInput, EvaluationOutput),
}
TASKS = {
    Task.EVALUATE_ACCESS: (PolicyInput, EvaluationOutput),
    Task.EVALUATE_POLICY: (PolicyInput, EvaluationOutput),
}
