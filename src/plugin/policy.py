"""Evaluate upward membership reachability and resource ancestor chains, without I/O."""

from pathlib import Path

from contract import (
    Decision,
    Effect,
    EvaluationOutput,
    InspectInput,
    Membership,
    PolicyInput,
    PrincipalType,
    Reason,
    ResourceOutput,
)


def identifiers(values, label):
    if any(not value or value != value.strip() for value in values) or len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique, nonempty IDs without surrounding whitespace")
    return set(values)


def validate_policy(policy: PolicyInput):
    users = identifiers(policy.users, "users")
    actions = identifiers(policy.actions, "actions")
    groups = identifiers([group.group_id for group in policy.groups], "groups")
    resource_ids = identifiers([resource.resource_id for resource in policy.resources], "resources")
    identifiers([rule.rule_id for rule in policy.rules], "rules")
    for group in policy.groups:
        members = identifiers(group.member_users, "member_users")
        nested = identifiers(group.member_groups, "member_groups")
        if not members <= users or not nested <= groups:
            raise ValueError("group members must reference declared users and groups")
    resources = {resource.resource_id: resource for resource in policy.resources}
    for resource in policy.resources:
        if resource.parent_id is not None and resource.parent_id not in resource_ids:
            raise ValueError("resource parent must be declared")
    # Walk parent chains once, stopping at a completed chain or detecting an active loop.
    finished = set()
    for resource_id in resources:
        chain = set()
        current = resource_id
        while current is not None and current not in finished:
            if current in chain:
                raise ValueError("resource parent cycles are invalid")
            chain.add(current)
            current = resources[current].parent_id
        finished.update(chain)
    for rule in policy.rules:
        principals = users if rule.principal_type == PrincipalType.USER else groups
        if rule.principal_id not in principals or rule.resource_id not in resource_ids:
            raise ValueError("rule principal and resource must be declared")
        selected = identifiers(rule.actions, "rule actions")
        if not selected or not selected <= actions:
            raise ValueError("rule actions must be a nonempty subset of declared actions")
    return resources


def inspect_resource(value: InspectInput, workspace: Path) -> ResourceOutput:
    resources = validate_policy(value.policy)
    if value.resource_id not in resources:
        raise ValueError("inspected resource must be declared")
    resource = resources[value.resource_id]
    return ResourceOutput(
        resource_id=resource.resource_id,
        parent_id=resource.parent_id,
        inherit=resource.inherit,
        children=sorted(item.resource_id for item in value.policy.resources if item.parent_id == resource.resource_id),
        rule_ids=sorted(rule.rule_id for rule in value.policy.rules if rule.resource_id == resource.resource_id),
    )


def evaluate_policy(value: PolicyInput, workspace: Path) -> EvaluationOutput:
    resources = validate_policy(value)
    direct = {user: set() for user in value.users}
    containers = {group.group_id: set() for group in value.groups}
    for group in value.groups:
        for user in group.member_users:
            direct[user].add(group.group_id)
        for nested in group.member_groups:
            containers[nested].add(group.group_id)
    effective = {}
    for user in sorted(value.users):
        reached = set()
        pending = list(direct[user])
        while pending:
            group = pending.pop()
            if group not in reached:
                reached.add(group)
                pending.extend(containers[group] - reached)
        effective[user] = reached

    local_rules = {resource: [] for resource in resources}
    for rule in value.rules:
        local_rules[rule.resource_id].append(rule)
    applicable = {}
    for resource_id in sorted(resources):
        rules = list(local_rules[resource_id])
        current = resources[resource_id]
        while current.inherit and current.parent_id is not None:
            current = resources[current.parent_id]
            rules.extend(rule for rule in local_rules[current.resource_id] if rule.propagate)
        applicable[resource_id] = rules

    decisions = []
    for user in sorted(value.users):
        for resource in sorted(resources):
            matching = [
                rule
                for rule in applicable[resource]
                if (rule.principal_type == PrincipalType.USER and rule.principal_id == user)
                or (rule.principal_type == PrincipalType.GROUP and rule.principal_id in effective[user])
            ]
            for action in sorted(value.actions):
                allow = sorted(
                    rule.rule_id for rule in matching if action in rule.actions and rule.effect == Effect.ALLOW
                )
                deny = sorted(
                    rule.rule_id for rule in matching if action in rule.actions and rule.effect == Effect.DENY
                )
                reason = Reason.EXPLICIT_DENY if deny else Reason.ALLOW if allow else Reason.DEFAULT_DENY
                decisions.append(Decision(user, resource, action, bool(allow) and not deny, reason, allow, deny))
    return EvaluationOutput(
        memberships=[Membership(user, sorted(groups)) for user, groups in effective.items()],
        decisions=decisions,
    )
