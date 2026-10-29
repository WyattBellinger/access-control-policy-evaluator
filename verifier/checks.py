"""Independent fixed-point membership and forward ACL propagation; no runtime imports."""

from collections import deque
from itertools import product

from contract import Effect, PrincipalType, Reason


def verdict(valid, message, **details):
    return {"valid": valid, "score": float(valid), "message": message, "details": details}


def unique_ids(values, label):
    found = set()
    for value in values:
        if not value.strip() or value != value.strip() or value in found:
            raise ValueError(f"invalid or duplicate ID in {label}")
        found.add(value)
    return found


def read_policy(policy):
    if policy is None:
        raise ValueError("policy input is required")
    users = unique_ids(policy.users, "users")
    actions = unique_ids(policy.actions, "actions")
    groups = unique_ids([group.group_id for group in policy.groups], "groups")
    resources = unique_ids([resource.resource_id for resource in policy.resources], "resources")
    unique_ids([rule.rule_id for rule in policy.rules], "rules")
    for group in policy.groups:
        if not unique_ids(group.member_users, "member_users") <= users:
            raise ValueError("undeclared user in group")
        if not unique_ids(group.member_groups, "member_groups") <= groups:
            raise ValueError("undeclared nested group")
    children = {resource: [] for resource in resources}
    roots = deque()
    for resource in policy.resources:
        if resource.parent_id is None:
            roots.append(resource.resource_id)
        elif resource.parent_id not in resources:
            raise ValueError("undeclared resource parent")
        else:
            children[resource.parent_id].append(resource.resource_id)
    # Every vertex in a forest is reachable from a root; cycles leave vertices unvisited.
    count = 0
    while roots:
        resource = roots.popleft()
        count += 1
        roots.extend(children[resource])
    if count != len(resources):
        raise ValueError("resource parent cycle")
    for rule in policy.rules:
        declared = users if rule.principal_type == PrincipalType.USER else groups
        if rule.principal_id not in declared or rule.resource_id not in resources:
            raise ValueError("undeclared rule principal or resource")
        selected = unique_ids(rule.actions, "rule actions")
        if not selected or not selected <= actions:
            raise ValueError("rule actions must be nonempty and declared")
    return users, actions, resources


def expected_relations(policy):
    # Grow user sets inside groups until no inclusion adds a member (least fixed point).
    members = {group.group_id: set(group.member_users) for group in policy.groups}
    changed = True
    while changed:
        changed = False
        for group in policy.groups:
            expanded = set(members[group.group_id])
            for nested in group.member_groups:
                expanded.update(members[nested])
            if expanded != members[group.group_id]:
                members[group.group_id] = expanded
                changed = True

    children = {resource.resource_id: [] for resource in policy.resources}
    for resource in policy.resources:
        if resource.parent_id is not None and resource.inherit:
            children[resource.parent_id].append(resource.resource_id)
    matches = {}
    # Push each rule down eligible edges, instead of walking ancestors as the runtime does.
    for rule in policy.rules:
        principals = {rule.principal_id} if rule.principal_type == PrincipalType.USER else members[rule.principal_id]
        pending = [rule.resource_id]
        while pending:
            resource = pending.pop()
            for user in principals:
                for action in rule.actions:
                    key = (user, resource, action)
                    if key not in matches:
                        matches[key] = {Effect.ALLOW: set(), Effect.DENY: set()}
                    matches[key][rule.effect].add(rule.rule_id)
            if rule.propagate:
                pending.extend(children[resource])
    return members, matches


def check_evaluation(arguments, output):
    try:
        users, actions, resources = read_policy(arguments)
    except ValueError as error:
        return verdict(False, str(error))
    if output is None:
        return verdict(False, "output is required")
    if [row.user_id for row in output.memberships] != sorted(users):
        return verdict(False, "memberships must contain every user exactly once, sorted")
    expected_count = len(users) * len(resources) * len(actions)
    if len(output.decisions) != expected_count:
        return verdict(False, "decision matrix is incomplete or has extra rows", expected_count=expected_count)
    members, matches = expected_relations(arguments)
    for row in output.memberships:
        expected = sorted(group for group, group_users in members.items() if row.user_id in group_users)
        if row.group_ids != expected:
            return verdict(
                False, "effective groups differ", user_id=row.user_id, expected=expected, actual=row.group_ids
            )
    for row, key in zip(output.decisions, product(sorted(users), sorted(resources), sorted(actions)), strict=True):
        if (row.user_id, row.resource_id, row.action) != key:
            return verdict(
                False, "decisions must enumerate every triple exactly once in sorted order", expected=list(key)
            )
        selected = matches.get(key, {Effect.ALLOW: set(), Effect.DENY: set()})
        allow = sorted(selected[Effect.ALLOW])
        deny = sorted(selected[Effect.DENY])
        if row.allow_rule_ids != allow or row.deny_rule_ids != deny:
            return verdict(
                False,
                "matching rule IDs differ (including overridden allows)",
                triple=list(key),
                expected_allow=allow,
                expected_deny=deny,
                actual_allow=row.allow_rule_ids,
                actual_deny=row.deny_rule_ids,
            )
        reason = Reason.EXPLICIT_DENY if deny else Reason.ALLOW if allow else Reason.DEFAULT_DENY
        if row.allowed != (bool(allow) and not deny) or row.reason != reason:
            return verdict(
                False,
                "decision violates deny-overrides/default-deny rules",
                triple=list(key),
                expected_reason=reason.value,
            )
    return verdict(
        True, "all memberships, access decisions and matching rules agree", users=len(users), decisions=expected_count
    )


def check_resource(arguments, output):
    if output is None:
        return verdict(False, "output is required")
    resource = next(item for item in arguments.policy.resources if item.resource_id == arguments.resource_id)
    children = sorted(
        item.resource_id for item in arguments.policy.resources if item.parent_id == arguments.resource_id
    )
    rules = sorted(rule.rule_id for rule in arguments.policy.rules if rule.resource_id == arguments.resource_id)
    if (
        output.resource_id != resource.resource_id
        or output.parent_id != resource.parent_id
        or output.inherit != resource.inherit
        or output.children != children
        or output.rule_ids != rules
    ):
        return verdict(False, "resource facts differ from the supplied policy")
    return verdict(True, "resource facts match")
