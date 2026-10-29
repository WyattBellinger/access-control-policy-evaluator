import copy
import itertools
import random

import pytest
from slimconfig import build_output, plain_output

from contract import InspectInput, PolicyInput
from plugin import evaluate_policy, inspect_resource
from verifier import verify_task


@pytest.mark.parametrize("name", ["example", "inheritance", "cycles", "empty"])
def test_hand_specified_fixtures(name, load_fixture, tmp_path):
    raw = load_fixture(name)
    before = copy.deepcopy(raw)
    result = evaluate_policy(build_output(raw, PolicyInput), tmp_path)
    assert plain_output(result) == load_fixture(name + "-expected")
    assert verify_task("evaluate-access", build_output(raw, PolicyInput), result, None, tmp_path)["valid"]
    assert raw == before
    assert list(tmp_path.iterdir()) == []


def test_resource_inspector_returns_only_local_facts(load_fixture, tmp_path):
    value = build_output({"policy": load_fixture("example"), "resource_id": "docs"}, InspectInput)
    assert plain_output(inspect_resource(value, tmp_path)) == {
        "resource_id": "docs",
        "parent_id": "root",
        "inherit": True,
        "children": ["secret"],
        "rule_ids": ["alice-local-deny", "docs-read", "local-override"],
    }


def test_input_order_does_not_affect_output(load_fixture, tmp_path):
    raw = load_fixture("example")
    for values in raw.values():
        values.reverse()
    for group in raw["groups"]:
        group["member_users"].reverse()
        group["member_groups"].reverse()
    for rule in raw["rules"]:
        rule["actions"].reverse()
    assert plain_output(evaluate_policy(build_output(raw, PolicyInput), tmp_path)) == load_fixture("example-expected")


def test_diamond_membership_duplicate_semantics_and_namespace_separation(tmp_path):
    raw = {
        "users": ["same"],
        "actions": ["read"],
        "groups": [
            {"group_id": "same", "member_users": ["same"], "member_groups": []},
            {"group_id": "left", "member_users": [], "member_groups": ["same"]},
            {"group_id": "right", "member_users": [], "member_groups": ["same"]},
            {"group_id": "top", "member_users": ["same"], "member_groups": ["left", "right"]},
        ],
        "resources": [{"resource_id": "r", "parent_id": None, "inherit": True}],
        "rules": [
            {
                "rule_id": name,
                "principal_type": "group",
                "principal_id": "top",
                "resource_id": "r",
                "actions": ["read"],
                "effect": "allow",
                "propagate": True,
            }
            for name in ["2", "10"]
        ],
    }
    result = evaluate_policy(build_output(raw, PolicyInput), tmp_path)
    assert result.memberships[0].group_ids == ["left", "right", "same", "top"]
    assert result.decisions[0].allow_rule_ids == ["10", "2"]
    assert verify_task("evaluate-access", build_output(raw, PolicyInput), result, None, tmp_path)["valid"]


def test_literal_actions_exact_unicode_and_case(tmp_path):
    names = ["A", "a", "two words", "é", "e\u0301", "λ"]
    raw = {
        "users": names,
        "actions": ["*", "Read", "read", "write"],
        "groups": [],
        "resources": [{"resource_id": "r", "parent_id": None, "inherit": True}],
        "rules": [
            {
                "rule_id": "literal",
                "principal_type": "user",
                "principal_id": "A",
                "resource_id": "r",
                "actions": ["*", "write"],
                "effect": "allow",
                "propagate": True,
            }
        ],
    }
    result = evaluate_policy(build_output(raw, PolicyInput), tmp_path)
    assert [row.user_id for row in result.memberships] == sorted(names)
    assert [(row.user_id, row.action) for row in result.decisions if row.allowed] == [("A", "*"), ("A", "write")]
    assert verify_task("evaluate-access", build_output(raw, PolicyInput), result, None, tmp_path)["valid"]


@pytest.mark.parametrize("dimension", ["users", "resources", "actions"])
def test_empty_dimensions_keep_memberships(dimension, tmp_path):
    raw = {
        "users": ["u"],
        "actions": ["read"],
        "groups": [],
        "resources": [{"resource_id": "r", "parent_id": None, "inherit": False}],
        "rules": [],
    }
    raw[dimension] = []
    result = evaluate_policy(build_output(raw, PolicyInput), tmp_path)
    assert result.decisions == []
    assert [row.user_id for row in result.memberships] == raw["users"]
    assert verify_task("evaluate-access", build_output(raw, PolicyInput), result, None, tmp_path)["valid"]


def test_deep_group_and_resource_chains_are_iterative(tmp_path):
    size = 1600
    raw = {
        "users": ["u"],
        "actions": ["read"],
        "groups": [
            {
                "group_id": f"g{i}",
                "member_users": ["u"] if i == size - 1 else [],
                "member_groups": [f"g{i + 1}"] if i + 1 < size else [],
            }
            for i in range(size)
        ],
        "resources": [
            {"resource_id": f"r{i}", "parent_id": f"r{i - 1}" if i else None, "inherit": True} for i in range(size)
        ],
        "rules": [
            {
                "rule_id": "all",
                "principal_type": "group",
                "principal_id": "g0",
                "resource_id": "r0",
                "actions": ["read"],
                "effect": "allow",
                "propagate": True,
            }
        ],
    }
    value = build_output(raw, PolicyInput)
    result = evaluate_policy(value, tmp_path)
    assert len(result.memberships[0].group_ids) == size
    assert len(result.decisions) == size
    assert all(row.allowed and row.allow_rule_ids == ["all"] for row in result.decisions)
    assert verify_task("evaluate-access", value, result, None, tmp_path)["valid"]
    raw["resources"][0]["parent_id"] = f"r{size - 1}"
    with pytest.raises(ValueError, match="cycle"):
        evaluate_policy(build_output(raw, PolicyInput), tmp_path)


def path_oracle(raw):
    """Small-graph exhaustive simple paths, independent of both implementation algorithms."""
    groups = {g["group_id"]: g for g in raw["groups"]}
    resources = {r["resource_id"]: r for r in raw["resources"]}

    def belongs(user, group, visited):
        if group in visited:
            return False
        record = groups[group]
        return user in record["member_users"] or any(
            belongs(user, child, visited | {group}) for child in record["member_groups"]
        )

    def scope(rule, target):
        if rule["resource_id"] == target:
            return True
        row = resources[target]
        return bool(
            rule["propagate"] and row["inherit"] and row["parent_id"] is not None and scope(rule, row["parent_id"])
        )

    memberships = [
        {"user_id": u, "group_ids": sorted(g for g in groups if belongs(u, g, set()))} for u in sorted(raw["users"])
    ]
    decisions = []
    for u, r, a in itertools.product(sorted(raw["users"]), sorted(resources), sorted(raw["actions"])):
        applicable = [
            rule
            for rule in raw["rules"]
            if a in rule["actions"]
            and scope(rule, r)
            and (
                u == rule["principal_id"]
                if rule["principal_type"] == "user"
                else belongs(u, rule["principal_id"], set())
            )
        ]
        allow = sorted(rule["rule_id"] for rule in applicable if rule["effect"] == "allow")
        deny = sorted(rule["rule_id"] for rule in applicable if rule["effect"] == "deny")
        decisions.append(
            {
                "user_id": u,
                "resource_id": r,
                "action": a,
                "allowed": bool(allow) and not bool(deny),
                "reason": "explicit-deny" if deny else "allow" if allow else "default-deny",
                "allow_rule_ids": allow,
                "deny_rule_ids": deny,
            }
        )
    return {"memberships": memberships, "decisions": decisions}


def test_exhaustive_three_group_membership_graphs(tmp_path):
    # All 512 directed inclusion graphs, including self-loops, with each seed or no seed.
    groups = ["A", "B", "C"]
    edges = list(itertools.product(groups, repeat=2))
    for mask in range(512):
        for seed in [None, *groups]:
            raw = {
                "users": ["u"],
                "actions": ["read"],
                "groups": [
                    {
                        "group_id": g,
                        "member_users": ["u"] if g == seed else [],
                        "member_groups": [b for bit, (a, b) in enumerate(edges) if a == g and mask & (1 << bit)],
                    }
                    for g in groups
                ],
                "resources": [{"resource_id": "r", "parent_id": None, "inherit": True}],
                "rules": [
                    {
                        "rule_id": g,
                        "principal_type": "group",
                        "principal_id": g,
                        "resource_id": "r",
                        "actions": ["read"],
                        "effect": "allow",
                        "propagate": False,
                    }
                    for g in groups
                ],
            }
            value = build_output(raw, PolicyInput)
            result = evaluate_policy(value, tmp_path)
            assert plain_output(result) == path_oracle(raw), (mask, seed)
            assert verify_task("evaluate-access", value, result, None, tmp_path)["valid"], (mask, seed)


def test_seeded_policies_against_simple_path_oracle(tmp_path):
    rng = random.Random(480)
    for _ in range(150):
        users = ["u0", "u1", "u2"]
        actions = ["read", "write", "delete"]
        group_ids = ["g0", "g1", "g2", "g3"]
        resource_ids = [f"r{i}" for i in range(7)]
        raw = {
            "users": users,
            "actions": actions,
            "groups": [
                {
                    "group_id": g,
                    "member_users": [u for u in users if rng.random() < 0.25],
                    "member_groups": [other for other in group_ids if rng.random() < 0.25],
                }
                for g in group_ids
            ],
            "resources": [
                {
                    "resource_id": r,
                    "parent_id": rng.choice([None, *resource_ids[:i]]),
                    "inherit": rng.choice([False, True]),
                }
                for i, r in enumerate(resource_ids)
            ],
            "rules": [],
        }
        for i in range(20):
            kind = rng.choice(["user", "group"])
            raw["rules"].append(
                {
                    "rule_id": f"rule-{i}",
                    "principal_type": kind,
                    "principal_id": rng.choice(users if kind == "user" else group_ids),
                    "resource_id": rng.choice(resource_ids),
                    "actions": rng.sample(actions, rng.randint(1, 3)),
                    "effect": rng.choice(["allow", "deny"]),
                    "propagate": rng.choice([True, False]),
                }
            )
        value = build_output(raw, PolicyInput)
        result = evaluate_policy(value, tmp_path)
        assert plain_output(result) == path_oracle(raw)
        assert verify_task("evaluate-access", value, result, None, tmp_path)["valid"]
