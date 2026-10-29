import copy

import pytest
from slimconfig import build_output

import verifier
from contract import EvaluationOutput, InspectInput, PolicyInput, ResourceOutput
from plugin import evaluate_policy, inspect_resource


def check(policy, raw, task="evaluate-access"):
    return verifier.verify_task(
        task, build_output(policy, PolicyInput), build_output(raw, EvaluationOutput), None, "unused"
    )


@pytest.mark.parametrize("task", ["evaluate-access", "evaluate-policy"])
@pytest.mark.parametrize("name", ["example", "inheritance", "cycles", "empty"])
def test_accepts_exact_hand_specified_results(task, name, load_fixture):
    result = check(load_fixture(name), load_fixture(name + "-expected"), task)
    assert result["valid"] and result["score"] == 1.0
    assert result == check(load_fixture(name), load_fixture(name + "-expected"), task)


@pytest.mark.parametrize(
    "field", ["allowed", "reason", "user_id", "resource_id", "action", "allow_rule_ids", "deny_rule_ids"]
)
def test_rejects_mutation_of_every_cell_field(field, load_fixture):
    policy = load_fixture("example")
    wanted = load_fixture("example-expected")
    for index, row in enumerate(wanted["decisions"]):
        bad = copy.deepcopy(wanted)
        replacement = {
            "allowed": not row["allowed"],
            "reason": "default-deny" if row["reason"] != "default-deny" else "allow",
            "user_id": "invented",
            "resource_id": "invented",
            "action": "invented",
            "allow_rule_ids": [*row["allow_rule_ids"], "invented"],
            "deny_rule_ids": [*row["deny_rule_ids"], "invented"],
        }
        bad["decisions"][index][field] = replacement[field]
        result = check(policy, bad)
        assert not result["valid"] and result["score"] == 0.0, (index, field)


@pytest.mark.parametrize("mode", ["missing", "extra", "duplicate", "reversed", "only_allows"])
def test_rejects_incomplete_or_unordered_matrix(mode, load_fixture):
    raw = load_fixture("example-expected")
    if mode == "missing":
        raw["decisions"].pop()
    elif mode == "extra":
        raw["decisions"].append(copy.deepcopy(raw["decisions"][0]))
    elif mode == "duplicate":
        raw["decisions"][1] = copy.deepcopy(raw["decisions"][0])
    elif mode == "reversed":
        raw["decisions"].reverse()
    else:
        raw["decisions"] = [row for row in raw["decisions"] if row["allowed"]]
    assert not check(load_fixture("example"), raw)["valid"]


@pytest.mark.parametrize(
    "mode",
    [
        "missing_user",
        "extra_user",
        "duplicate_user",
        "reversed_users",
        "missing_group",
        "duplicate_group",
        "extra_group",
        "reversed_groups",
        "wrong_user",
    ],
)
def test_rejects_incorrect_membership_certificate(mode, load_fixture):
    raw = load_fixture("example-expected")
    rows = raw["memberships"]
    if mode == "missing_user":
        rows.pop()
    elif mode == "extra_user":
        rows.append({"user_id": "invented", "group_ids": []})
    elif mode == "duplicate_user":
        rows[1] = copy.deepcopy(rows[0])
    elif mode == "reversed_users":
        rows.reverse()
    elif mode == "missing_group":
        rows[1]["group_ids"].pop()
    elif mode == "duplicate_group":
        rows[1]["group_ids"].append(rows[1]["group_ids"][-1])
    elif mode == "extra_group":
        rows[0]["group_ids"].append("auditors")
    elif mode == "reversed_groups":
        rows[1]["group_ids"].reverse()
    else:
        rows[0]["user_id"] = "Alice"
    assert not check(load_fixture("example"), raw)["valid"]


@pytest.mark.parametrize(
    "mode",
    [
        "missing_overridden_allow",
        "missing_deny",
        "duplicate_allow",
        "duplicate_deny",
        "reversed_allow",
        "unrelated_rule",
        "known_but_out_of_scope",
        "pretend_local_override",
    ],
)
def test_rejects_incorrect_rule_explanations_even_with_right_bits(mode, load_fixture):
    raw = load_fixture("example-expected")
    row = next(
        row
        for row in raw["decisions"]
        if (row["user_id"], row["resource_id"], row["action"]) == ("bob", "docs", "write")
    )
    if mode == "missing_overridden_allow":
        row["allow_rule_ids"] = []
    elif mode == "missing_deny":
        row["deny_rule_ids"] = []
    elif mode == "duplicate_allow":
        row["allow_rule_ids"].append("local-override")
    elif mode == "duplicate_deny":
        row["deny_rule_ids"].append("blocked-writes")
    elif mode == "reversed_allow":
        row["allow_rule_ids"].reverse()
    elif mode == "unrelated_rule":
        row["allow_rule_ids"] = ["docs-read"]
    elif mode == "known_but_out_of_scope":
        row["deny_rule_ids"] = ["archive-deny"]
    else:
        row["allowed"] = True
        row["reason"] = "allow"
    assert not check(load_fixture("example"), raw)["valid"]


INVALID_CASES = [
    "duplicate_user",
    "duplicate_action",
    "duplicate_group",
    "duplicate_resource",
    "duplicate_rule",
    "blank_user",
    "blank_action",
    "blank_group",
    "blank_resource",
    "blank_rule",
    "padded_user",
    "padded_action",
    "padded_group",
    "padded_resource",
    "padded_rule",
    "unknown_user_member",
    "unknown_group_member",
    "duplicate_user_member",
    "duplicate_group_member",
    "unknown_parent",
    "self_parent",
    "parent_cycle",
    "unknown_rule_user",
    "unknown_rule_group",
    "unknown_rule_resource",
    "unknown_rule_action",
    "empty_rule_actions",
    "duplicate_rule_actions",
]


def invalid_policy(raw, case):
    plural = {"user": "users", "action": "actions", "group": "groups", "resource": "resources", "rule": "rules"}
    prefix, _, kind = case.partition("_")
    if prefix in {"duplicate", "blank", "padded"} and kind in plural:
        rows = raw[plural[kind]]
        if prefix == "duplicate":
            rows.append(copy.deepcopy(rows[0]))
        elif kind in {"user", "action"}:
            rows[0] = " " if prefix == "blank" else "\t" + rows[0]
        else:
            field = kind + "_id"
            rows[0][field] = "" if prefix == "blank" else rows[0][field] + " "
    elif case == "unknown_user_member":
        raw["groups"][0]["member_users"].append("ghost")
    elif case == "unknown_group_member":
        raw["groups"][0]["member_groups"].append("ghost")
    elif case == "duplicate_user_member":
        raw["groups"][0]["member_users"] *= 2
    elif case == "duplicate_group_member":
        raw["groups"][0]["member_groups"] *= 2
    elif case == "unknown_parent":
        raw["resources"][0]["parent_id"] = "ghost"
    elif case == "self_parent":
        raw["resources"][0]["parent_id"] = "root"
    elif case == "parent_cycle":
        raw["resources"][0]["parent_id"] = "archive"
    elif case in {"unknown_rule_user", "unknown_rule_group"}:
        raw["rules"][0]["principal_type"] = "user" if case.endswith("user") else "group"
        raw["rules"][0]["principal_id"] = "ghost"
    elif case == "unknown_rule_resource":
        raw["rules"][0]["resource_id"] = "ghost"
    elif case == "unknown_rule_action":
        raw["rules"][0]["actions"].append("ghost")
    elif case == "empty_rule_actions":
        raw["rules"][0]["actions"] = []
    elif case == "duplicate_rule_actions":
        raw["rules"][0]["actions"] *= 2
    else:
        raise AssertionError(case)
    return raw


@pytest.mark.parametrize("case", INVALID_CASES)
def test_invalid_inputs_rejected_by_tools_and_verifier(case, load_fixture, tmp_path):
    value = build_output(invalid_policy(load_fixture("example"), case), PolicyInput)
    inspected = InspectInput(value, "docs")
    assert not verifier.verify_input("evaluate_policy", value)["valid"]
    assert not verifier.verify_input("inspect_resource", inspected)["valid"]
    assert not verifier.verify_task("evaluate-access", value, EvaluationOutput([], []), None, tmp_path)["valid"]
    assert not verifier.verify_output("evaluate_policy", value, EvaluationOutput([], []), tmp_path)["valid"]
    with pytest.raises(ValueError):
        evaluate_policy(value, tmp_path)
    with pytest.raises(ValueError):
        inspect_resource(inspected, tmp_path)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("users", "u"),
        ("users", [1]),
        ("users", [True]),
        ("actions", None),
        ("groups", [{}]),
        ("resources", [{}]),
        ("rules", [{}]),
    ],
)
def test_schema_rejects_malformed_policy(field, bad, load_fixture):
    raw = load_fixture("example")
    raw[field] = bad
    with pytest.raises(ValueError):
        build_output(raw, PolicyInput)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("principal_type", "everyone"),
        ("effect", "permit"),
        ("propagate", 1),
        ("propagate", "true"),
        ("actions", "read"),
        ("actions", [None]),
        ("principal_id", None),
    ],
)
def test_schema_rejects_malformed_rule(field, bad, load_fixture):
    raw = load_fixture("example")
    raw["rules"][0][field] = bad
    with pytest.raises(ValueError):
        build_output(raw, PolicyInput)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        {"memberships": []},
        {"memberships": None, "decisions": []},
        {"memberships": [], "decisions": [], "valid": True},
    ],
)
def test_schema_rejects_missing_malformed_output(raw):
    with pytest.raises(ValueError):
        build_output(raw, EvaluationOutput)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("allowed", 1),
        ("allowed", "false"),
        ("reason", "denied"),
        ("allow_rule_ids", None),
        ("deny_rule_ids", [1]),
        ("action", None),
    ],
)
def test_schema_rejects_malformed_decision(field, bad, load_fixture):
    raw = load_fixture("example-expected")
    raw["decisions"][0][field] = bad
    with pytest.raises(ValueError):
        build_output(raw, EvaluationOutput)


def test_schema_rejects_missing_extra_and_wrong_resource_fields(load_fixture):
    for mode in ["missing_parent", "unknown_field", "wrong_boolean"]:
        raw = load_fixture("example")
        if mode == "missing_parent":
            del raw["resources"][0]["parent_id"]
        elif mode == "unknown_field":
            raw["resources"][0]["owner"] = "alice"
        else:
            raw["resources"][0]["inherit"] = 0
        with pytest.raises(ValueError):
            build_output(raw, PolicyInput)


@pytest.mark.parametrize(
    "field,bad", [("resource_id", "root"), ("parent_id", None), ("inherit", False), ("children", []), ("rule_ids", [])]
)
def test_inspector_rejects_changed_facts(field, bad, load_fixture, tmp_path):
    given = build_output({"policy": load_fixture("example"), "resource_id": "docs"}, InspectInput)
    answer = {
        "resource_id": "docs",
        "parent_id": "root",
        "inherit": True,
        "children": ["secret"],
        "rule_ids": ["alice-local-deny", "docs-read", "local-override"],
    }
    assert verifier.verify_output("inspect_resource", given, build_output(answer, ResourceOutput), tmp_path)["valid"]
    answer[field] = bad
    assert not verifier.verify_output("inspect_resource", given, build_output(answer, ResourceOutput), tmp_path)[
        "valid"
    ]


def test_unknown_inspected_resource(load_fixture, tmp_path):
    value = InspectInput(build_output(load_fixture("example"), PolicyInput), "ghost")
    assert not verifier.verify_input("inspect_resource", value)["valid"]
    with pytest.raises(ValueError):
        inspect_resource(value, tmp_path)


def test_missing_values_unknown_entrypoints_and_tool_checks(load_fixture, tmp_path):
    value = build_output(load_fixture("example"), PolicyInput)
    answer = build_output(load_fixture("example-expected"), EvaluationOutput)
    for tool in ["evaluate_policy", "inspect_resource", "unknown"]:
        assert not verifier.verify_input(tool, None)["valid"]
    assert not verifier.verify_input("unknown", value)["valid"]
    assert not verifier.verify_output("unknown", value, answer, tmp_path)["valid"]
    assert not verifier.verify_output("evaluate_policy", value, None, tmp_path)["valid"]
    assert not verifier.verify_task("evaluate-access", value, None, None, tmp_path)["valid"]
    assert not verifier.verify_task("evaluate-access", None, answer, None, tmp_path)["valid"]
    assert not verifier.verify_task("unknown", value, answer, None, tmp_path)["valid"]
    assert verifier.verify_output("evaluate_policy", value, answer, tmp_path)["valid"]
    assert not verifier.verify_output("inspect_resource", InspectInput(value, "docs"), None, tmp_path)["valid"]
    answer.decisions[0].allowed = not answer.decisions[0].allowed
    assert not verifier.verify_output("evaluate_policy", value, answer, tmp_path)["valid"]
