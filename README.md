# Access Control Policy Evaluator

A `nanoagent.plugin/v0001` task that answers: **Which users can perform each
action on each resource after group expansion, permission inheritance and explicit
denials?** It checks the complete decision matrix and every matching rule ID,
including allows overridden by denials. It evaluates a supplied policy; it does
not inspect or change operating-system, cloud or application permissions.

## Tools

| Tool | Purpose |
|---|---|
| `inspect_resource` | Read one resource's parent, inheritance flag, immediate children and directly attached rule IDs |
| `evaluate_policy` | Compute the full membership and permission matrix for offline regression runs |

| Task | Runner | Available tools | Reference |
|---|---|---|---|
| `evaluate-access` | `agent` | `inspect_resource` | `null` |
| `evaluate-policy` | `tool` | `evaluate_policy` | `null` |

The agent reasons from the supplied policy and submits an `EvaluationOutput`
using NanoAgent's typed `submit` tool. The optional inspector reads local facts;
it does not compute effective access. The full evaluator is excluded from the
agent task. The independent verifier derives correctness from the original
policy, so neither task needs a pinned reference or an LLM judge. The tool task
provides a reproducible baseline and a way to exercise the real MCP runtime.

## Policy specification

Every field below is required, including empty lists and nullable `parent_id`.
`contract.py` declares their exact types. Unknown fields and incorrect types fail
the host's schema checks; invalid relationships fail semantic validation.

| Input field | Meaning |
|---|---|
| `users` | Complete list of user IDs |
| `actions` | Complete action catalog, such as `read`, `write` or `delete` |
| `groups` | Objects with `group_id`, `member_users`, `member_groups` |
| `resources` | Objects with `resource_id`, `parent_id` (ID or `null`), `inherit` (boolean) |
| `rules` | Objects with `rule_id`, `principal_type`, `principal_id`, `resource_id`, `actions`, `effect`, `propagate` |

All IDs are nonempty strings without surrounding whitespace, case-sensitive and
compared exactly. Interior spaces and Unicode are allowed, without normalization.
IDs are unique within each namespace; a user and a group may share an ID because
`principal_type` is explicitly `user` or `group`. Lists of members and actions
must also have no duplicates. Input order has no effect on the result. An action
named `*` is a literal action, not a wildcard; `write` implies no `read` access.

1. **Membership.** A group's members are its `member_users` plus all users in its
   `member_groups`, transitively. If `staff.member_groups=["engineers"]`, every
   engineer is staff; staff users do not automatically become engineers. Group
   cycles and self-membership are legal, with the least fixed point seeded by
   explicit user memberships. A cycle without user members grants nobody access.
   A user belongs to each reachable containing group once, regardless of paths.
2. **Resources.** Each resource has at most one declared parent. Multiple roots
   and disconnected trees are legal. Parent cycles, including self-parenting,
   are invalid, even when inheritance is disabled. A root's `inherit` flag has
   no effect because it has no parent.
3. **Rule scope.** A rule always applies on its own resource. With
   `propagate=true`, it also applies to descendants for which **every child on
   the path from the rule's resource has `inherit=true`**. An `inherit=false`
   resource blocks all ancestor rules, but retains its local rules; its local
   propagating rules can flow to inheriting children. A nonpropagating rule is
   local only. No rule flows upward or across siblings.
4. **Rule matching.** The user must equal a rule's named user or belong to its
   named group. The action must occur explicitly in the rule's nonempty action
   list. `effect` is exactly `allow` or `deny`. All principal IDs, resources,
   group members and actions must be declared. Different rule IDs may describe
   identical permissions; each matching ID must still appear in the result.
5. **Decision.** Any matching denial beats every allow, irrespective of depth,
   rule order, direct versus inherited origin, or user versus group principal.
   Otherwise any matching allow grants access. Otherwise access is denied by
   default. A closer allow cannot override an ancestor deny in this rule system.

For a user/resource/action triple, let A and D be the sets of matching allow and
deny rule IDs. `allowed = bool(A) and not bool(D)`. The required explanation is:

| Condition | `allowed` | `reason` |
|---|---|---|
| D is nonempty | `false` | `explicit-deny` |
| D is empty, A is nonempty | `true` | `allow` |
| A and D are empty | `false` | `default-deny` |

`explicit-deny` means an explicit deny **rule**, including an inherited rule.
All matching denies are responsible for denial; matching allows remain in the
trace even when overridden. Default denial has no matching rule IDs.

## Complete output and example

`memberships` contains exactly one `{user_id, group_ids}` row for every user,
sorted by `user_id`. Each `group_ids` list is the sorted, deduplicated effective
membership set, including direct and transitive groups.

`decisions` contains exactly **users × resources × actions** rows, sorted by
`(user_id, resource_id, action)` using Python string/code-point order. Every row
has `user_id`, `resource_id`, `action`, `allowed`, `reason`, `allow_rule_ids` and
`deny_rule_ids`. Both rule lists contain every matching ID once, sorted by ID.
Denied rows cannot be omitted. An empty users/resources/actions dimension yields
no decisions; memberships still includes every user. Empty policies are valid.

The synthetic [example policy](tests/fixtures/example.json) has three users,
four groups (including a seeded cycle), five resources, two actions and nine rules.
Its [hand-specified expected result](tests/fixtures/example-expected.json)
contains 30 decisions. Selected rows illustrate the semantics:

| User | Resource/action | Matching allows | Matching denies | Result |
|---|---|---|---|---|
| bob | docs/write | base, local-override | blocked-writes | explicit-deny |
| alice | docs/read | base, docs-read | alice-local-deny | explicit-deny |
| alice | secret/write | alice-secret | none | allow |
| bob | secret/write | none | none | default-deny |
| eve | archive/read | audit-read | archive-deny | explicit-deny |

`secret.inherit=false` excludes the ancestor `base` and `blocked-writes` rules;
its own `audit-read` and `alice-secret` rules propagate to `archive`.
The other fixtures isolate inheritance barriers, unseeded membership cycles,
and the empty-policy boundary. All data is invented and contains no real users'
access policies.

## Deterministic verification

The verifier implements `verify_input`, `verify_output` and `verify_task`, returning
`valid`, binary `score`, `message` and `details`. Scores are all-or-nothing: a
correct allow/deny bit with incorrect rule IDs still fails. It validates the
original policy, checks all memberships, enforces exact matrix completeness and
ordering, and compares every decision, reason and allow/deny ID list. It reports
the first mismatch in a deterministic order. Missing, extra, duplicated,
reordered or fabricated entries fail.

The runtime finds containing groups per user and walks resource ancestor chains.
The verifier independently grows group user sets to a least fixed point and
pushes each rule forward through inheriting children. It imports only contract
declarations and deterministic standard-library modules, never runtime code.
It performs no LLM calls, network access, clock reads, randomness, subprocesses
or file writes. The workspace and reference parameters are unused because the
entire answer is a pure function of typed input. NanoAgent performs type validation,
isolates verifier calls, and executes them twice to check repeatability.

## Layout

```text
nanoagent.yaml             Typed manifest, permissions, task instructions
contract.py                Complete input/output types and enums
src/plugin/__main__.py     Typed MCP stdio server
src/plugin/policy.py       Input validation, resource inspection, offline evaluator
verifier/                  Independent validation and full semantic checks
tests/                     Fixtures, mutation, boundary and independent-oracle checks
ui/                        Standard schema renderer and host styling
product/                   Marketplace metadata and original generic lock icon
pyproject.toml, uv.lock     Independently installable package and pinned dependencies
.env                       No required environment variables
LICENSE                    MIT code license
```

Reports, validation tools, logs, packages and run outputs belong outside this
repository, in the sibling `access-control-policy-evaluator-evidence/` folder.
The plugin requests no network hosts and no filesystem writes. Initial dependency
installation may use the network; policy tools and verifiers run offline.

## Develop and run

Use Git, uv and Python 3.12+. From this plugin's root:

```bash
uv sync --frozen --extra dev
uv run --frozen pytest -v
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv lock --check --offline
```

Place this checkout next to the course's NanoAgent checkout (the host Python
project is `../nanoagent/nanoagent`). Install and inspect with:

```bash
uv sync --project ../nanoagent/nanoagent --frozen
uv run --project ../nanoagent/nanoagent --frozen nanoagent plugin inspect "$PWD"
```

Run the real offline MCP tool task with the supplied example, using a NEW run
folder each time:

```bash
mkdir -p ../access-control-policy-evaluator-evidence
cat > ../access-control-policy-evaluator-evidence/example.yaml <<EOF_CONFIG
_ > nanoagent.cli.plugin.PluginRunConfig:
plugin: "$PWD"
task: evaluate-policy
arguments: "$PWD/tests/fixtures/example.json"
inputs: []
timeout: 60.0
EOF_CONFIG
uv run --project ../nanoagent/nanoagent --frozen nanoagent plugin run \
  config="$PWD/../access-control-policy-evaluator-evidence/example.yaml" \
  home="$PWD/../access-control-policy-evaluator-evidence/example-run"
```

The run's `result.json` contains the actual output; `verdict.json` must say
`valid: true`, `score: 1.0`. Compare the output to `example-expected.json`.
For a correct/incorrect verifier reproduction without a model or host:

```bash
uv run --frozen python - <<'PY'
import copy, json
from pathlib import Path
from slimconfig import build_output
from contract import PolicyInput, EvaluationOutput
from verifier import verify_task
folder = Path("tests/fixtures")
policy = build_output(json.loads((folder / "example.json").read_text()), PolicyInput)
raw = json.loads((folder / "example-expected.json").read_text())
good = verify_task("evaluate-access", policy, build_output(raw, EvaluationOutput), None, Path("."))
bad = copy.deepcopy(raw)
bad["decisions"][0]["allowed"] = not bad["decisions"][0]["allowed"]
wrong = verify_task("evaluate-access", policy, build_output(bad, EvaluationOutput), None, Path("."))
assert good["valid"] and not wrong["valid"]
print(json.dumps({"correct": good, "incorrect": wrong}, indent=2))
PY
```

The sibling evidence README documents the full integration validation, including
scripted positive/negative agent submissions and installing the packed artifact.
These scripted calls exercise the harness with known fixture answers; they do
not establish a real model's ability to solve the task.

## RUSH Lab handoff

1. Create a public independent GitHub repository for this plugin and push the
   complete source and lockfile. The local checkout has its own Git history.
2. Submit its URL through RUSH Lab's **Submit Your Artifact** flow. `status: ready`
   means ready for package validation; publication and platform acceptance must
   be recorded separately.
3. After installation, ask the plugin chat to run `evaluate-access` with the
   full `tests/fixtures/example.json` policy. It should reason about memberships
   and rules, optionally call `inspect_resource`, and submit the complete matrix.
   Supplying this synthetic policy is intentional; this is not a live IAM scanner.
4. Save the actual task output and task verifier verdict. Marketplace format
   checks alone do not establish semantic correctness or actual model performance.
   Have another student or TA reproduce the README checks and record the outcome.

Package locally with:

```bash
uv run --project ../nanoagent/nanoagent --frozen nanoagent plugin pack \
  "$PWD" "$PWD/../access-control-policy-evaluator-evidence/access-control-policy-evaluator-v0.1.0.tar.gz"
```

## Limits

This is a deliberately specified educational rule system. It does not emulate
POSIX ACLs, Windows ACLs, AWS IAM or a particular application's policy precedence.
It has no roles beyond groups, conditions, time-based rules, ownership, implicit
administrator privileges, wildcard actions, multiple resource parents, or live
identity provider. Completeness is relative to the supplied users, resources,
actions and rules. The verifier cannot establish that the supplied policy matches
a real deployment. Full matrices and traces grow with the Cartesian product and
number of matching rules; very large policies may exceed host/model context or
execution limits. The assignment report and RUSH Lab validation remain separate
steps after local implementation; no report is generated by this plugin.
