"""NanoAgent v0001 entrypoints; shape checking is performed by the typed host."""

from .checks import check_evaluation, check_resource, read_policy, verdict


def verify_input(tool, value):
    if tool not in {"inspect_resource", "evaluate_policy"}:
        return verdict(False, "unknown tool")
    if value is None:
        return verdict(False, "input is required")
    try:
        _, _, resources = read_policy(value.policy if tool == "inspect_resource" else value)
        if tool == "inspect_resource" and value.resource_id not in resources:
            return verdict(False, "inspected resource must be declared")
    except ValueError as error:
        return verdict(False, str(error))
    return verdict(True, "policy input is valid")


def verify_output(tool, input_value, output_value, workspace):
    checked = verify_input(tool, input_value)
    if not checked["valid"]:
        return checked
    if tool == "inspect_resource":
        return check_resource(input_value, output_value)
    return check_evaluation(input_value, output_value)


def verify_task(task, arguments, output, reference, workspace):
    if task not in {"evaluate-access", "evaluate-policy"}:
        return verdict(False, "unknown task")
    return check_evaluation(arguments, output)
