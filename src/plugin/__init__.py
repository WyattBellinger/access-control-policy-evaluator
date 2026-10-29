"""Offline policy tools; no system permissions are read or changed."""

from .policy import evaluate_policy, inspect_resource

__all__ = ["evaluate_policy", "inspect_resource"]
