"""Grader exports and lookup utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from env.models import State
from env.registry import PackageRegistry
from graders.grader_easy import EasyGrader
from graders.grader_hard import HardGrader
from graders.grader_medium import MediumGrader


class BaseGrader(ABC):
	"""Abstract grader interface."""

	@abstractmethod
	def grade(self, state: State) -> tuple[float, dict[str, Any]]:
		raise NotImplementedError


def get_grader(task_id: str, registry: PackageRegistry | None = None) -> BaseGrader:
	"""Return task-specific grader implementation."""

	if task_id == "flat_audit":
		return EasyGrader()
	if task_id == "typosquat_transitive":
		return MediumGrader()
	if task_id == "full_sbom_remediation":
		return HardGrader(registry=registry)
	raise ValueError(f"Unknown task id: {task_id}")
