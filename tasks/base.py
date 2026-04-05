"""Task definitions shared structure."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BaseTask:
	"""Immutable task metadata used by environment and graders."""

	task_id: str
	name: str
	difficulty: str
	max_steps: int
	objective: str
	requirements: list[str]
	gold: dict[str, Any] = field(default_factory=dict)
