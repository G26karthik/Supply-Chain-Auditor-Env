"""Deterministic grader for medium task."""

from __future__ import annotations

from typing import Any

from env.models import State
from tasks.task_medium import TASK_MEDIUM


def _clamp01(value: float) -> float:
	return max(0.0, min(1.0, value))


class MediumGrader:
	"""Grades typosquatting and transitive CVE discovery behavior."""

	def __init__(self) -> None:
		self.gold_typosquats = set(TASK_MEDIUM.gold["typosquats"])
		self.gold_transitive = (
			TASK_MEDIUM.gold["transitive_cve"]["package"],
			TASK_MEDIUM.gold["transitive_cve"]["version"],
		)

	def grade(self, state: State) -> tuple[float, dict[str, Any]]:
		flagged_names = {flag.package_name for flag in state.flags}
		flagged_pairs = {(flag.package_name, flag.version) for flag in state.flags}

		typosquat_score = sum(0.5 for name in self.gold_typosquats if name in flagged_names)
		transitive_score = 1.0 if self.gold_transitive in flagged_pairs else 0.0

		false_positives = sum(
			1
			for flag in state.flags
			if flag.package_name not in self.gold_typosquats and (flag.package_name, flag.version) != self.gold_transitive
		)
		fp_penalty = min(false_positives * 0.1, 0.3)

		raw_score = (typosquat_score * 0.5 + transitive_score * 0.5) - fp_penalty
		score = _clamp01(raw_score)
		breakdown = {
			"typosquat_score": typosquat_score,
			"transitive_score": transitive_score,
			"false_positives": false_positives,
			"false_positive_penalty": fp_penalty,
			"raw_score": raw_score,
			"score": score,
		}
		return score, breakdown
