"""Deterministic grader for easy task."""

from __future__ import annotations

from typing import Any

from env.models import State
from tasks.task_easy import TASK_EASY


def _clamp01(value: float) -> float:
	return max(0.0, min(1.0, value))


class EasyGrader:
	"""Grades flat CVE audit task using F1 score."""

	def __init__(self) -> None:
		self.gold_pairs = set(TASK_EASY.gold["cve_pairs"].keys())

	def grade(self, state: State) -> tuple[float, dict[str, Any]]:
		found: set[str] = set()
		false_positives = 0

		for flag in state.flags:
			key = f"{flag.package_name}:{flag.version}"
			if key in self.gold_pairs:
				found.add(key)
			else:
				false_positives += 1

		found_count = len(found)
		precision_denominator = found_count + false_positives
		precision = found_count / precision_denominator if precision_denominator > 0 else 0.0
		recall = found_count / len(self.gold_pairs) if self.gold_pairs else 0.0
		f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

		score = _clamp01(f1)
		breakdown = {
			"found": sorted(found),
			"false_positives": false_positives,
			"precision": precision,
			"recall": recall,
			"f1": f1,
			"score": score,
		}
		return score, breakdown
