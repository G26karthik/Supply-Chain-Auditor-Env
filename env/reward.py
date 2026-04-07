"""Reward shaping for Supply Chain Auditor episodes."""

from __future__ import annotations

from dataclasses import dataclass

from env.models import Reward


REWARD_TABLE: dict[str, float] = {
	"correct_cve_flagged": 0.12,
	"typosquat_detected": 0.18,
	"transitive_dep_traced": 0.08,
	"false_positive_flag": -0.08,
	"valid_remediation": 0.08,
	"invalid_remediation": -0.05,
	"sbom_generated": 0.05,
	"redundant_action": -0.02,
	"step_penalty": -0.01,
	"report_submitted_complete": 0.20,
	"report_submitted_partial": 0.10,
}


def clamp(value: float, min_val: float = -1.0, max_val: float = 1.0) -> float:
	"""Clamp numeric value into [min_val, max_val]."""

	return max(min_val, min(max_val, value))


def clamp01(value: float) -> float:
	"""Clamp numeric value to strictly within (0.0, 1.0) open interval."""

	return max(0.001, min(0.999, value))


@dataclass
class RewardResult:
	"""Result bundle for reward updates."""

	reward: Reward
	cumulative_reward: float


class RewardEngine:
	"""Compute bounded step rewards from named events."""

	def __init__(self, reward_table: dict[str, float] | None = None) -> None:
		self.reward_table = dict(REWARD_TABLE if reward_table is None else reward_table)

	def apply(self, event: str, cumulative_reward: float, reason: str | None = None) -> RewardResult:
		"""Apply one reward event and return step reward plus updated cumulative value."""

		delta = self.reward_table.get(event, 0.0)
		updated_cumulative = clamp01(cumulative_reward + delta)

		# Step rewards are bounded to [-1, 1] per spec.
		step_reward = Reward(
			value=clamp(delta, -1.0, 1.0),
			reason=reason or event,
		)
		return RewardResult(reward=step_reward, cumulative_reward=updated_cumulative)

	def from_score(self, score: float, cumulative_reward: float) -> RewardResult:
		"""Award submission reward based on terminal task score."""

		if score > 0.8:
			event = "report_submitted_complete"
		elif score >= 0.4:
			event = "report_submitted_partial"
		else:
			event = "step_penalty"
		return self.apply(event=event, cumulative_reward=cumulative_reward)
