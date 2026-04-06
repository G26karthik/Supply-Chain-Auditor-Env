"""Main OpenEnv-compatible environment for supply chain auditing."""

from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment

from env.models import Action, ActionType, FlagEntry, Observation, RemediationEntry, Reward, State
from env.registry import PackageRegistry
from env.reward import RewardEngine, clamp01
from graders import BaseGrader, get_grader
from tasks import get_task
from tasks.base import BaseTask


class SupplyChainEnv(Environment):
	"""Environment where an agent audits dependencies for software supply chain risks."""

	SUPPORTS_CONCURRENT_SESSIONS: bool = True

	def __init__(self, fixtures_dir: str | None = None) -> None:
		self.registry = PackageRegistry(fixtures_dir=fixtures_dir)
		self.reward_engine = RewardEngine()

		self._task: BaseTask | None = None
		self._grader: BaseGrader | None = None
		self._state: State | None = None
		self._seen_actions: set[tuple[Any, ...]] = set()
		self._seen_trace_nodes: set[tuple[str, str]] = set()
		self._last_breakdown: dict[str, Any] = {}

	def reset(self, seed: Optional[int] = None, episode_id: Optional[str] = None, **kwargs: Any) -> Observation:
		"""Start a new episode for the provided task id."""

		task_id = kwargs.get("task_id", "flat_audit")
		task = get_task(task_id)
		self._task = task
		self._grader = get_grader(task_id, registry=self.registry)
		self._seen_actions = set()
		self._seen_trace_nodes = set()
		self._last_breakdown = {}

		self._state = State(
			episode_id=episode_id or str(uuid4()),
			step_count=0,
			task_id=task.task_id,
			step=0,
			max_steps=task.max_steps,
			requirements=list(task.requirements),
			objective=task.objective,
			flags=[],
			remediations=[],
			sbom=None,
			cumulative_reward=0.0,
			done=False,
			score=None,
		)

		return self._build_observation(message="Episode initialized.")

	def step(self, action: Action) -> Observation:
		"""Apply an action and advance environment state by one step."""

		if self._state is None or self._task is None or self._grader is None:
			raise RuntimeError("Environment not initialized. Call reset() first.")

		if self._state.done:
			return self._build_observation(
				message="Episode already complete. Call reset() to start a new run.",
				reward=0.0,
				info={"score": self._state.score, "breakdown": self._last_breakdown}
			)

		action_key = (
			action.action_type.value,
			action.package_name,
			action.version,
			action.target_version,
			action.depth,
		)
		redundant = action_key in self._seen_actions
		self._seen_actions.add(action_key)

		event = "step_penalty"
		last_action_result: dict[str, Any]
		message = ""

		if redundant and action.action_type != ActionType.SUBMIT_REPORT:
			event = "redundant_action"
			last_action_result = {"no_op": True}
			message = "Redundant action detected."
		else:
			last_action_result, event, message = self._dispatch(action)

		self._state.step += 1

		done = action.action_type == ActionType.SUBMIT_REPORT or self._state.step >= self._state.max_steps
		info: dict[str, Any] = {}

		if done:
			score, breakdown = self._grader.grade(self._state)
			score = clamp01(score)
			self._state.score = score
			self._state.done = True
			self._last_breakdown = breakdown

			terminal_reward = self.reward_engine.from_score(
				score=score,
				cumulative_reward=self._state.cumulative_reward,
			)
			self._state.cumulative_reward = terminal_reward.cumulative_reward
			reward = terminal_reward.reward
			info = {"score": score, "breakdown": breakdown}
		else:
			reward_result = self.reward_engine.apply(
				event=event,
				cumulative_reward=self._state.cumulative_reward,
				reason=message or event,
			)
			self._state.cumulative_reward = reward_result.cumulative_reward
			reward = reward_result.reward

		observation = self._build_observation(
			last_action_result=last_action_result,
			message=message,
			reward=reward.value,
			score=info.get("score")
		)
		return observation

	@property
	def state(self) -> State:
		"""Return deep-copy state snapshot for callers and validators."""

		if self._state is None:
			raise RuntimeError("Environment not initialized. Call reset(task_id) first.")
		return self._state.model_copy(deep=True)

	def close(self) -> None:
		"""Optional cleanup hook for compatibility with generic OpenEnv runners."""

		return None

	def _dispatch(self, action: Action) -> tuple[dict[str, Any], str, str]:
		if action.action_type == ActionType.INSPECT_PACKAGE:
			return self._handle_inspect(action)
		if action.action_type == ActionType.CHECK_CVE:
			return self._handle_check_cve(action)
		if action.action_type == ActionType.TRACE_DEPS:
			return self._handle_trace_deps(action)
		if action.action_type == ActionType.FLAG_PACKAGE:
			return self._handle_flag(action)
		if action.action_type == ActionType.UNFLAG_PACKAGE:
			return self._handle_unflag(action)
		if action.action_type == ActionType.GENERATE_SBOM:
			return self._handle_generate_sbom()
		if action.action_type == ActionType.REMEDIATE:
			return self._handle_remediate(action)
		if action.action_type == ActionType.SUBMIT_REPORT:
			result = {
				"submitted": True,
				"report": action.report or {},
			}
			return result, "step_penalty", "Report submitted for grading."
		return {"error": "unknown action"}, "step_penalty", "Unknown action type."

	def _build_observation(
		self,
		last_action_result: dict[str, Any] | None = None,
		message: str = "",
		reward: float = 0.0,
		score: float | None = None,
	) -> Observation:
		assert self._state is not None
		return Observation(
			task_id=self._state.task_id,
			step=self._state.step,
			max_steps=self._state.max_steps,
			requirements=list(self._state.requirements),
			objective=self._state.objective,
			last_action_result=last_action_result,
			flags=list(self._state.flags),
			remediations=list(self._state.remediations),
			sbom=list(self._state.sbom) if self._state.sbom else None,
			message=message,
			done=self._state.done,
			reward=reward,
			score=score,
		)

	def _validate_package_fields(self, action: Action) -> tuple[str | None, str | None, dict[str, Any] | None]:
		if not action.package_name or not action.version:
			return None, None, {"error": "package_name and version are required"}
		return action.package_name, action.version, None

	def _handle_inspect(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "step_penalty", "inspect_package requires package_name and version."

		assert package_name is not None and version is not None
		package_info = self.registry.get_package_info(package_name, version)
		if package_info is None:
			return {"error": "package not found in registry"}, "step_penalty", "Package not found."
		return package_info, "step_penalty", "Package metadata retrieved."

	def _handle_check_cve(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "step_penalty", "check_cve requires package_name and version."

		assert package_name is not None and version is not None
		if not self.registry.package_exists(package_name, version):
			return {"cves": []}, "step_penalty", "Package not found; returning empty CVE list."

		cves = self.registry.get_cves(package_name, version)
		return {"cves": cves}, "step_penalty", f"Found {len(cves)} CVE record(s)."

	def _flatten_tree_nodes(self, node: dict[str, Any]) -> set[tuple[str, str]]:
		nodes: set[tuple[str, str]] = {(node["package"], node["version"])}
		for child in node.get("children", []):
			nodes.update(self._flatten_tree_nodes(child))
		return nodes

	def _handle_trace_deps(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "step_penalty", "trace_deps requires package_name and version."

		assert package_name is not None and version is not None
		if not self.registry.package_exists(package_name, version):
			return {"error": "package not found in registry"}, "step_penalty", "Package not found."

		depth = max(1, min(action.depth, 5))
		tree = self.registry.build_dependency_tree(package_name, version, depth=depth)

		traced_nodes = self._flatten_tree_nodes(tree)
		previous_nodes = set(self._seen_trace_nodes)
		self._seen_trace_nodes.update(traced_nodes)
		new_nodes = len(self._seen_trace_nodes - previous_nodes)

		event = "transitive_dep_traced" if new_nodes > 1 else "step_penalty"
		message = f"Dependency tree traced to depth {depth}; discovered {new_nodes} new node(s)."
		return tree, event, message

	def _handle_flag(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "step_penalty", "flag_package requires package_name and version."

		assert package_name is not None and version is not None
		reason = action.reason or "risk identified"

		already_flagged = any(
			entry.package_name == package_name and entry.version == version for entry in self._state.flags
		)
		if already_flagged:
			return {
				"flagged": False,
				"package": package_name,
				"version": version,
				"reason": "already flagged",
			}, "redundant_action", "Package already flagged; no-op."

		self._state.flags.append(
			FlagEntry(
				package_name=package_name,
				version=version,
				reason=reason,
			)
		)

		if self.registry.is_typosquat(package_name):
			event = "typosquat_detected"
			message = "Typosquatted package flagged."
		elif self.registry.get_cves(package_name, version):
			event = "correct_cve_flagged"
			message = "Vulnerable package flagged."
		else:
			event = "false_positive_flag"
			message = "Package flagged but no known CVE/typosquat match."

		return {
			"flagged": True,
			"package": package_name,
			"version": version,
			"reason": reason,
		}, event, message

	def _handle_unflag(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "step_penalty", "unflag_package requires package_name and version."

		assert package_name is not None and version is not None
		original_len = len(self._state.flags)
		self._state.flags = [
			entry
			for entry in self._state.flags
			if not (entry.package_name == package_name and entry.version == version)
		]
		removed = len(self._state.flags) != original_len
		return {
			"unflagged": removed,
			"package": package_name,
			"version": version,
		}, "step_penalty", "Flag removed." if removed else "No matching flag found."

	def _collect_sbom(self) -> list[dict[str, str]]:
		seeds: set[tuple[str, str]] = set()
		for spec in self._state.requirements:
			seeds.add(self.registry.parse_spec(spec))

		for flag in self._state.flags:
			seeds.add((flag.package_name, flag.version))

		for remediation in self._state.remediations:
			seeds.add((remediation.package_name, remediation.from_version))
			seeds.add((remediation.package_name, remediation.to_version))

		sbom_pairs: set[tuple[str, str]] = set()
		for package_name, version in seeds:
			sbom_pairs.update(self.registry.collect_closure(package_name, version, depth=5))

		return [
			{"package_name": package_name, "version": version}
			for package_name, version in sorted(sbom_pairs)
		]

	def _handle_generate_sbom(self) -> tuple[dict[str, Any], str, str]:
		sbom = self._collect_sbom()
		self._state.sbom = sbom
		return {
			"count": len(sbom),
			"sbom": sbom,
		}, "sbom_generated", "SBOM generated from direct and transitive dependencies."

	def _handle_remediate(self, action: Action) -> tuple[dict[str, Any], str, str]:
		package_name, version, error = self._validate_package_fields(action)
		if error is not None:
			return error, "invalid_remediation", "remediate requires package_name and version."

		if not action.target_version:
			return {
				"valid": False,
				"message": "target_version is required",
			}, "invalid_remediation", "target_version missing."

		assert package_name is not None and version is not None
		target_version = action.target_version

		if not self.registry.package_exists(package_name, version):
			return {
				"valid": False,
				"message": "source package version not in registry",
			}, "invalid_remediation", "Source package/version not found."

		if not self.registry.package_exists(package_name, target_version):
			return {
				"valid": False,
				"message": "version not in registry",
			}, "invalid_remediation", "Target version not found in registry."

		self._state.remediations = [
			entry for entry in self._state.remediations if entry.package_name != package_name
		]
		self._state.remediations.append(
			RemediationEntry(
				package_name=package_name,
				from_version=version,
				to_version=target_version,
			)
		)

		return {
			"valid": True,
			"message": "remediation accepted",
			"package": package_name,
			"from_version": version,
			"to_version": target_version,
		}, "valid_remediation", "Remediation accepted."
