"""Typed models for Supply Chain Auditor OpenEnv environment."""

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field
from openenv.core.env_server.types import Action as OpenEnvAction
from openenv.core.env_server.types import Observation as OpenEnvObservation
from openenv.core.env_server.types import State as OpenEnvState


class ActionType(str, Enum):
	"""Supported action types emitted by the agent."""

	INSPECT_PACKAGE = "inspect_package"
	CHECK_CVE = "check_cve"
	TRACE_DEPS = "trace_deps"
	FLAG_PACKAGE = "flag_package"
	UNFLAG_PACKAGE = "unflag_package"
	GENERATE_SBOM = "generate_sbom"
	REMEDIATE = "remediate"
	SUBMIT_REPORT = "submit_report"


class Action(OpenEnvAction):
	"""Agent action payload."""

	action_type: ActionType
	package_name: Optional[str] = None
	version: Optional[str] = None
	depth: int = Field(default=1, ge=1, le=5)
	reason: Optional[str] = None
	target_version: Optional[str] = None
	report: Optional[dict[str, Any]] = None


class PackageInfo(BaseModel):
	"""Package metadata returned for inspect actions."""

	name: str
	version: str
	description: str
	author: str
	license: str
	published_at: str
	direct_deps: list[str]


class CVERecord(BaseModel):
	"""Structured CVE record."""

	cve_id: str
	severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
	cvss_score: float
	description: str
	affected_versions: list[str]
	fixed_in: Optional[str] = None


class DependencyNode(BaseModel):
	"""Recursive dependency tree node."""

	package: str
	version: str
	depth: int
	children: list["DependencyNode"] = Field(default_factory=list)


class FlagEntry(BaseModel):
	"""Marked risky package in current episode."""

	package_name: str
	version: str
	reason: str


class RemediationEntry(BaseModel):
	"""Proposed package upgrade entry."""

	package_name: str
	from_version: str
	to_version: str


class Observation(OpenEnvObservation):
	"""Observation returned each step."""

	task_id: str
	step: int
	max_steps: int
	requirements: list[str]
	objective: str
	last_action_result: Optional[dict[str, Any]] = None
	flags: list[FlagEntry] = Field(default_factory=list)
	remediations: list[RemediationEntry] = Field(default_factory=list)
	sbom: Optional[list[dict[str, str]]] = None
	message: str = ""
	# reward and done are inherited from OpenEnvObservation
	score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class Reward(BaseModel):
	"""Step reward bounded to [-1.0, 1.0] per hackathon constraints."""

	value: float = Field(ge=-1.0, le=1.0)
	reason: str


class State(OpenEnvState):
	"""Internal mutable environment snapshot."""

	task_id: str
	step: int
	max_steps: int
	requirements: list[str]
	objective: str
	flags: list[FlagEntry]
	remediations: list[RemediationEntry]
	sbom: Optional[list[dict[str, str]]] = None
	cumulative_reward: float = Field(ge=0.0, le=1.0)
	done: bool = False
	score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


DependencyNode.model_rebuild()
