"""Deterministic grader for hard task."""

from __future__ import annotations

from typing import Any

from env.models import State
from env.registry import PackageRegistry
from tasks.task_hard import TASK_HARD


def _clamp01(value: float) -> float:
	return max(0.0, min(1.0, value))


class HardGrader:
	"""Grades coverage, SBOM quality, remediations, and upgrade parsimony."""

	def __init__(self, registry: PackageRegistry | None = None) -> None:
		self.registry = registry or PackageRegistry()
		self.minimum_upgrades = int(TASK_HARD.gold.get("minimum_upgrades", 1))
		self.gold_closure = self._compute_gold_closure()
		self.gold_cve_pairs = self._compute_gold_cve_pairs()
		self.required_critical_high_targets = self._compute_required_targets()

	def _compute_gold_closure(self) -> set[tuple[str, str]]:
		closure: set[tuple[str, str]] = set()
		for spec in TASK_HARD.requirements:
			name, version = self.registry.parse_spec(spec)
			closure.update(self.registry.collect_closure(name, version, depth=5))
		return closure

	def _compute_gold_cve_pairs(self) -> set[tuple[str, str]]:
		pairs: set[tuple[str, str]] = set()
		for package_name, version in self.gold_closure:
			if self.registry.get_cves(package_name, version):
				pairs.add((package_name, version))
		return pairs

	def _compute_required_targets(self) -> dict[str, set[str]]:
		targets: dict[str, set[str]] = {}
		for package_name, version in self.gold_cve_pairs:
			cves = self.registry.get_cves(package_name, version)
			for cve in cves:
				if cve.get("severity") not in {"CRITICAL", "HIGH"}:
					continue
				fixed_in = cve.get("fixed_in")
				if not fixed_in:
					continue
				targets.setdefault(package_name, set()).add(fixed_in)
		return targets

	@staticmethod
	def _extract_sbom_pairs(sbom: list[dict[str, Any]] | None) -> set[tuple[str, str]]:
		if not sbom:
			return set()
		parsed: set[tuple[str, str]] = set()
		for item in sbom:
			package_name = item.get("package_name") or item.get("package")
			version = item.get("version")
			if package_name and version:
				parsed.add((str(package_name), str(version)))
		return parsed

	def grade(self, state: State) -> tuple[float, dict[str, Any]]:
		flagged_pairs = {(flag.package_name, flag.version) for flag in state.flags}
		found_pairs = flagged_pairs.intersection(self.gold_cve_pairs)
		false_positives = len(flagged_pairs - self.gold_cve_pairs)

		found_count = len(found_pairs)
		precision_denominator = found_count + false_positives
		precision = found_count / precision_denominator if precision_denominator > 0 else 0.0
		recall = found_count / len(self.gold_cve_pairs) if self.gold_cve_pairs else 0.0
		cve_f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
		cve_coverage = _clamp01(cve_f1)

		sbom_pairs = self._extract_sbom_pairs(state.sbom)
		sbom_intersection = sbom_pairs.intersection(self.gold_closure)
		sbom_completeness = _clamp01(
			len(sbom_intersection) / len(self.gold_closure) if self.gold_closure else 0.0
		)

		required_packages = set(self.required_critical_high_targets.keys())
		covered_packages: set[str] = set()
		valid_entries = 0
		invalid_entries = 0
		for remediation in state.remediations:
			package_name = remediation.package_name
			target_version = remediation.to_version
			allowed_versions = self.required_critical_high_targets.get(package_name, set())
			exists = self.registry.package_exists(package_name, target_version)

			if exists and target_version in allowed_versions:
				valid_entries += 1
				covered_packages.add(package_name)
			else:
				invalid_entries += 1

		coverage = len(covered_packages) / len(required_packages) if required_packages else 1.0
		total_remediations = valid_entries + invalid_entries
		quality = valid_entries / total_remediations if total_remediations > 0 else 0.0
		remediation_validity = _clamp01(0.7 * coverage + 0.3 * quality)

		actual_upgrades = len({entry.package_name for entry in state.remediations})
		if actual_upgrades <= self.minimum_upgrades:
			parsimony = 1.0
		else:
			extra_upgrades = actual_upgrades - self.minimum_upgrades
			parsimony = _clamp01(1.0 - (0.2 * extra_upgrades))

		score = _clamp01(
			0.35 * cve_coverage
			+ 0.20 * sbom_completeness
			+ 0.30 * remediation_validity
			+ 0.15 * parsimony
		)

		breakdown = {
			"cve_coverage": cve_coverage,
			"sbom_completeness": sbom_completeness,
			"remediation_validity": remediation_validity,
			"parsimony": parsimony,
			"found_cves": sorted([f"{n}:{v}" for n, v in found_pairs]),
			"total_gold_cves": len(self.gold_cve_pairs),
			"false_positives": false_positives,
			"required_critical_high_packages": sorted(required_packages),
			"covered_critical_high_packages": sorted(covered_packages),
			"actual_upgrades": actual_upgrades,
			"minimum_upgrades": self.minimum_upgrades,
			"score": score,
		}
		return score, breakdown
