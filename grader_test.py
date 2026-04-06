#!/usr/bin/env python3
"""
Grader sanity check script for hackathon validation.

Runs all 3 graders with:
1. Perfect submission (gold answers) → must return 1.0
2. Empty submission → must return 0.0

This demonstrates deterministic, reproducible grading.
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, ".")

from env.environment import SupplyChainEnv
from env.models import State, FlagEntry, RemediationEntry, ActionType, Action
from graders import get_grader
from tasks import TASK_EASY, TASK_MEDIUM, TASK_HARD


def create_state(task, flags: list, remediations: list, sbom: list | None) -> State:
    """Create a State object for grading."""
    flag_entries = [FlagEntry(**f) for f in flags]
    rem_entries = [RemediationEntry(**r) for r in remediations]
    return State(
        task_id=task.task_id,
        step=task.max_steps,
        max_steps=task.max_steps,
        requirements=task.requirements,
        objective=task.objective,
        flags=flag_entries,
        remediations=rem_entries,
        sbom=sbom,
        cumulative_reward=0.0,
        done=True,
    )


def test_grader(task_id: str, task, env: SupplyChainEnv) -> tuple[bool, bool, float, float]:
    """Test grader with perfect and empty submissions. Returns (perfect_pass, empty_pass, perfect_score, empty_score)."""
    grader = get_grader(task_id, registry=env.registry)

    # Build perfect submission
    perfect_flags = []
    perfect_remediations = []
    perfect_sbom = [{"package_name": pkg.split("==")[0], "version": pkg.split("==")[1]} for pkg in task.requirements]

    if task_id == "flat_audit":
        for pkg_ver in task.gold["cve_pairs"].keys():
            pkg, ver = pkg_ver.split(":")
            perfect_flags.append({"package_name": pkg, "version": ver, "reason": "CVE"})
    elif task_id == "typosquat_transitive":
        for typo in task.gold["typosquats"]:
            perfect_flags.append({"package_name": typo, "version": "1.0.0", "reason": "typosquat"})
        trans = task.gold["transitive_cve"]
        perfect_flags.append({"package_name": trans["package"], "version": trans["version"], "reason": "transitive CVE"})
    elif task_id == "full_sbom_remediation":
        # For hard task, we need:
        # 1. All gold CVE pairs flagged
        # 2. Complete SBOM from gold_closure
        # 3. Exactly the required remediations
        from graders.grader_hard import HardGrader
        hard_grader = HardGrader(env.registry)
        
        # Flag all gold CVE pairs
        for pkg, ver in hard_grader.gold_cve_pairs:
            perfect_flags.append({"package_name": pkg, "version": ver, "reason": "CVE"})
        
        # Build complete SBOM from gold closure
        perfect_sbom = [{"package_name": pkg, "version": ver} for pkg, ver in hard_grader.gold_closure]
        
        # Add exactly the required remediations
        for pkg, target_vers in hard_grader.required_critical_high_targets.items():
            target_ver = list(target_vers)[0]  # Get one valid target
            # Find the vulnerable version from gold_cve_pairs
            for p, v in hard_grader.gold_cve_pairs:
                if p == pkg:
                    perfect_remediations.append({"package_name": pkg, "from_version": v, "to_version": target_ver})
                    break

    perfect_state = create_state(task, perfect_flags, perfect_remediations, perfect_sbom)
    perfect_score, _ = grader.grade(perfect_state)

    empty_state = create_state(task, [], [], None)
    empty_score, _ = grader.grade(empty_state)

    return abs(perfect_score - 1.0) < 0.01, abs(empty_score - 0.0) < 0.01, perfect_score, empty_score


def main() -> None:
    print("=" * 60)
    print("GRADER SANITY CHECK")
    print("=" * 60)

    env = SupplyChainEnv()
    tasks = [
        ("flat_audit", TASK_EASY),
        ("typosquat_transitive", TASK_MEDIUM),
        ("full_sbom_remediation", TASK_HARD),
    ]

    all_pass = True
    for task_id, task in tasks:
        perfect_pass, empty_pass, perfect_score, empty_score = test_grader(task_id, task, env)

        status_perfect = "PASS" if perfect_pass else "FAIL"
        status_empty = "PASS" if empty_pass else "FAIL"

        print(f"\n{task_id}:")
        print(f"  Perfect submission → {perfect_score:.3f} (expect 1.0): {status_perfect}")
        print(f"  Empty submission → {empty_score:.3f} (expect 0.0):   {status_empty}")

        if not perfect_pass or not empty_pass:
            all_pass = False

    print("\n" + "=" * 60)
    if all_pass:
        print("ALL GRADER TESTS PASS")
    else:
        print("SOME GRADER TESTS FAILED")
        sys.exit(1)
    print("=" * 60)


if __name__ == "__main__":
    main()
