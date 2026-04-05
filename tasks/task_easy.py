"""Easy task: flat dependency CVE audit."""

from tasks.base import BaseTask


TASK_EASY = BaseTask(
	task_id="flat_audit",
	name="Flat Dependency Audit",
	difficulty="easy",
	max_steps=30,
	objective=(
		"Audit this requirements.txt for known CVEs. Flag any vulnerable package "
		"and identify its CVE ID(s). Submit your report when complete."
	),
	requirements=[
		"requests==2.28.0",
		"flask==2.3.0",
		"pillow==9.0.0",
		"sqlalchemy==1.4.41",
		"paramiko==2.11.0",
		"boto3==1.26.0",
		"pydantic==1.10.0",
		"setuptools==65.5.0",
		"numpy==1.23.0",
		"certifi==2022.6.15",
		"urllib3==1.26.12",
		"click==8.1.0",
	],
	gold={
		"cve_pairs": {
			"urllib3:1.26.12": ["CVE-2023-45803"],
			"pillow:9.0.0": ["CVE-2023-44271"],
			"paramiko:2.11.0": ["CVE-2023-48795"],
		}
	},
)
