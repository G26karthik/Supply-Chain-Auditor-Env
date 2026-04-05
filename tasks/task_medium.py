"""Medium task: typosquatting and transitive CVE audit."""

from tasks.base import BaseTask


TASK_MEDIUM = BaseTask(
	task_id="typosquat_transitive",
	name="Typosquatting + Transitive CVE Detection",
	difficulty="medium",
	max_steps=50,
	objective=(
		"Audit this manifest for typosquatted packages and hidden CVEs in transitive "
		"dependencies. Use TRACE_DEPS to look beyond direct packages. Flag all risks "
		"and submit your report."
	),
	requirements=[
		"requests==2.31.0",
		"requets==1.0.0",
		"flask==2.3.0",
		"urllib4==1.0.0",
		"numpy==1.23.0",
		"pandas==1.5.0",
		"pillow==9.2.0",
		"pydantic==1.10.0",
	],
	gold={
		"typosquats": ["requets", "urllib4"],
		"transitive_cve": {
			"package": "markupsafe",
			"version": "2.0.0",
			"cve_id": "CVE-2024-34064",
		},
	},
)
