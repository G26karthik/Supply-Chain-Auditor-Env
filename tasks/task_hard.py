"""Hard task: full SBOM and remediation planning."""

from tasks.base import BaseTask


TASK_HARD = BaseTask(
	task_id="full_sbom_remediation",
	name="Full SBOM + Remediation Plan",
	difficulty="hard",
	max_steps=100,
	objective=(
		"Perform a full supply chain audit of this monorepo. Generate a complete SBOM, "
		"identify all CVEs (direct and transitive), then produce a minimal remediation "
		"plan that eliminates all CRITICAL and HIGH severity issues. Submit your report "
		"when complete."
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
		"requets==1.0.0",
		"urllib4==1.0.0",
		"pandas==1.5.0",
		"fastapi==0.104.0",
		"uvicorn==0.24.0",
		"starlette==0.27.0",
		"httpx==0.24.1",
		"aiohttp==3.8.1",
		"cryptography==3.4.8",
		"botocore==1.29.0",
		"pip==22.0.0",
		"wheel==0.38.4",
		"requests-toolbelt==0.10.1",
		"jinja2==3.0.3",
		"werkzeug==2.3.0",
		"markupsafe==2.0.0",
		"itsdangerous==2.1.2",
		"charset-normalizer==2.0.12",
	],
	gold={
		"critical_high_targets": {
			"pillow": "10.0.0",
			"paramiko": "3.4.0",
			"markupsafe": "2.1.3",
			"cryptography": "41.0.6",
			"pip": "23.3.1",
		},
		"minimum_upgrades": 5,
	},
)
