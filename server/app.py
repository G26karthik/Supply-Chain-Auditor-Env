"""FastAPI server exposing the SupplyChainEnv via openenv standard HTTP server."""

from __future__ import annotations

import uvicorn
from openenv.core.env_server.http_server import create_app

from env.environment import SupplyChainEnv
from env.models import Action, Observation


app = create_app(
	env=SupplyChainEnv,
	action_cls=Action,
	observation_cls=Observation,
	env_name="SupplyChainAuditor",
	max_concurrent_envs=10,
)


def main(host: str = "0.0.0.0", port: int = 7860) -> None:
	"""Run the server process used for local and HF Space deployment."""
	uvicorn.run("server.app:app", host=host, port=port)


if __name__ == "__main__":
	main()
