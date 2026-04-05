"""Fixture-backed registry and lookup helpers for package intelligence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PackageRegistry:
	"""In-memory registry loaded from static fixture files."""

	def __init__(self, fixtures_dir: str | Path | None = None) -> None:
		if fixtures_dir is None:
			fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures"
		self.fixtures_dir = Path(fixtures_dir)

		self.packages: dict[str, dict[str, dict[str, Any]]] = self._load_json("packages.json")
		self.cve_db: dict[str, list[dict[str, Any]]] = self._load_json("cve_db.json")
		self.dep_graph: dict[str, dict[str, Any]] = self._load_json("dep_graph.json")
		self.typosquat_db: dict[str, dict[str, str]] = self._load_json("typosquat_db.json")

	def _load_json(self, filename: str) -> Any:
		path = self.fixtures_dir / filename
		with path.open("r", encoding="utf-8") as handle:
			return json.load(handle)

	@staticmethod
	def parse_spec(spec: str) -> tuple[str, str]:
		"""Parse a requirement spec like 'package==1.2.3'."""

		if "==" not in spec:
			raise ValueError(f"Invalid dependency spec: {spec}")
		name, version = spec.split("==", 1)
		return name.strip(), version.strip()

	@staticmethod
	def make_key(package_name: str, version: str) -> str:
		"""Build package-version key used by CVE/graph fixture maps."""

		return f"{package_name}:{version}"

	def package_exists(self, package_name: str, version: str | None = None) -> bool:
		"""Return true when package or package@version exists in registry."""

		package_versions = self.packages.get(package_name)
		if package_versions is None:
			return False
		if version is None:
			return True
		return version in package_versions

	def list_versions(self, package_name: str) -> list[str]:
		"""List known versions for a package."""

		return sorted(self.packages.get(package_name, {}).keys())

	def get_package(self, package_name: str, version: str) -> dict[str, Any] | None:
		"""Fetch raw package metadata for package@version."""

		return self.packages.get(package_name, {}).get(version)

	def get_package_info(self, package_name: str, version: str) -> dict[str, Any] | None:
		"""Fetch normalized package metadata payload."""

		data = self.get_package(package_name, version)
		if data is None:
			return None
		return {
			"name": package_name,
			"version": version,
			"description": data.get("description", ""),
			"author": data.get("author", ""),
			"license": data.get("license", ""),
			"published_at": data.get("published_at", ""),
			"direct_deps": list(data.get("direct_deps", [])),
		}

	def get_direct_deps(self, package_name: str, version: str) -> list[str]:
		"""Fetch direct dependency specs for package@version."""

		package = self.get_package(package_name, version)
		if package is None:
			return []
		return list(package.get("direct_deps", []))

	def get_cves(self, package_name: str, version: str) -> list[dict[str, Any]]:
		"""Fetch CVE records for package@version."""

		key = self.make_key(package_name, version)
		return list(self.cve_db.get(key, []))

	def get_dep_entry(self, package_name: str, version: str) -> dict[str, Any]:
		"""Fetch dependency graph fixture entry for package@version."""

		key = self.make_key(package_name, version)
		if key in self.dep_graph:
			return self.dep_graph[key]
		return {"direct": self.get_direct_deps(package_name, version), "transitive": {}}

	def is_typosquat(self, package_name: str) -> bool:
		"""Return true when package appears in typosquat fixture list."""

		return package_name in self.typosquat_db

	def get_typosquat_info(self, package_name: str) -> dict[str, str] | None:
		"""Fetch typosquat metadata if present."""

		return self.typosquat_db.get(package_name)

	def build_dependency_tree(
		self,
		package_name: str,
		version: str,
		depth: int = 1,
		_visited: set[tuple[str, str]] | None = None,
		_current_depth: int = 0,
	) -> dict[str, Any]:
		"""Build recursive dependency tree up to a depth limit."""

		if _visited is None:
			_visited = set()

		depth = max(1, min(depth, 5))
		node = {
			"package": package_name,
			"version": version,
			"depth": _current_depth,
			"children": [],
		}

		if _current_depth >= depth:
			return node

		marker = (package_name, version)
		if marker in _visited:
			return node

		next_visited = set(_visited)
		next_visited.add(marker)

		for dep_spec in self.get_direct_deps(package_name, version):
			dep_name, dep_version = self.parse_spec(dep_spec)
			child = self.build_dependency_tree(
				dep_name,
				dep_version,
				depth=depth,
				_visited=next_visited,
				_current_depth=_current_depth + 1,
			)
			node["children"].append(child)

		return node

	def collect_closure(self, package_name: str, version: str, depth: int = 5) -> set[tuple[str, str]]:
		"""Collect dependency closure up to depth limit."""

		depth = max(1, min(depth, 5))
		seen: set[tuple[str, str]] = set()
		queue: list[tuple[str, str, int]] = [(package_name, version, 0)]

		while queue:
			current_name, current_version, current_depth = queue.pop(0)
			marker = (current_name, current_version)
			if marker in seen:
				continue

			seen.add(marker)
			if current_depth >= depth:
				continue

			for dep_spec in self.get_direct_deps(current_name, current_version):
				dep_name, dep_version = self.parse_spec(dep_spec)
				queue.append((dep_name, dep_version, current_depth + 1))

		return seen
