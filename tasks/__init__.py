"""Task exports and lookup helpers."""

from tasks.base import BaseTask
from tasks.task_easy import TASK_EASY
from tasks.task_hard import TASK_HARD
from tasks.task_medium import TASK_MEDIUM


TASKS: dict[str, BaseTask] = {
	TASK_EASY.task_id: TASK_EASY,
	TASK_MEDIUM.task_id: TASK_MEDIUM,
	TASK_HARD.task_id: TASK_HARD,
}


def get_task(task_id: str) -> BaseTask:
	"""Return a task by id or raise ValueError for unknown task ids."""

	if task_id not in TASKS:
		raise ValueError(f"Unknown task id: {task_id}")
	return TASKS[task_id]


def list_tasks() -> list[BaseTask]:
	"""Return all registered task definitions."""

	return list(TASKS.values())
