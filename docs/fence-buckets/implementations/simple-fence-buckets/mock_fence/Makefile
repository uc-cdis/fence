
.PHONY: lint typecheck pre-commit-install

lint:
	ruff check . --fix
	ruff format .

typecheck:
	mypy mock_fence fence

pre-commit-install:
	pre-commit install
