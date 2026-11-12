.PHONY: test format build

test:
	ruff check tutor2fa tests
	ruff format --check tutor2fa tests
	pytest -q

format:
	ruff check --fix tutor2fa tests
	ruff format tutor2fa tests

build:
	python -m build
	twine check dist/*
