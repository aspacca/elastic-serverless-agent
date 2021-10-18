.PHONY: help
SHELL := /bin/bash

help: ## Display this help text
	@grep -E '^[a-zA-Z_-]+[%]?:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

lint: black flake8 isort mypy ## Lint the project

test:
	PYTEST_ARGS="${PYTEST_ARGS}" tests/scripts/docker/run_tests.sh

coverage: PYTEST_ARGS=--cov=. --cov-context=test --cov-config=.coveragerc --cov-branch
coverage: export COVERAGE_FILE=.coverage
coverage: test

black:  ## Run black in the project
	tests/scripts/docker/black.sh diff

flake8:  ## Run flake8 in the project
	tests/scripts/docker/flake8.sh

mypy:  ## Run mypy in the project
	tests/scripts/docker/mypy.sh

isort:  ## Run isort in the project
	tests/scripts/docker/isort.sh diff

license:  ## Run license validation in the project
	tests/scripts/license_headers_check.sh check

