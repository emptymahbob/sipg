.PHONY: help install install-dev test lint format clean build publish

help: ## Show this help message
	@echo "SIPG - Shodan IP Grabber"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install SIPG in development mode
	pip install -e .

install-dev: ## Install SIPG with development dependencies
	pip install -e ".[dev]"

test: ## Run tests
	pytest tests/ -v

lint: ## Run linting checks
	flake8 sipg/ tests/
	mypy sipg/

format: ## Format code with black
	black sipg/ tests/

clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build: clean ## Build package
	python setup.py sdist bdist_wheel

publish: build ## Build and publish to PyPI
	twine upload dist/*

check: format lint test ## Run all checks (format, lint, test)

dev-setup: install-dev ## Set up development environment
	pre-commit install 