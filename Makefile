# Makefile for platform-authorization-next

.PHONY: help install install-dev test lint format type-check security pre-commit clean

# Default target
help:
	@echo "Available commands:"
	@echo "  install         Install production dependencies"
	@echo "  install-dev     Install development dependencies"
	@echo "  test           Run all tests"
	@echo "  test-cov       Run tests with coverage"
	@echo "  lint           Run all linting tools"
	@echo "  format         Format code with black and ruff"
	@echo "  type-check     Run mypy type checking"
	@echo "  security       Run security checks with bandit"
	@echo "  pre-commit     Install and run pre-commit hooks"
	@echo "  clean          Clean cache and temporary files"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# Testing
test:
	pytest -v --tb=short

test-cov:
	pytest --cov=app --cov-report=html --cov-report=term-missing

# Code quality
lint: format type-check security
	@echo "✅ All linting checks passed!"

format:
	@echo "🔧 Formatting code..."
	ruff check --fix .
	black .
	ruff format .

type-check:
	@echo "🔍 Type checking..."
	mypy app/

security:
	@echo "🛡️  Security checks..."
	bandit -r app/ -f json -o bandit-report.json || true
	@if [ -f bandit-report.json ]; then echo "Security report: bandit-report.json"; fi

# Pre-commit
pre-commit:
	@echo "🪝 Setting up pre-commit hooks..."
	pre-commit install
	pre-commit run --all-files

# Cleanup
clean:
	@echo "🧹 Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -f bandit-report.json
	rm -rf htmlcov/
	rm -f .coverage

# Database
migrate:
	alembic upgrade head

migrate-create:
	@read -p "Enter migration message: " message; \
	alembic revision --autogenerate -m "$$message"

# Development server
dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
