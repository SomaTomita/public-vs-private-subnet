.PHONY: fmt lint fmt-check setup

# Install pre-commit and all hooks
setup:
	pip3 install pre-commit
	pre-commit install
	pre-commit install-hooks

# Format everything (auto-fix)
fmt:
	pre-commit run --all-files

# Same as fmt but CI-friendly (fails on diff)
fmt-check:
	pre-commit run --all-files --show-diff-on-failure

# Run only specific formatters
fmt-tf:
	terraform -chdir=terraform fmt
fmt-sh:
	pre-commit run shfmt --all-files
fmt-py:
	pre-commit run ruff-format --all-files
fmt-md:
	pre-commit run markdownlint --all-files

# Lint only (no auto-fix)
lint:
	pre-commit run shellcheck --all-files
	pre-commit run ruff --all-files
