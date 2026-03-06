# Contributing to Pico-Auth

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v                          # Unit and integration tests
tox                                       # Full matrix (3.11-3.14)
pytest tests/test_docker_e2e.py -m docker -v  # Docker E2E tests
```

Docker E2E tests require Docker and the `pico-client-auth` sibling directory. They are excluded from the default suite — use `-m docker` to run them.

## Code Style

- Python 3.11+
- Format with `ruff format pico_auth/ tests/`
- Lint with `ruff check pico_auth/ tests/`

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Ensure tests pass and code is formatted
4. Submit a PR with a clear description

## Reporting Issues

Use [GitHub Issues](https://github.com/dperezcabrera/pico-auth/issues) for bugs and feature requests.
