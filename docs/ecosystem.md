# Ecosystem

Pico-Auth is built on the Pico framework stack:

| Package | Role in Pico-Auth |
|---------|-------------------|
| [pico-ioc](https://github.com/dperezcabrera/pico-ioc) | Dependency injection (`@component`, `@configured`) |
| [pico-boot](https://github.com/dperezcabrera/pico-boot) | Bootstrap and plugin discovery |
| [pico-fastapi](https://github.com/dperezcabrera/pico-fastapi) | FastAPI integration (`@controller`, `@get`, `@post`) |
| [pico-sqlalchemy](https://github.com/dperezcabrera/pico-sqlalchemy) | Async SQLAlchemy (`SessionManager`, `AppBase`) |

## Related Projects

| Package | Description |
|---------|-------------|
| [pico-celery](https://github.com/dperezcabrera/pico-celery) | Celery task queue integration |
| [pico-pydantic](https://github.com/dperezcabrera/pico-pydantic) | Pydantic validation integration |
| [pico-agent](https://github.com/dperezcabrera/pico-agent) | LLM agent framework |
| [pico-skills](https://github.com/dperezcabrera/pico-skills) | AI coding skills for Claude Code and Codex |
