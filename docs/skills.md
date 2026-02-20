# AI Coding Skills

Pico-Auth integrates with [pico-skills](https://github.com/dperezcabrera/pico-skills) to provide AI-assisted development.

## Available Skills

| Skill | Description |
|-------|-------------|
| `add-component` | Add a new pico-ioc component with dependency injection |
| `add-controller` | Add a FastAPI controller with pico-fastapi |
| `add-repository` | Add a SQLAlchemy entity and repository |
| `add-tests` | Generate tests for pico-framework components |
| `add-auth` | Add JWT authentication to a pico-fastapi application |

## Using Skills

Skills are invoked via the `/skill-name` command in Claude Code or Codex:

```
/add-controller   # Add a new API endpoint
/add-repository   # Add a new database entity
/add-tests        # Generate test coverage
```

## Project Conventions

Pico-Auth follows the conventions defined in `AGENTS.md`:

- **Flat package layout**: `pico_auth/` (not `src/pico_auth/`)
- **Async-first**: All repository and service methods are async
- **Error responses**: `{"error": "message"}` in JSON body, not HTTP status codes
- **Clean separation**: config -> models -> repository -> service -> routes
- **Testing**: E2E via httpx `AsyncClient` with ASGI transport
