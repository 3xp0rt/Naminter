# Contributing

Contributions are always welcome! Please submit a pull request with your improvements or open an issue to discuss.

## Development

1. Clone the repository:
```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
```

2. Install in editable mode with dev dependencies:

    ```bash
    uv sync --extra dev
    ```

    `pyproject.toml` sets a **30-day dependency cooldown** (`[tool.uv] exclude-newer`) so
    resolution ignores PyPI uploads from the last month.

3. Before pushing, run the same checks as [CI](https://github.com/3xp0rt/naminter/blob/main/.github/workflows/ci.yml):

    ```bash
    uv run ruff format
    uv run ruff check
    uv run pytest
    ```

    Optional — run Ruff on staged files at commit time: `uv run pre-commit install`
    (uses the same project Ruff as above; does not run pytest).

    Coverage must stay at **90% or above** on `naminter` (see `pyproject.toml`).
    Prioritize tests for public behavior: CLI commands, `Naminter` enumeration flows,
    validation of real datasets, and network error handling. You do not need tests for
    every defensive branch in the validator.

    Boilerplate (`TYPE_CHECKING`, `if __name__ == "__main__"`, abstract methods, and
    similar) is excluded via `exclude_also` in `[tool.coverage.report]`. Avoid
    `# pragma: no cover` unless you have a rare script-style entry point.

## Documentation

This project uses [MkDocs](https://www.mkdocs.org/) with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) for documentation.

### Serving docs locally

To preview documentation changes locally:

```bash
uv run mkdocs serve
```

This starts a local server at `http://127.0.0.1:8000/` with live reload.

### Building docs

To build the static documentation site:

```bash
uv run mkdocs build
```

The built site will be in the `site/` directory.

### Documentation structure

- `docs/` - Documentation source files (Markdown)
- `mkdocs.yml` - MkDocs configuration
- API documentation is auto-generated from docstrings using `mkdocstrings`

## Code Style

- **Google-style** docstrings
- **Type hints** for all function signatures

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the code style guidelines
4. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format
5. Push to your fork (`git push origin feature/amazing-feature`)
6. Open a pull request with a detailed description of your changes

## Commit Message Guidelines

This project follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification. Each commit message should be structured as follows:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Commit Types

| Type | Description |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation only changes |
| `style` | Changes that do not affect the meaning of the code (formatting, etc.) |
| `refactor` | A code change that neither fixes a bug nor adds a feature |
| `perf` | A code change that improves performance |
| `test` | Adding missing tests or correcting existing tests |
| `build` | Changes that affect the build system or external dependencies |
| `ci` | Changes to CI configuration files and scripts |
| `chore` | Other changes that don't modify src or test files |

### Examples

```bash
feat: add validation support
fix: resolve timeout issue in network requests
docs: update installation instructions
refactor(core): simplify validation logic
chore(release): bump version to 1.0.7
```

## Pull Request Guidelines

- Provide a clear description of what the PR does
- Reference any related issues
- Update documentation if needed

