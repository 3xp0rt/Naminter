# Contributing

Contributions are always welcome! Please submit a pull request with your improvements or open an issue to discuss.

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
```

2. Install in editable mode with dev dependencies:

    ```bash
    uv sync --extra dev
    ```

    Alternatively, using `uv pip`:

    ```bash
    uv pip install -e ".[dev]"
    ```

3. Run linting:
```bash
uv run ruff format
uv run ruff check
```

## Code Style

This project uses:

- **Ruff** for linting and formatting
- **Google-style** docstrings
- **Type hints** for all function signatures

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the code style guidelines
4. Run linting and ensure all checks pass
5. Commit your changes with clear, descriptive messages
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a pull request with a detailed description of your changes

## Pull Request Guidelines

- Provide a clear description of what the PR does
- Reference any related issues
- Ensure code follows the project's style guidelines
- Update documentation if needed

