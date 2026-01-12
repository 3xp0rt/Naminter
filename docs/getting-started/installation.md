# Installation

## From PyPI

Install Naminter with pip or uv:

```bash
# Using pip
pip install naminter

# Using uv
uv tool install naminter
```

## From Source

Clone the repository and install in editable mode:

```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
pip install -e .

# Or with uv
uv pip install -e .
```

For development with dev dependencies:

```bash
uv sync --extra dev
```

## Using Docker

All needed folders are mounted on the first start of the docker compose run command.

```bash
# Using the prebuilt docker image from the GitHub registry
docker run --rm -it ghcr.io/3xp0rt/naminter --username john_doe

# Build the docker from the source yourself
git clone https://github.com/3xp0rt/naminter.git && cd naminter
docker build -t naminter .
docker compose run --rm naminter --username john_doe
```

## Requirements

- Python 3.11 or higher
- See `pyproject.toml` for full dependency list

## Verification

After installation, verify that Naminter is correctly installed:

```bash
naminter --version
```

You should see the version number displayed. If you encounter any issues, ensure that:

1. Python 3.11+ is installed: `python --version`
2. The installation completed without errors
3. Your PATH includes the Python scripts directory

