# Installation

## From PyPI

Install Naminter with pip or uv.

### pip

Use a [venv](https://docs.python.org/3/library/venv.html) so Naminter and its dependencies stay isolated from system Python:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install naminter
```

With the venv active, `naminter` is on your `PATH` (via `.venv/bin`).

### uv

```bash
# Persistent CLI on your PATH (similar to pipx)
uv tool install naminter
```

### Updating

Use the same tool you installed with:

```bash
# pip (with venv active)
pip install --upgrade naminter

# uv tool (persistent install)
uv tool upgrade naminter
```

For optional dependency groups, pass the extra on upgrade (for example,
`pip install --upgrade "naminter[dev]"` or `uv tool upgrade "naminter[dev]"`).

### Optional Dependencies

Naminter supports optional dependency groups:

```bash
# Install core dependencies only (for library usage)
pip install naminter[core]
# or with uv
uv pip install naminter[core]

# Install with CLI dependencies (same as default)
pip install naminter[cli]
# or with uv
uv pip install naminter[cli]

# Install with development dependencies
pip install naminter[dev]
# or with uv
uv pip install naminter[dev]
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

### Core Dependencies

The core module requires:

- `curl-cffi` - HTTP client with browser impersonation
- `jsonschema` - JSON schema validation
- `orjson` - Fast JSON parsing

### CLI Dependencies

The CLI module additionally requires:

- `click` - Command-line interface framework
- `rich` - Rich console output
- `rich-click` - Rich click integration
- `aiofiles` - Async file I/O
- `jinja2` - Template engine (for HTML export)
- `weasyprint` - PDF generation
- `pathvalidate` - Path validation
- `uvloop` - Fast event loop implementation

See `pyproject.toml` for the reference.

## Verification

After installation, verify that Naminter is correctly installed:

```bash
naminter --version
```

You should see the version number displayed. If you encounter any issues, ensure that:

1. Python 3.11+ is installed: `python --version`
2. The installation completed without errors
3. Your venv is activated, or your PATH includes the Python scripts directory

