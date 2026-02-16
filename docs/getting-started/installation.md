# Installation

## From PyPI

Install Naminter with pip or uv:

```bash
# Default installation (includes both CLI and core)
pip install naminter

# Using uv
uvx naminter
```

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
3. Your PATH includes the Python scripts directory

