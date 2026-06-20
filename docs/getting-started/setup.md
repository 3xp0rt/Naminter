# Setup

Install, update, verify, and uninstall Naminter.

## Installing

### PyPI

Install Naminter with pip or uv tool.

#### pip

Use a [venv](https://docs.python.org/3/library/venv.html) so Naminter and its dependencies stay isolated from system Python:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install naminter
```

With the venv active, `naminter` is on your `PATH` (via `.venv/bin`).

#### uv tool

Persistent CLI on your PATH:

```bash
uv tool install naminter
```

#### Optional Dependencies

A plain install (`pip install naminter` or `uv tool install naminter`) already includes both core and CLI dependencies — no `[cli]` extra is needed.

The `dev` extra adds development, testing, and documentation tools:

**pip** — create a venv first if you have not already (see [pip](#pip) above):

```bash
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install "naminter[dev]"
```

The `core` and `cli` groups in `pyproject.toml` document dependency subsets; see [Dependencies](#dependencies).

### Source

Clone the repository and install in editable mode.

#### pip

Use a venv if you have not already (see [pip](#pip) above):

```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### Docker

#### Prebuilt image

Run the published image from GitHub Container Registry:

```bash
docker run --rm -it ghcr.io/3xp0rt/naminter --username john_doe
```

#### Local build

Clone the repository, build the image, and run with Docker Compose. All needed folders are mounted on the first start of the `docker compose run` command.

```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
docker build -t naminter .
docker compose run --rm naminter --username john_doe
```

## Updating

Use the same method you installed with.

### PyPI

#### pip

```bash
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade naminter
```

For optional dependency groups, pass the extra on upgrade:

```bash
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade "naminter[dev]"
```

#### uv tool

```bash
uv tool upgrade naminter
```

For optional dependency groups:

```bash
uv tool upgrade "naminter[dev]"
```

### Source

#### pip

```bash
cd naminter
git pull
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### Docker

#### Prebuilt image

```bash
docker pull ghcr.io/3xp0rt/naminter
```

#### Local build

Rebuild the image after pulling source changes:

```bash
cd naminter
git pull
docker build -t naminter .
```

## Verifying

After installing or updating, confirm Naminter is working.

For pip, uv tool, and source installs:

```bash
naminter --version
```

For the prebuilt Docker image:

```bash
docker run --rm ghcr.io/3xp0rt/naminter --version
```

You should see the version number displayed. If you encounter any issues, ensure that:

1. Python 3.11+ is installed: `python --version`
2. The installation or upgrade completed without errors
3. Your venv is activated, or your PATH includes the Python scripts directory

## Uninstalling

Use the same method you installed with.

### PyPI

#### pip

```bash
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip uninstall naminter
```

If you created a venv only for Naminter, remove it after uninstalling:

```bash
deactivate
rm -rf .venv
```

#### uv tool

```bash
uv tool uninstall naminter
```

### Source

#### pip

```bash
cd naminter
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip uninstall naminter
```

Remove the clone when you no longer need it:

```bash
cd ..
rm -rf naminter
```

### Docker

#### Prebuilt image

```bash
docker rmi ghcr.io/3xp0rt/naminter
```

#### Local build

```bash
docker rmi naminter
```

Confirm removal:

- **pip, uv tool, and source:** `naminter --version` should report that the command was not found
- **Docker:** `docker images` should no longer list the Naminter image

## Dependencies

- Python 3.11 or higher

A default install includes all core and CLI dependencies below.

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
