import asyncio
import json
import webbrowser
from pathlib import Path
from typing import Any

import aiofiles

from naminter.cli.constants import (
    MAX_FILENAME_LENGTH,
    RESPONSE_FILE_DATE_FORMAT,
    RESPONSE_FILE_EXTENSION,
)
from naminter.cli.exceptions import BrowserError, ConfigurationError, FileIOError
from naminter.core.constants import (
    DEFAULT_FILE_ENCODING,
    EMPTY_STRING,
)
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
    HttpTimeoutError,
    WMNDataError,
)
from naminter.core.models import WMNResult
from naminter.core.network import BaseSession


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for cross-platform compatibility."""
    if not filename or not str(filename).strip():
        return "unnamed"

    invalid_chars = '<>:"|?*\\/\0'
    sanitized = EMPTY_STRING.join(
        "_" if c in invalid_chars or ord(c) < 32 else c for c in str(filename)
    )
    sanitized = (
        sanitized.strip(" .")[:MAX_FILENAME_LENGTH]
        if sanitized.strip(" .")
        else "unnamed"
    )
    return sanitized


async def fetch_json(http_client: BaseSession, url: str) -> dict[str, Any]:
    """Fetch and parse JSON from a URL."""
    if not url or not url.strip():
        msg = f"Invalid URL: {url}"
        raise ConfigurationError(msg)

    try:
        response = await http_client.get(url)
    except (HttpError, HttpTimeoutError, HttpSessionError):
        raise
    except Exception as e:
        msg = f"Network error while fetching from {url}: {e}"
        raise HttpError(msg, cause=e) from e

    if response.status_code != 200:
        msg = f"Failed to fetch from {url}: HTTP {response.status_code}"
        raise HttpError(msg)

    try:
        return response.json()
    except (ValueError, json.JSONDecodeError) as e:
        msg = f"Failed to parse JSON from {url}: {e}"
        raise WMNDataError(msg, cause=e) from e
    except Exception as e:
        msg = f"Unexpected error parsing response from {url}: {e}"
        raise WMNDataError(msg, cause=e) from e


async def read_json(path: str | Path) -> dict[str, Any]:
    """Read JSON from a local file without blocking the event loop."""
    try:
        async with aiofiles.open(path, encoding=DEFAULT_FILE_ENCODING) as file:
            content = await file.read()
    except FileNotFoundError as e:
        msg = f"File not found: {path}"
        raise FileIOError(msg) from e
    except PermissionError as e:
        msg = f"Permission denied accessing file: {path}"
        raise FileIOError(msg) from e
    except UnicodeDecodeError as e:
        msg = f"Encoding error reading file {path}: {e}"
        raise FileIOError(msg) from e
    except OSError as e:
        msg = f"Error reading file {path}: {e}"
        raise FileIOError(msg) from e

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        msg = f"Invalid JSON in file {path}: {e}"
        raise WMNDataError(msg, cause=e) from e


async def open_browser(url: str) -> None:
    """Open a URL in the browser with error handling."""
    if not url or not url.strip():
        msg = "Invalid URL provided to browser"
        raise BrowserError(msg)

    try:
        await asyncio.to_thread(webbrowser.open, url)
    except webbrowser.Error as e:
        msg = f"Browser error opening {url}: {e}"
        raise BrowserError(msg) from e
    except OSError as e:
        msg = f"OS error opening browser for {url}: {e}"
        raise BrowserError(msg) from e
    except Exception as e:
        msg = f"Unexpected error opening browser for {url}: {e}"
        raise BrowserError(msg) from e


async def write_file(file_path: Path, content: str) -> None:
    """Write content to a file with error handling."""
    try:
        async with aiofiles.open(
            file_path, mode="w", encoding=DEFAULT_FILE_ENCODING
        ) as file:
            await file.write(content)
    except PermissionError as e:
        msg = f"Permission denied writing to {file_path}: {e}"
        raise FileIOError(msg) from e
    except OSError as e:
        msg = f"OS error writing to {file_path}: {e}"
        raise FileIOError(msg) from e
    except Exception as e:
        msg = f"Unexpected error writing to {file_path}: {e}"
        raise FileIOError(msg) from e


def generate_response_filename(result: WMNResult) -> str:
    """Generate a sanitized filename for saving response data."""
    safe_site_name = sanitize_filename(result.name)
    safe_username = sanitize_filename(result.username)
    status_str = result.status.value
    created_at_str = result.created_at.strftime(RESPONSE_FILE_DATE_FORMAT)

    return (
        f"{status_str}_{result.response_code}_"
        f"{safe_site_name}_{safe_username}_{created_at_str}"
        f"{RESPONSE_FILE_EXTENSION}"
    )
