"""File, network, and browser utility functions for Naminter CLI."""

import asyncio
from pathlib import Path
from typing import Any
import webbrowser

import aiofiles
import orjson
from pathvalidate import sanitize_filename

from naminter.cli.constants import (
    DEFAULT_UNNAMED_VALUE,
    MAX_FILENAME_LENGTH,
    RESPONSE_FILE_DATE_FORMAT,
    RESPONSE_FILE_EXTENSION,
)
from naminter.cli.exceptions import (
    BrowserError,
    FileError,
    NetworkError,
    ValidationError,
)
from naminter.core.constants import DEFAULT_FILE_ENCODING
from naminter.core.exceptions import HttpError
from naminter.core.models import WMNResult
from naminter.core.network import BaseSession


# =============================================================================
# Filename Utilities
# =============================================================================


def get_response_filename(result: WMNResult) -> str:
    """Generate a sanitized filename for saving response data.

    Args:
        result: The WMNResult containing response data.

    Returns:
        str: Sanitized filename in format
            ``{status}_{statuscode}_{site}_{username}_{timestamp}.html``.

    Raises:
        ValidationError: If WMNResult is missing required attributes.
    """
    try:
        safe_site_name = (
            sanitize_filename(
                str(result.name or "").strip(), max_len=MAX_FILENAME_LENGTH
            )
            or DEFAULT_UNNAMED_VALUE
        )
        safe_username = (
            sanitize_filename(
                str(result.username or "").strip(), max_len=MAX_FILENAME_LENGTH
            )
            or DEFAULT_UNNAMED_VALUE
        )
        status_str = result.status.value
        created_at_str = result.created_at.strftime(RESPONSE_FILE_DATE_FORMAT)
        status_code = result.status_code
    except AttributeError as e:
        msg = f"WMNResult missing required attribute: {e}"
        raise ValidationError(msg) from e

    base_name = (
        f"{status_str}_{status_code}_{safe_site_name}_{safe_username}_{created_at_str}"
    )
    safe_base_name = (
        sanitize_filename(base_name, max_len=MAX_FILENAME_LENGTH)
        or DEFAULT_UNNAMED_VALUE
    )
    return f"{safe_base_name}{RESPONSE_FILE_EXTENSION}"


# =============================================================================
# File Operations
# =============================================================================


async def read_file(file_path: str | Path) -> str:
    """Read text content from a file asynchronously with error handling.

    Args:
        file_path: Path to the file to read.

    Returns:
        str: Text content of the file.

    Raises:
        ValidationError: If file_path is missing or invalid.
        FileError: For any problem reading the file.
    """
    if not file_path:
        msg = "File path is required"
        raise ValidationError(msg)

    path_obj = Path(file_path)

    try:
        async with aiofiles.open(path_obj, encoding=DEFAULT_FILE_ENCODING) as f:
            content = await f.read()
    except FileNotFoundError as e:
        msg = f"File not found: {path_obj}"
        raise FileError(msg) from e
    except PermissionError as e:
        msg = f"Permission denied reading file: {path_obj}"
        raise FileError(msg) from e
    except UnicodeDecodeError as e:
        msg = f"Encoding error reading file {path_obj}: {e}"
        raise FileError(msg) from e
    except OSError as e:
        msg = f"OS error reading file {path_obj}: {e}"
        raise FileError(msg) from e

    if not content or not content.strip():
        msg = f"File is empty: {path_obj}"
        raise FileError(msg)

    return content


async def read_json(path: str | Path) -> dict[str, Any]:
    """Read JSON from a local file without blocking the event loop.

    Args:
        path: Path to the JSON file.

    Returns:
        dict[str, Any]: Parsed JSON data.

    Raises:
        ValidationError: If path is missing or invalid.
        FileError: For any problem reading or parsing the JSON file.
    """
    content = await read_file(path)
    try:
        return orjson.loads(content)
    except orjson.JSONDecodeError as e:
        path_obj = Path(path)
        msg = f"Invalid JSON in file {path_obj} at position {e.pos}: {e.msg}"
        raise FileError(msg) from e


async def write_file(file_path: str | Path, data: str | bytes) -> None:
    """Write data to a file asynchronously with error handling.

    Args:
        file_path: Path to the file to write.
        data: Text or binary data to write to the file.

    Raises:
        ValidationError: If file_path is missing or invalid.
        FileError: For any problem creating directories or writing the file.
    """
    if not file_path:
        msg = "File path is required"
        raise ValidationError(msg)

    path_obj = Path(file_path)

    try:
        path_obj.parent.mkdir(parents=True, exist_ok=True)
    except FileExistsError as e:
        msg = f"Cannot create directory, file exists at path: {path_obj.parent}"
        raise FileError(msg) from e
    except PermissionError as e:
        msg = f"Permission denied creating directory for {path_obj}"
        raise FileError(msg) from e
    except OSError as e:
        msg = f"OS error creating directory for {path_obj}: {e}"
        raise FileError(msg) from e

    try:
        if isinstance(data, bytes):
            async with aiofiles.open(path_obj, mode="wb") as f:
                await f.write(data)
        else:
            async with aiofiles.open(
                path_obj, mode="w", encoding=DEFAULT_FILE_ENCODING
            ) as f:
                await f.write(data)
    except PermissionError as e:
        msg = f"Permission denied writing to {path_obj}"
        raise FileError(msg) from e
    except UnicodeEncodeError as e:
        msg = f"Encoding error writing to {path_obj}: {e}"
        raise FileError(msg) from e
    except OSError as e:
        msg = f"OS error writing to {path_obj}: {e}"
        raise FileError(msg) from e


# =============================================================================
# Network Operations
# =============================================================================


async def fetch_json(http_client: BaseSession, url: str) -> dict[str, Any] | list[Any]:
    """Fetch and parse JSON from a URL.

    Args:
        http_client: HTTP client session to use for the request.
        url: URL to fetch JSON from.

    Returns:
        dict[str, Any] | list[Any]: Parsed JSON data as dictionary or list.

    Raises:
        ValidationError: If url is missing or empty.
        NetworkError: For any URL / HTTP / network / JSON issues.
    """
    url_stripped = url.strip() if url else ""
    if not url_stripped:
        msg = "URL is required and cannot be empty"
        raise ValidationError(msg)

    try:
        response = await http_client.get(url_stripped)
    except HttpError as e:
        msg = f"Network error fetching {url_stripped}: {e}"
        raise NetworkError(msg) from e

    if not response.text or not response.text.strip():
        msg = f"Empty response from {url_stripped}"
        raise NetworkError(msg)

    try:
        result = response.json()
    except (ValueError, orjson.JSONDecodeError) as e:
        msg = f"Failed to parse JSON from {url_stripped}: {e}"
        raise NetworkError(msg) from e

    if not isinstance(result, (dict, list)):
        msg = f"Unexpected JSON type from {url_stripped}: expected dict or list"
        raise NetworkError(msg)
    return result


# =============================================================================
# Browser Operations
# =============================================================================


def _resolve_url(url: str | Path) -> str:
    """Resolve a URL or Path to a string.

    Args:
        url: URL string or Path to resolve.

    Returns:
        str: Resolved URL string.
    """
    if isinstance(url, Path):
        return url.resolve().as_uri()
    return url.strip() if url else ""


async def open_url(url: str | Path) -> None:
    """Open a URL in the browser with error handling.

    Args:
        url: URL string or Path to open in the default browser.
            Paths are converted to file URIs automatically.

    Raises:
        ValidationError: If url is missing or invalid.
        BrowserError: For any issue with the browser operation.
    """
    url_str = _resolve_url(url)

    if not url_str:
        msg = "URL is required and cannot be empty"
        raise ValidationError(msg)

    try:
        await asyncio.to_thread(webbrowser.open, url_str)
    except webbrowser.Error as e:
        msg = f"Browser error opening {url_str}: {e}"
        raise BrowserError(msg) from e
    except OSError as e:
        msg = f"OS error opening browser for {url_str}: {e}"
        raise BrowserError(msg) from e
