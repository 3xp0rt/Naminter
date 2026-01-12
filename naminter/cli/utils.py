import asyncio
import json
from pathlib import Path
from typing import Any
import webbrowser

import aiofiles

from naminter.cli.constants import (
    DEFAULT_UNNAMED_VALUE,
    MAX_FILENAME_LENGTH,
    OPTION_AUTO_VALUE,
    RESPONSE_FILE_DATE_FORMAT,
    RESPONSE_FILE_EXTENSION,
)
from naminter.cli.exceptions import (
    BrowserError,
    FileError,
    NetworkError,
    ValidationError,
)
from naminter.core.constants import (
    ASCII_CONTROL_CHAR_THRESHOLD,
    DEFAULT_FILE_ENCODING,
    EMPTY_STRING,
    HTTP_STATUS_OK,
)
from naminter.core.exceptions import HttpError
from naminter.core.models import WMNResult
from naminter.core.network import BaseSession


# Option parsing utilities
def parse_option_path(option_value: str | None) -> str | None:
    """Parse export/response option value, returning None for auto or unset.

    Args:
        option_value: The option value to parse. Can be None, OPTION_AUTO_VALUE, or
            a path string.

    Returns:
        None if the option is unset or set to auto mode, otherwise the path string.
    """
    if option_value in {None, OPTION_AUTO_VALUE}:
        return None
    return option_value


# Filename utilities
def sanitize_filename(filename: str) -> str | None:
    """Sanitize filename for cross-platform compatibility.

    Removes or replaces invalid characters that are not allowed in filenames
    on various operating systems (Windows, macOS, Linux).

    Args:
        filename: The filename to sanitize.

    Returns:
        A sanitized filename safe for all platforms, or None if invalid.

    Raises:
        ValidationError: If filename cannot be converted to string.
    """
    if not filename:
        return None

    try:
        filename_str = str(filename).strip()
    except (TypeError, ValueError) as e:
        msg = f"Failed to convert filename to string: {e}"
        raise ValidationError(msg) from e

    if not filename_str:
        return None

    invalid_chars = '<>:"|?*\\/\0'
    translation_table = str.maketrans(invalid_chars, "_" * len(invalid_chars))
    sanitized = EMPTY_STRING.join(
        "_" if ord(c) < ASCII_CONTROL_CHAR_THRESHOLD else c
        for c in filename_str.translate(translation_table)
    )
    sanitized = sanitized.strip(" .")

    if len(sanitized) > MAX_FILENAME_LENGTH:
        sanitized = sanitized[:MAX_FILENAME_LENGTH].rstrip(" .")

    return sanitized or None


def get_response_filename(result: WMNResult) -> str:
    """Generate a sanitized filename for saving response data.

    Args:
        result: The WMNResult containing response data.

    Returns:
        A sanitized filename with format: status_code_site_username_timestamp.html

    Raises:
        ValidationError: If WMNResult is missing required attributes.
    """
    try:
        safe_site_name = sanitize_filename(result.name) or DEFAULT_UNNAMED_VALUE
        safe_username = sanitize_filename(result.username) or DEFAULT_UNNAMED_VALUE
        status_str = result.status.value
        created_at_str = result.created_at.strftime(RESPONSE_FILE_DATE_FORMAT)
        status_code = result.status_code
    except AttributeError as e:
        msg = f"WMNResult missing required attribute: {e}"
        raise ValidationError(msg) from e

    base_name = (
        f"{status_str}_{status_code}_{safe_site_name}_{safe_username}_{created_at_str}"
    )
    safe_base_name = sanitize_filename(base_name) or DEFAULT_UNNAMED_VALUE
    return f"{safe_base_name}{RESPONSE_FILE_EXTENSION}"


# File operations
async def read_file(file_path: str | Path) -> str:
    """Read text content from a file asynchronously with error handling.

    Args:
        file_path: Path to the file to read.

    Returns:
        Text content of the file.

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
        Parsed JSON data as dictionary.

    Raises:
        ValidationError: If path is missing or invalid.
        FileError: For any problem reading or parsing the JSON file.
    """
    content = await read_file(path)
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        path_obj = Path(path)
        msg = (
            f"Invalid JSON in file {path_obj} at line {e.lineno}, "
            f"column {e.colno}: {e.msg}"
        )
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
    except PermissionError as e:
        msg = f"Permission denied creating directory for {path_obj}"
        raise FileError(msg) from e
    except OSError as e:
        msg = f"OS error creating directory for {path_obj}: {e}"
        raise FileError(msg) from e

    try:
        mode = "wb" if isinstance(data, bytes) else "w"
        encoding = None if isinstance(data, bytes) else DEFAULT_FILE_ENCODING
        async with aiofiles.open(path_obj, mode=mode, encoding=encoding) as f:
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


# Network operations
async def fetch_json(http_client: BaseSession, url: str) -> dict[str, Any]:
    """Fetch and parse JSON from a URL.

    Args:
        http_client: HTTP client session to use for the request.
        url: URL to fetch JSON from.

    Returns:
        Parsed JSON data as dictionary.

    Raises:
        ValidationError: If http_client or url is missing or invalid.
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

    if response.status_code != HTTP_STATUS_OK:
        msg = f"Failed to fetch from {url_stripped}: HTTP {response.status_code}"
        raise NetworkError(msg)

    if not response.text or not response.text.strip():
        msg = f"Empty response from {url_stripped}"
        raise NetworkError(msg)

    try:
        return response.json()
    except (ValueError, json.JSONDecodeError) as e:
        msg = f"Failed to parse JSON from {url_stripped}: {e}"
        raise NetworkError(msg) from e


# Browser operations
async def open_url(url: str) -> None:
    """Open a URL in the browser with error handling.

    Args:
        url: URL to open in the default browser.

    Raises:
        ValidationError: If url is missing or invalid.
        BrowserError: For any issue with the browser operation.
    """
    url_stripped = url.strip() if url else ""
    if not url_stripped:
        msg = "URL is required and cannot be empty"
        raise ValidationError(msg)

    try:
        await asyncio.to_thread(webbrowser.open, url_stripped)
    except webbrowser.Error as e:
        msg = f"Browser error opening {url_stripped}: {e}"
        raise BrowserError(msg) from e
    except OSError as e:
        msg = f"OS error opening browser for {url_stripped}: {e}"
        raise BrowserError(msg) from e
    except Exception as e:
        msg = f"Unexpected error opening browser for {url_stripped}: {e}"
        raise BrowserError(msg) from e
