"""Tests for naminter.cli.utils helpers."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naminter.cli.exceptions import FileError, NetworkError, ValidationError
from naminter.cli.utils import (
    fetch_json,
    get_response_filename,
    open_url,
    read_file,
    read_json,
    write_file,
)
from naminter.core.exceptions import HttpError
from naminter.core.models import WMNResponse, WMNResult, WMNStatus

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_get_response_filename_shape() -> None:
    fixed = datetime(2024, 6, 15, 12, 30, 45, tzinfo=UTC)
    result = WMNResult(
        name="My Site",
        category="c",
        username="user_name",
        status=WMNStatus.EXISTS,
        status_code=200,
        created_at=fixed,
    )
    name = get_response_filename(result)
    assert name.endswith(".html")
    assert "exists" in name
    assert "200" in name


@pytest.mark.asyncio
async def test_fetch_json_empty_url() -> None:
    client = MagicMock()
    with pytest.raises(ValidationError, match="URL is required"):
        await fetch_json(client, "")


@pytest.mark.asyncio
async def test_fetch_json_http_error() -> None:
    client = MagicMock()
    client.get = AsyncMock(side_effect=HttpError("down"))
    with pytest.raises(NetworkError, match="Network error"):
        await fetch_json(client, "https://example.com/j")


@pytest.mark.asyncio
async def test_fetch_json_success() -> None:
    client = MagicMock()
    resp = WMNResponse(
        status_code=200,
        text='{"a": 1}',
        elapsed=timedelta(0),
    )
    client.get = AsyncMock(return_value=resp)
    data = await fetch_json(client, "https://example.com/j")
    assert data == {"a": 1}


def test_get_response_filename_validation_error_on_bad_result() -> None:
    bad = SimpleNamespace(name="n", username="u")
    with pytest.raises(ValidationError, match="WMNResult missing required attribute"):
        get_response_filename(bad)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_read_file_requires_path() -> None:
    with pytest.raises(ValidationError, match="File path is required"):
        await read_file("")


@pytest.mark.asyncio
async def test_read_file_missing(tmp_path: Path) -> None:
    missing = tmp_path / "nope.txt"
    with pytest.raises(FileError, match="File not found"):
        await read_file(missing)


@pytest.mark.asyncio
async def test_read_file_empty(tmp_path: Path) -> None:
    p = tmp_path / "e.txt"
    p.write_text("   \n", encoding="utf-8")
    with pytest.raises(FileError, match="empty"):
        await read_file(p)


@pytest.mark.asyncio
async def test_read_write_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "a.txt"
    await write_file(p, "hello")
    assert await read_file(p) == "hello"


@pytest.mark.asyncio
async def test_read_json_invalid(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{", encoding="utf-8")
    with pytest.raises(FileError, match="Invalid JSON"):
        await read_json(p)


@pytest.mark.asyncio
async def test_fetch_json_empty_response_body() -> None:
    client = MagicMock()
    client.get = AsyncMock(
        return_value=WMNResponse(
            status_code=200,
            text="  ",
            elapsed=timedelta(0),
        ),
    )
    with pytest.raises(NetworkError, match="Empty response"):
        await fetch_json(client, "https://example.com/x")


@pytest.mark.asyncio
async def test_fetch_json_non_object_list_ok() -> None:
    client = MagicMock()
    client.get = AsyncMock(
        return_value=WMNResponse(
            status_code=200,
            text="[1,2]",
            elapsed=timedelta(0),
        ),
    )
    assert await fetch_json(client, "https://example.com/x") == [1, 2]


@pytest.mark.asyncio
async def test_fetch_json_unexpected_json_type() -> None:
    client = MagicMock()
    client.get = AsyncMock(
        return_value=WMNResponse(
            status_code=200,
            text='"scalar"',
            elapsed=timedelta(0),
        ),
    )
    with pytest.raises(NetworkError, match="Unexpected JSON type"):
        await fetch_json(client, "https://example.com/x")


@pytest.mark.asyncio
async def test_open_url_success() -> None:
    def run_open(u: str) -> bool:
        return u.startswith("https://")

    async def fake_to_thread(
        func: Callable[..., object],
        /,
        *args: object,
        **kwargs: object,
    ) -> object:
        await asyncio.sleep(0)
        return func(*args, **kwargs)

    with (
        patch("naminter.cli.utils.asyncio.to_thread", new=fake_to_thread),
        patch("naminter.cli.utils.webbrowser.open", run_open),
    ):
        await open_url("https://example.com")


@pytest.mark.asyncio
async def test_open_url_empty_raises() -> None:
    with pytest.raises(ValidationError, match="URL is required"):
        await open_url("  ")
