"""Tests for CurlCFFISession (mocked curl_cffi AsyncSession)."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from curl_cffi.requests.exceptions import SessionClosed as CurlSessionClosed
import pytest

from naminter.core.constants import HTTP_METHOD_GET
from naminter.core.exceptions import HttpError, HttpSessionError
from naminter.core.network import CurlCFFISession


def _make_response(
    *,
    status_code: int = 200,
    text: str = "ok",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.elapsed = timedelta(seconds=0)
    r.headers = headers or {"X": "y"}
    return r


@pytest.mark.asyncio
async def test_proxy_string_normalized_to_dict() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.request = AsyncMock(return_value=_make_response())
        mock_as.return_value = inst
        s = CurlCFFISession(proxies="http://proxy:1")
        await s.open()
    kwargs = mock_as.call_args.kwargs
    assert kwargs["proxies"] == {"http": "http://proxy:1", "https": "http://proxy:1"}


@pytest.mark.asyncio
async def test_open_idempotent() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.request = AsyncMock(return_value=_make_response())
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        await s.open()
    assert mock_as.call_count == 1


@pytest.mark.asyncio
async def test_open_wraps_exception_as_http_session_error() -> None:
    with patch("naminter.core.network.AsyncSession", side_effect=RuntimeError("nope")):
        s = CurlCFFISession()
        with pytest.raises(HttpSessionError, match="Failed to initialize"):
            await s.open()


@pytest.mark.asyncio
async def test_request_before_open_raises() -> None:
    s = CurlCFFISession()
    with pytest.raises(HttpSessionError, match="not initialized"):
        await s.request(HTTP_METHOD_GET, "https://x")


@pytest.mark.asyncio
async def test_request_unsupported_method() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        with pytest.raises(HttpError, match="Unsupported HTTP method"):
            await s.request("PUT", "https://x")


@pytest.mark.asyncio
async def test_get_and_post_delegate_to_request() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.request = AsyncMock(return_value=_make_response(text="body"))
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        g = await s.get("https://a")
        assert g.text == "body"
        p = await s.post("https://b", data="d")
        assert p.text == "body"
        assert inst.request.call_count == 2


@pytest.mark.asyncio
async def test_request_maps_response_and_filters_none_headers() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        r = _make_response()
        r.headers = {"A": "1", "B": None}
        inst.request = AsyncMock(return_value=r)
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        out = await s.request(HTTP_METHOD_GET, "https://z", headers={"h": "v"})
        assert out.status_code == 200
        assert out.headers == {"A": "1"}


@pytest.mark.asyncio
async def test_request_http_error_on_generic_exception() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.request = AsyncMock(side_effect=OSError("down"))
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        with pytest.raises(HttpError, match="GET request failed"):
            await s.get("https://z")


@pytest.mark.asyncio
async def test_close_when_no_session_is_noop() -> None:
    s = CurlCFFISession()
    await s.close()


@pytest.mark.asyncio
async def test_close_clears_session() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.close = AsyncMock()
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        await s.close()
        inst.close.assert_awaited_once()
        assert s._session is None


@pytest.mark.asyncio
async def test_close_raises_cancelled_error() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()

        async def boom() -> None:
            raise asyncio.CancelledError

        inst.close = boom
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        with pytest.raises(asyncio.CancelledError):
            await s.close()


@pytest.mark.asyncio
async def test_close_ignores_curl_session_closed() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.close = AsyncMock(side_effect=CurlSessionClosed("already closed"))
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        await s.close()


@pytest.mark.asyncio
async def test_close_logs_warning_on_os_error() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.close = AsyncMock(side_effect=OSError("x"))
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        await s.close()


@pytest.mark.asyncio
async def test_request_raises_session_error_when_curl_session_closed() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.request = AsyncMock(side_effect=CurlSessionClosed("closed"))
        mock_as.return_value = inst
        s = CurlCFFISession()
        await s.open()
        with pytest.raises(HttpSessionError, match="HTTP session was closed"):
            await s.get("https://z")


@pytest.mark.asyncio
async def test_context_manager_opens_and_closes() -> None:
    with patch("naminter.core.network.AsyncSession") as mock_as:
        inst = MagicMock()
        inst.close = AsyncMock()
        mock_as.return_value = inst
        async with CurlCFFISession() as s:
            assert s._session is not None
        inst.close.assert_awaited()
