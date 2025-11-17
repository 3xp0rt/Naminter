import asyncio
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints
from curl_cffi.requests import AsyncSession, ProxySpec
from curl_cffi.requests.exceptions import RequestException as CurlRequestException
from curl_cffi.requests.exceptions import Timeout as CurlTimeout

if TYPE_CHECKING:
    from curl_cffi.requests.session import HttpMethod


from .constants import HTTP_REQUEST_TIMEOUT_SECONDS
from .exceptions import HttpError, HttpSessionError, HttpTimeoutError
from .models import WMNResponse


@runtime_checkable
class BaseSession(Protocol):
    """Async HTTP client protocol for Naminter adapters."""

    async def open(self) -> None:
        """Open the underlying HTTP session."""
        ...

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        ...

    async def get(
        self, url: str, headers: Mapping[str, str] | None = None
    ) -> WMNResponse:
        """HTTP GET request (see class docstring for error contract)."""
        ...

    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """HTTP POST request (see class docstring for error contract)."""
        ...

    async def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """Generic HTTP request (see class docstring for error contract)."""
        ...


class CurlCFFISession:
    def __init__(
        self,
        *,
        proxies: str | dict[str, str] | None = None,
        verify: bool = True,
        timeout: int = HTTP_REQUEST_TIMEOUT_SECONDS,
        allow_redirects: bool = True,
        impersonate: BrowserTypeLiteral | None = None,
        ja3: str | None = None,
        akamai: str | None = None,
        extra_fp: ExtraFingerprints | dict[str, Any] | None = None,
    ) -> None:
        self._logger = logging.getLogger(__name__)
        self._session: AsyncSession | None = None

        if isinstance(proxies, str):
            proxies = {"http": proxies, "https": proxies}

        self._proxies: dict[str, str] | None = proxies
        self._verify: bool = verify
        self._timeout: int = timeout
        self._allow_redirects: bool = allow_redirects
        self._impersonate: BrowserTypeLiteral | None = impersonate
        self._ja3: str | None = ja3
        self._akamai: str | None = akamai
        self._extra_fp: ExtraFingerprints | dict[str, Any] | None = extra_fp

        self._lock = asyncio.Lock()

    async def open(self) -> None:
        if self._session is not None:
            return

        async with self._lock:
            if self._session is None:
                try:
                    proxies_spec: ProxySpec | None = cast(
                        "ProxySpec | None", self._proxies
                    )
                    extra_fp_spec: Any = self._extra_fp
                    self._session = AsyncSession(
                        proxies=proxies_spec,
                        verify=self._verify,
                        timeout=self._timeout,
                        allow_redirects=self._allow_redirects,
                        impersonate=self._impersonate,
                        ja3=self._ja3,
                        akamai=self._akamai,
                        extra_fp=extra_fp_spec,
                    )
                except Exception as e:
                    msg = "Unexpected error opening HTTP session"
                    raise HttpSessionError(msg, cause=e) from e

    async def close(self) -> None:
        if not self._session:
            return
        try:
            await self._session.close()
        except Exception as e:
            self._logger.warning("Unexpected error closing HTTP session: %s", e)
        finally:
            self._session = None

    async def get(
        self, url: str, headers: Mapping[str, str] | None = None
    ) -> WMNResponse:
        return await self.request("GET", url, headers=headers)

    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        return await self.request("POST", url, headers=headers, data=data)

    async def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        await self.open()

        assert self._session is not None

        try:
            response = await self._session.request(  # type: ignore[reportUnknownMemberType]
                method=cast("HttpMethod", method.upper()),
                url=url,
                headers=dict(headers) if headers else None,
                data=data,
            )

            return WMNResponse(
                status_code=response.status_code,
                text=response.text,
                elapsed=response.elapsed,
            )
        except CurlTimeout as e:
            msg = f"{method} timeout for {url}"
            raise HttpTimeoutError(msg, cause=e) from e
        except CurlRequestException as e:
            msg = f"{method} failed for {url}: {e}"
            raise HttpError(msg, cause=e) from e
        except Exception as e:
            msg = f"Unexpected error during {method} request to {url}: {e}"
            raise HttpError(msg, cause=e) from e


__all__ = [
    "BaseSession",
    "CurlCFFISession",
    "WMNResponse",
]
