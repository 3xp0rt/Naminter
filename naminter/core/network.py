"""HTTP session protocol and curl_cffi implementation for Naminter."""

import asyncio
from collections.abc import Mapping
import logging
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints
from curl_cffi.requests import AsyncSession, ProxySpec, Response
from curl_cffi.requests.exceptions import (
    SessionClosed as CurlSessionClosed,
)

from naminter.core.constants import (
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_TIMEOUT,
    HttpMethod,
)
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
)
from naminter.core.models import WMNResponse

if TYPE_CHECKING:
    from curl_cffi.requests.impersonate import ExtraFpDict


@runtime_checkable
class BaseSession(Protocol):
    """Async HTTP client protocol for Naminter adapters.

    Implementations should raise the following exceptions:
    - HttpSessionError: For session initialization/management errors
    - HttpError: For other network-related errors

    All exceptions should preserve the underlying cause when available.
    """

    async def open(self) -> None:
        """Open the underlying HTTP session.

        Raises:
            HttpSessionError: If session initialization fails.
        """
        ...

    async def close(self) -> None:
        """Close the underlying HTTP session.

        Should handle errors gracefully and not raise exceptions during
        cleanup, except for CancelledError which must be propagated.

        Raises:
            asyncio.CancelledError: Propagated to allow proper cancellation
                handling.
        """
        ...

    async def get(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> WMNResponse:
        """HTTP GET request.

        Args:
            url: The URL to request.
            headers: Optional HTTP headers to include.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or invalid.
            HttpError: For other network-related errors.
        """
        ...

    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """HTTP POST request.

        Args:
            url: The URL to request.
            headers: Optional HTTP headers to include.
            data: Optional request body data.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or invalid.
            HttpError: For other network-related errors.
        """
        ...

    async def request(
        self,
        method: HttpMethod | str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """Generic HTTP request.

        Args:
            method: HTTP method (GET or POST only).
            url: The URL to request.
            headers: Optional HTTP headers to include.
            data: Optional request body data.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or invalid.
            HttpError: For other network-related errors.
        """
        ...

    async def __aenter__(self) -> "BaseSession":
        """Async context manager entry."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit."""
        ...


class CurlCFFISession:
    """HTTP session implementation using curl_cffi library.

    Provides browser impersonation, proxy support, SSL verification,
    and custom fingerprinting capabilities.
    """

    def __init__(
        self,
        *,
        proxies: str | ProxySpec | None = None,
        verify: bool = True,
        timeout: int = HTTP_TIMEOUT,
        allow_redirects: bool = True,
        impersonate: BrowserTypeLiteral | str | None = None,
        ja3: str | None = None,
        akamai: str | None = None,
        extra_fp: ExtraFingerprints | dict[str, Any] | str | None = None,
    ) -> None:
        """Initialize CurlCFFISession with configuration.

        Args:
            proxies: Proxy configuration as string or dict.
            verify: Whether to verify SSL certificates.
            timeout: Request timeout in seconds.
            allow_redirects: Whether to follow HTTP redirects.
            impersonate: Browser to impersonate (e.g., 'chrome', 'firefox').
            ja3: JA3 fingerprint string for TLS fingerprinting.
            akamai: Akamai fingerprint string.
            extra_fp: Additional fingerprinting options.
        """
        self._logger = logging.getLogger(__name__)
        self._session: AsyncSession | None = None

        if isinstance(proxies, str):
            self._proxies: ProxySpec | None = {"http": proxies, "https": proxies}
        else:
            self._proxies = proxies
        self._verify: bool = verify
        self._timeout: int = timeout
        self._allow_redirects: bool = allow_redirects
        self._impersonate: BrowserTypeLiteral | str | None = impersonate
        self._ja3: str | None = ja3
        self._akamai: str | None = akamai
        self._extra_fp: ExtraFingerprints | dict[str, Any] | str | None = extra_fp

        self._lock = asyncio.Lock()

    async def open(self) -> None:
        """Open the HTTP session.

        Raises:
            HttpSessionError: If session initialization fails.
        """
        async with self._lock:
            if self._session is not None:
                return

            try:
                self._session = AsyncSession(
                    proxies=self._proxies,
                    verify=self._verify,
                    timeout=self._timeout,
                    allow_redirects=self._allow_redirects,
                    impersonate=cast("BrowserTypeLiteral | None", self._impersonate),
                    ja3=self._ja3,
                    akamai=self._akamai,
                    extra_fp=cast(
                        "ExtraFingerprints | ExtraFpDict | None",
                        self._extra_fp,
                    ),
                )
            except Exception as e:
                msg = f"Failed to initialize HTTP session: {e}"
                raise HttpSessionError(msg) from e

    async def close(self) -> None:
        """Close the HTTP session.

        Handles errors gracefully during cleanup. Catches session closure
        errors and logs them without propagating.

        Raises:
            asyncio.CancelledError: Re-raised to allow proper cancellation
                handling.
        """
        async with self._lock:
            if self._session is None:
                return
            try:
                await self._session.close()
            except asyncio.CancelledError:
                raise
            except CurlSessionClosed:
                self._logger.debug("HTTP session was already closed")
            except (OSError, RuntimeError, AttributeError) as e:
                self._logger.warning("Unexpected error closing HTTP session: %s", e)
            finally:
                self._session = None

    async def get(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> WMNResponse:
        """HTTP GET request.

        Args:
            url: The URL to request.
            headers: Optional HTTP headers to include.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or was closed.
            HttpError: For other network-related errors.
        """
        return await self.request(HTTP_METHOD_GET, url, headers=headers)

    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """HTTP POST request.

        Args:
            url: The URL to request.
            headers: Optional HTTP headers to include.
            data: Optional request body data.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or was closed.
            HttpError: For other network-related errors.
        """
        return await self.request(HTTP_METHOD_POST, url, headers=headers, data=data)

    async def request(
        self,
        method: HttpMethod | str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """Perform HTTP request.

        Args:
            method: HTTP method (GET or POST only).
            url: The URL to request.
            headers: Optional HTTP headers.
            data: Optional request body.

        Returns:
            WMNResponse: Response with status, text, and elapsed time.

        Raises:
            HttpSessionError: If session is not initialized or was closed.
            HttpError: For unsupported HTTP methods or other network-related errors.
        """
        if self._session is None:
            msg = "HTTP session not initialized."
            raise HttpSessionError(msg)

        method_upper: HttpMethod
        if method.upper() == HTTP_METHOD_GET:
            method_upper = HTTP_METHOD_GET
        elif method.upper() == HTTP_METHOD_POST:
            method_upper = HTTP_METHOD_POST
        else:
            msg = (
                f"Unsupported HTTP method: {method!r}. "
                f"Only {HTTP_METHOD_GET} and {HTTP_METHOD_POST} are supported."
            )
            raise HttpError(msg)

        headers_dict: dict[str, str] | None = None
        if headers is not None:
            headers_dict = dict(headers)

        try:
            response: Response = await self._session.request(
                method=method_upper,
                url=url,
                headers=headers_dict,
                data=data,
            )

            response_headers: dict[str, str] = {
                key: value
                for key, value in response.headers.items()
                if value is not None
            }
            return WMNResponse(
                status_code=response.status_code,
                text=response.text,
                elapsed=response.elapsed,
                headers=response_headers,
            )
        except CurlSessionClosed as e:
            msg = f"HTTP session was closed: {e}"
            raise HttpSessionError(msg) from e
        except Exception as e:
            msg = f"{method_upper} request failed for {url}: {e}"
            raise HttpError(msg) from e

    async def __aenter__(self) -> "CurlCFFISession":
        """Async context manager entry."""
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit."""
        await self.close()


__all__ = [
    "BaseSession",
    "CurlCFFISession",
]
