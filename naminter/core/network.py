import asyncio
from collections.abc import Mapping
import logging
from typing import Any, Protocol, cast, runtime_checkable

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints
from curl_cffi.requests import AsyncSession, ProxySpec, Response
from curl_cffi.requests.exceptions import (
    CertificateVerifyError as CurlCertificateVerifyError,
)
from curl_cffi.requests.exceptions import (
    ConnectionError as CurlConnectionError,
)
from curl_cffi.requests.exceptions import (
    CookieConflict as CurlCookieConflict,
)
from curl_cffi.requests.exceptions import (
    DNSError as CurlDNSError,
)
from curl_cffi.requests.exceptions import (
    HTTPError as CurlHTTPError,
)
from curl_cffi.requests.exceptions import (
    ImpersonateError as CurlImpersonateError,
)
from curl_cffi.requests.exceptions import (
    IncompleteRead as CurlIncompleteRead,
)
from curl_cffi.requests.exceptions import (
    InterfaceError as CurlInterfaceError,
)
from curl_cffi.requests.exceptions import (
    InvalidProxyURL as CurlInvalidProxyURL,
)
from curl_cffi.requests.exceptions import (
    InvalidURL as CurlInvalidURL,
)
from curl_cffi.requests.exceptions import (
    ProxyError as CurlProxyError,
)
from curl_cffi.requests.exceptions import (
    RequestException as CurlRequestException,
)
from curl_cffi.requests.exceptions import (
    SessionClosed as CurlSessionClosed,
)
from curl_cffi.requests.exceptions import (
    SSLError as CurlSSLError,
)
from curl_cffi.requests.exceptions import (
    Timeout as CurlTimeout,
)
from curl_cffi.requests.exceptions import (
    TooManyRedirects as CurlTooManyRedirects,
)

from naminter.core.constants import (
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HttpMethod,
)
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
    HttpStatusError,
    HttpTimeoutError,
)
from naminter.core.models import WMNResponse


@runtime_checkable
class BaseSession(Protocol):
    """Async HTTP client protocol for Naminter adapters.

    Implementations should raise the following exceptions:
    - HttpSessionError: For session initialization/management errors
    - HttpTimeoutError: For request timeouts
    - HttpStatusError: For HTTP error status codes (4xx, 5xx)
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

        Should handle errors gracefully and not raise exceptions during cleanup.
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
            HttpTimeoutError: If the request times out.
            HttpStatusError: If HTTP error status code is returned.
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
            HttpTimeoutError: If the request times out.
            HttpStatusError: If HTTP error status code is returned.
            HttpError: For other network-related errors.
        """
        ...

    async def request(
        self,
        method: HttpMethod,
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
            HttpTimeoutError: If the request times out.
            HttpStatusError: If HTTP error status code is returned.
            HttpError: For other network-related errors.
        """
        ...

    async def __aenter__(self) -> "BaseSession":
        """Async context manager entry."""
        ...

    async def __aexit__(
        self,
        exc_type: type | None,
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
        proxies: str | dict[str, str] | None = None,
        verify: bool = True,
        timeout: int = HTTP_REQUEST_TIMEOUT_SECONDS,
        allow_redirects: bool = True,
        impersonate: BrowserTypeLiteral | None = None,
        ja3: str | None = None,
        akamai: str | None = None,
        extra_fp: ExtraFingerprints | dict[str, Any] | None = None,
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
        """Open the HTTP session.

        Raises:
            HttpSessionError: If session initialization fails.
        """
        async with self._lock:
            if self._session is not None:
                return

            try:
                proxies_spec: ProxySpec | None = cast("ProxySpec | None", self._proxies)
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
            except CurlImpersonateError as e:
                msg = f"Browser impersonation failed: {e}"
                raise HttpSessionError(msg, cause=e) from e
            except (CurlInvalidProxyURL, CurlInvalidURL) as e:
                msg = f"Invalid URL in session configuration: {e}"
                raise HttpError(msg, cause=e) from e
            except CurlInterfaceError as e:
                msg = f"Network interface error during session initialization: {e}"
                raise HttpSessionError(msg, cause=e) from e
            except CurlRequestException as e:
                msg = f"Failed to initialize HTTP session: {e}"
                raise HttpSessionError(msg, cause=e) from e
            except Exception as e:
                msg = "Unexpected error opening HTTP session"
                raise HttpSessionError(msg, cause=e) from e

    async def close(self) -> None:
        """Close the HTTP session.

        Handles errors gracefully during cleanup and does not raise exceptions.
        Catches session closure errors and logs them without propagating.
        CancelledError is re-raised to allow proper cancellation handling.
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
        return await self.request(HTTP_METHOD_GET, url, headers=headers)

    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        return await self.request(HTTP_METHOD_POST, url, headers=headers, data=data)

    async def request(
        self,
        method: HttpMethod,
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
            HttpTimeoutError: If the request times out.
            HttpStatusError: If HTTP error status code is returned (4xx, 5xx).
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
            headers_dict = {key: value for key, value in headers.items()}

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
        except CurlTimeout as e:
            msg = f"{method_upper} timeout for {url}"
            raise HttpTimeoutError(msg, cause=e) from e
        except CurlSessionClosed as e:
            msg = f"HTTP session was closed: {e}"
            raise HttpSessionError(msg, cause=e) from e
        except CurlHTTPError as e:
            status_code: int | None = None
            err_response: Response | None = getattr(e, "response", None)
            if err_response is not None:
                status_code = err_response.status_code
            msg = f"{method_upper} returned error status for {url}"
            raise HttpStatusError(msg, status_code=status_code, url=url, cause=e) from e
        except (
            CurlSSLError,
            CurlCertificateVerifyError,
            CurlDNSError,
            CurlConnectionError,
            CurlProxyError,
            CurlInterfaceError,
            CurlTooManyRedirects,
            CurlInvalidProxyURL,
            CurlInvalidURL,
            CurlIncompleteRead,
            CurlCookieConflict,
        ) as e:
            msg = f"{method_upper} request failed: {e}"
            raise HttpError(msg, cause=e) from e
        except CurlRequestException as e:
            msg = f"{method_upper} request failed: {e}"
            raise HttpError(msg, cause=e) from e
        except Exception as e:
            msg = f"Unexpected error during {method_upper} request: {e}"
            raise HttpError(msg, cause=e) from e

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
    "WMNResponse",
]
