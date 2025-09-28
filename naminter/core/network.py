import asyncio
import logging
import json
from typing import Any, Dict, Optional, Union, Protocol, Mapping, runtime_checkable

from curl_cffi.requests import AsyncSession
from curl_cffi.requests.exceptions import Timeout as CurlTimeout, RequestException as CurlRequestException
from curl_cffi import BrowserTypeLiteral

from .exceptions import NetworkError, TimeoutError, SessionError
from .models import Response


@runtime_checkable
class BaseSession(Protocol):
    """Async HTTP client protocol for Naminter adapters."""

    async def open(self) -> None:
        """Open the underlying HTTP session."""
        ...

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        ...

    async def get(self, url: str, headers: Optional[Mapping[str, str]] = None) -> Response:
        """HTTP GET request (see class docstring for error contract)."""
        ...

    async def post(
        self, url: str, headers: Optional[Mapping[str, str]] = None, data: Optional[Union[str, bytes]] = None
    ) -> Response:
        """HTTP POST request (see class docstring for error contract)."""
        ...

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
    ) -> Response:
        """Generic HTTP request (see class docstring for error contract)."""
        ...


class CurlCFFISession:
    def __init__(
        self,
        *,
        proxies: Optional[Union[str, Dict[str, str]]] = None,
        verify: bool = True,
        timeout: int = 30,
        allow_redirects: bool = True,
        impersonate: Optional[BrowserTypeLiteral] = None,
        ja3: Optional[str] = None,
        akamai: Optional[str] = None,
        extra_fp: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._logger = logging.getLogger(__name__)
        self._session: Optional[AsyncSession] = None

        if isinstance(proxies, str):
            proxies = {"http": proxies, "https": proxies}

        self._proxies: Optional[Union[str, Dict[str, str]]] = proxies
        self._verify: bool = verify
        self._timeout: int = timeout
        self._allow_redirects: bool = allow_redirects
        self._impersonate: Optional[BrowserTypeLiteral] = impersonate
        self._ja3: Optional[str] = ja3
        self._akamai: Optional[str] = akamai
        self._extra_fp: Optional[Dict[str, Any]] = extra_fp

        self._lock = asyncio.Lock()

    async def open(self) -> None:
        if self._session is not None:
            return
        async with self._lock:
            if self._session is None:
                try:
                    self._session = AsyncSession(
                        proxies=self._proxies,
                        verify=self._verify,
                        timeout=self._timeout,
                        allow_redirects=self._allow_redirects,
                        impersonate=self._impersonate,
                        ja3=self._ja3,
                        akamai=self._akamai,
                        extra_fp=self._extra_fp,
                    )
                except Exception as e:
                    raise SessionError("Failed to open curl-cffi session", cause=e) from e

    async def close(self) -> None:
        if not self._session:
            return
        try:
            await self._session.close()
        except Exception as e:
            self._logger.warning("Error closing curl-cffi session: %s", e)
        finally:
            self._session = None

    async def get(self, url: str, headers: Optional[Mapping[str, str]] = None) -> Response:
        await self.open()
        if self._session is None:
            raise SessionError("Session not initialized")

        try:
            response = await self._session.get(url, headers=dict(headers) if headers else None)
            elapsed = response.elapsed 
            return Response(status_code=response.status_code, text=response.text, elapsed=elapsed)
        except CurlTimeout as e:
            raise TimeoutError(f"GET timeout for {url}", cause=e) from e
        except CurlRequestException as e:
            raise NetworkError(f"GET failed for {url}: {e}", cause=e) from e
        except Exception as e:
            raise NetworkError(f"GET failed for {url}: {e}", cause=e) from e

    async def post(
        self, url: str, headers: Optional[Mapping[str, str]] = None, data: Optional[Union[str, bytes]] = None
    ) -> Response:
        await self.open()
        if self._session is None:
            raise SessionError("Session not initialized")

        try:
            response = await self._session.post(url, headers=dict(headers) if headers else None, data=data)
            elapsed = response.elapsed
            return Response(status_code=response.status_code, text=response.text, elapsed=elapsed)
        except CurlTimeout as e:
            raise TimeoutError(f"POST timeout for {url}", cause=e) from e
        except CurlRequestException as e:
            raise NetworkError(f"POST failed for {url}: {e}", cause=e) from e
        except Exception as e:
            raise NetworkError(f"POST failed for {url}: {e}", cause=e) from e

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
    ) -> Response:
        await self.open()
        if self._session is None:
            raise SessionError("Session not initialized")
            
        try:
            response = await self._session.request(method=method, url=url, headers=dict(headers) if headers else None, data=data)

            elapsed = response.elapsed
            return Response(status_code=response.status_code, text=response.text, elapsed=elapsed)
        except CurlTimeout as e:
            raise TimeoutError(f"{method} timeout for {url}", cause=e) from e
        except CurlRequestException as e:
            raise NetworkError(f"{method} failed for {url}: {e}", cause=e) from e
        except Exception as e:
            raise NetworkError(f"{method} failed for {url}: {e}", cause=e) from e



__all__ = [
    "Response",
    "BaseSession",
    "CurlCFFISession",
]


