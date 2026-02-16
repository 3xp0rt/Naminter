# Network

HTTP client and session utilities.

## Basic Usage

```python
from naminter import CurlCFFISession

async with CurlCFFISession(
    timeout=30,
    impersonate="chrome",
    proxies="http://proxy:8080"
) as http_client:
    response = await http_client.get("https://example.com")
```

## Custom Session Implementation

Implement `BaseSession` (see API Reference) to use another HTTP client (e.g. aiohttp, httpx). Raise `HttpSessionError` or `HttpError` as appropriate.

### Example: aiohttp

```python
import asyncio
import time
import aiohttp
from collections.abc import Mapping
from datetime import timedelta
from naminter import (
    BaseSession,
    HttpError,
    HttpSessionError,
    Naminter,
    WMNResponse,
)

class AiohttpSession:
    """Custom aiohttp-based session implementation."""
    
    def __init__(self, timeout: int = 30, **kwargs):
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None
        self._kwargs = kwargs
    
    async def open(self) -> None:
        """Open the aiohttp session."""
        if self._session is None:
            try:
                self._session = aiohttp.ClientSession(
                    timeout=self._timeout,
                    **self._kwargs
                )
            except Exception as e:
                raise HttpSessionError(f"Failed to create session: {e}") from e
    
    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session:
            await self._session.close()
            self._session = None
    
    async def get(
        self, url: str, headers: Mapping[str, str] | None = None
    ) -> WMNResponse:
        """Perform HTTP GET request."""
        return await self.request("GET", url, headers=headers)
    
    async def post(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """Perform HTTP POST request."""
        return await self.request("POST", url, headers=headers, data=data)
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: str | bytes | None = None,
    ) -> WMNResponse:
        """Perform generic HTTP request."""
        await self.open()
        
        if self._session is None:
            raise HttpSessionError("Session not initialized")
        
        try:
            start = time.monotonic()
            async with self._session.request(
                method=method,
                url=url,
                headers=dict(headers) if headers else None,
                data=data,
            ) as response:
                text = await response.text()
                elapsed = timedelta(seconds=time.monotonic() - start)
                return WMNResponse(
                    status_code=response.status,
                    text=text,
                    elapsed=elapsed,
                )
        except asyncio.TimeoutError as e:
            raise HttpError(f"{method} timeout for {url}") from e
        except aiohttp.ClientError as e:
            raise HttpError(f"{method} failed for {url}: {e}") from e
        except Exception as e:
            raise HttpError(f"Unexpected error: {e}") from e
    
    async def __aenter__(self) -> "AiohttpSession":
        """Async context manager entry."""
        await self.open()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

# Usage with Naminter
async with AiohttpSession() as http_client:
    async with Naminter(http_client=http_client, wmn_data=wmn_data) as naminter:
        async for result in naminter.enumerate_usernames(["username"]):
            print(f"{result.name}: {result.status.value}")
```

## API Reference

::: naminter.core.network.BaseSession

::: naminter.core.network.CurlCFFISession

