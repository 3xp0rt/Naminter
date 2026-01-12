# Network

HTTP client and network utilities for making requests.

## Overview

The network module provides HTTP session management with support for:
- Browser impersonation
- Proxy configuration
- SSL verification
- Custom timeouts and redirects
- Custom session implementations via `BaseSession` protocol

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

You can create your own HTTP session implementation by implementing the `BaseSession` protocol. This allows you to use any HTTP client library (aiohttp, httpx, etc.) with Naminter.

### Implementing BaseSession

The `BaseSession` protocol requires the following methods:

- `async open() -> None`: Initialize/open the HTTP session
- `async close() -> None`: Clean up/close the HTTP session
- `async get(url: str, headers: Mapping[str, str] | None = None) -> WMNResponse`: Perform HTTP GET request
- `async post(url: str, headers: Mapping[str, str] | None = None, data: str | bytes | None = None) -> WMNResponse`: Perform HTTP POST request
- `async request(method: str, url: str, headers: Mapping[str, str] | None = None, data: str | bytes | None = None) -> WMNResponse`: Generic HTTP request
- `async __aenter__() -> BaseSession`: Async context manager entry
- `async __aexit__(exc_type, exc_val, exc_tb) -> None`: Async context manager exit

### Error Handling

Your implementation should raise the following exceptions:
- `HttpSessionError`: For session initialization/management errors
- `HttpTimeoutError`: For request timeouts
- `HttpError`: For other network-related errors

### Example: aiohttp Implementation

```python
import asyncio
import aiohttp
from collections.abc import Mapping
from naminter import (
    BaseSession,
    HttpError,
    HttpSessionError,
    HttpTimeoutError,
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
                raise HttpSessionError("Failed to create session", cause=e) from e
    
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
            async with self._session.request(
                method=method,
                url=url,
                headers=dict(headers) if headers else None,
                data=data,
            ) as response:
                text = await response.text()
                return WMNResponse(
                    status_code=response.status,
                    text=text,
                    elapsed=0.0,  # aiohttp doesn't provide elapsed time directly
                )
        except asyncio.TimeoutError as e:
            raise HttpTimeoutError(f"{method} timeout for {url}", cause=e) from e
        except aiohttp.ClientError as e:
            raise HttpError(f"{method} failed for {url}: {e}", cause=e) from e
        except Exception as e:
            raise HttpError(f"Unexpected error: {e}", cause=e) from e
    
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

