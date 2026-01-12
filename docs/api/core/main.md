# Naminter

The main class for username enumeration across multiple platforms.

## Overview

The `Naminter` class provides asynchronous username enumeration functionality using the WhatsMyName dataset. It supports concurrent requests, custom filtering, and multiple validation modes.

## Basic Usage

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_REMOTE_URL

async def main():
    async with CurlCFFISession() as http_client:
        wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()
        
        async with Naminter(http_client=http_client, wmn_data=wmn_data) as naminter:
            async for result in naminter.enumerate_usernames(["username"]):
                print(f"{result.name}: {result.status.value}")

asyncio.run(main())
```

## API Reference

::: naminter.core.main.Naminter

