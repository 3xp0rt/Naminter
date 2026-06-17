# Naminter

Main class for username enumeration.

## Basic Usage

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_DATA_URL

async def main():
    async with CurlCFFISession() as http_client:
        data = (await http_client.get(WMN_DATA_URL)).json()
        
        async with Naminter(http_client=http_client, data=data) as naminter:
            async for result in naminter.enumerate_usernames(["username"]):
                print(f"{result.name}: {result.status.value}")

asyncio.run(main())
```

## Test Usage

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_DATA_URL

async def main():
    async with CurlCFFISession() as http_client:
        data = (await http_client.get(WMN_DATA_URL)).json()

        async with Naminter(http_client=http_client, data=data) as naminter:
            async for site_result in naminter.test_enumeration():
                if site_result.error:
                    print(f"ERROR {site_result.name}: {site_result.error}")
                else:
                    found = sum(1 for r in site_result.results if r.status.value == "exists")
                    total = len(site_result.results)
                    print(f"{site_result.name}: {found}/{total} known accounts found")

asyncio.run(main())
```

## API Reference

::: naminter.core.main.Naminter

