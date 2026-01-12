# Usage

## Basic CLI Usage

Enumerate a single username:

```bash
naminter --username john_doe
```

Enumerate multiple usernames:

```bash
naminter --username user1 --username user2 --username user3
```

## Advanced CLI Options

Customize the enumerator with various command-line arguments:

```bash
# Basic username enumeration with custom settings
naminter --username john_doe \
    --max-tasks 100 \
    --timeout 15 \
    --impersonate chrome \
    --include-categories social coding

# Using proxy and saving responses
naminter --username jane_smith \
    --proxy http://proxy:8080 \
    --save-response \
    --open-response

# Using custom schema validation
naminter --username alice_bob \
    --local-schema ./custom-schema.json \
    --local-list ./my-sites.json

# Using remote schema with custom list
naminter --username test_user \
    --remote-schema https://example.com/custom-schema.json \
    --remote-list https://example.com/my-sites.json

# Export results in multiple formats
naminter --username alice_bob \
    --csv \
    --json \
    --html \
    --filter-all

# Export with custom paths using merged flags
naminter --username alice_bob \
    --csv results.csv \
    --json results.json \
    --html report.html

# Site validation with detailed output
naminter --test \
    --show-details \
    --log-level DEBUG \
    --log-file debug.log
```

## Using as a Python Package

### Basic Example

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_REMOTE_URL

async def main():
    async with CurlCFFISession() as http_client:
        wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()

        async with Naminter(http_client=http_client, wmn_data=wmn_data) as naminter:
            async for result in naminter.enumerate_usernames(["example_username"]):
                if result.status.value == "exists":
                    print(f"✅ {result.username} found on {result.name}: {result.url}")
                elif result.status.value == "missing":
                    print(f"❌ {result.username} not found on {result.name}")
                elif result.status.value == "error":
                    print(f"⚠️ Error checking {result.username} on {result.name}: {result.error}")

asyncio.run(main())
```

### Advanced Configuration

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMNMode, WMN_REMOTE_URL

async def main():
    async with CurlCFFISession(
        timeout=15,
        impersonate="chrome",
        verify=True,
        proxies="http://proxy:8080"
    ) as http_client:
        wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()

        async with Naminter(
            http_client=http_client,
            wmn_data=wmn_data,
            max_tasks=100
        ) as naminter:
            usernames = ["user1", "user2", "user3"]
            async for result in naminter.enumerate_usernames(usernames, mode=WMNMode.ANY):
                if result.status.value == "exists":
                    print(f"✅ {result.username} on {result.name}: {result.url}")

asyncio.run(main())
```

### Site Validation

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_REMOTE_URL

async def main():
    async with CurlCFFISession() as http_client:
        wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()

        async with Naminter(http_client=http_client, wmn_data=wmn_data) as naminter:
            async for site_result in naminter.enumerate_test():
                if site_result.error:
                    print(f"❌ {site_result.name}: {site_result.error}")
                else:
                    found = sum(1 for r in site_result.results if r.status.value == "exists")
                    total = len(site_result.results)
                    print(f"✅ {site_result.name}: {found}/{total} known accounts found")

asyncio.run(main())
```

### Getting WMN Summary

```python
import asyncio
from naminter import Naminter, CurlCFFISession, WMN_REMOTE_URL, WMN_SCHEMA_URL

async def main():
    async with CurlCFFISession() as http_client:
        # Load data and (optionally) schema using public constants
        wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()
        wmn_schema = (await http_client.get(WMN_SCHEMA_URL)).json()

        async with Naminter(
            http_client=http_client,
            wmn_data=wmn_data,
            wmn_schema=wmn_schema,
        ) as naminter:
            summary = naminter.get_wmn_summary()
            print(f"Total sites: {summary.sites_count}")
            print(f"Total categories: {summary.categories_count}")
            print(f"Known accounts: {summary.known_count}")

asyncio.run(main())
```

