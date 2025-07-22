# 🔍 Naminter

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/3xp0rt/naminter?style=social)](https://github.com/3xp0rt/naminter)
[![PyPI Version](https://img.shields.io/pypi/v/naminter)](https://pypi.org/project/naminter/)
[![Downloads](https://img.shields.io/pypi/dm/naminter)](https://pypi.org/project/naminter/)

Naminter is a powerful, fast, and flexible username enumeration tool and Python package. Leveraging the comprehensive [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) list, Naminter efficiently enumerates usernames across hundreds of websites. With advanced features like browser impersonation, concurrent checking, and customizable filtering, it can be used both as a command-line tool and as a library in your Python projects.

<p align="center">
<img width="70%" height="70%" src="preview.png"/>
</p>

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [From PyPI](#from-pypi)
  - [From Source](#from-source)
- [Usage](#usage)
  - [Basic CLI Usage](#basic-cli-usage)
  - [Advanced CLI Options](#advanced-cli-options)
  - [Using as a Python Package](#using-as-a-python-package)
- [Command Line Options](#command-line-options)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Broad Site Coverage:** Leverages the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset for extensive username enumeration
- **Browser Impersonation:** Simulate Chrome, Firefox, Safari, Edge for accurate detection
- **Real-Time Console UI:** Live progress bar, colored output, and instant feedback
- **Concurrent & Fast:** High-speed, concurrent checks with adjustable task limits
- **Fuzzy Matching:** Optional fuzzy mode for broader username discovery
- **Category Filters:** Include or exclude sites by category
- **Custom Site Lists:** Use your own or remote WhatsMyName-format lists and schemas
- **Proxy & Network Options:** Full proxy support, SSL verification, and redirect control
- **Self-Check Mode:** Validate detection methods for reliability
- **Export Results:** Output to CSV, JSON, HTML, and PDF
- **Response Handling:** Save/open HTTP responses for analysis
- **Flexible Filtering:** Filter results by found, not found, errors, or unknown

## Installation

### From PyPI

Install Naminter with pip:

```bash
pip install naminter
```

### From Source

Clone the repository and install in editable mode:

```bash
git clone https://github.com/3xp0rt/naminter.git
cd naminter
pip install -e .
```

### Using Docker

All needed folders are mounted on the first start of the docker compose run command.

```bash
# Clone the repository
git clone https://github.com/3xp0rt/naminter.git
cd naminter
# Build the Docker image locally
docker build -t naminter .
# Run naminter inside the docker container
docker compose run --rm naminter --username john_doe
```

## Usage

### Basic CLI Usage

Check a single username:

```bash
naminter --username john_doe
```

Check multiple usernames:

```bash
naminter --username user1 --username user2 --username user3
```

### Advanced CLI Options

Customize the checker with various command-line arguments:

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

# Self-check with detailed output
naminter --self-check \
    --show-details \
    --log-level DEBUG \
    --log-file debug.log
```

### Using as a Python Package

Naminter can be used programmatically in Python projects to check the availability of usernames across various platforms. The Naminter class requires WhatsMyName (WMN) data to operate. You can either load this data from local files or fetch it from remote sources.

#### Getting Started - Loading WMN Data

Before using Naminter, you need to load the WhatsMyName dataset:

```python
import asyncio
import json
import aiohttp
from naminter import Naminter

async def load_wmn_data():
    """Load WhatsMyName data from the official repository."""
    async with aiohttp.ClientSession() as session:
        # Load the main sites data
        async with session.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json") as response:
            wmn_data = await response.json()
        
        # Optionally load the schema for validation
        async with session.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn_schema.json") as response:
            wmn_schema = await response.json()
    
    return wmn_data, wmn_schema

# Alternative: Load from local files
def load_local_wmn_data():
    """Load WhatsMyName data from local files."""
    with open("wmn-data.json", "r") as f:
        wmn_data = json.load(f)
    
    with open("wmn_schema.json", "r") as f:
        wmn_schema = json.load(f)
    
    return wmn_data, wmn_schema
```

#### Basic Asynchronous Example

```python
import asyncio
from naminter import Naminter

async def main():
    # Load WMN data
    wmn_data, wmn_schema = await load_wmn_data()
    
    # Initialize Naminter with the WMN data
    async with Naminter(wmn_data, wmn_schema) as naminter:
        results = await naminter.check_usernames(["example_username"])
        for result in results:
            if result.result_status.value == "found":
                print(f"✅ {result.username} found on {result.site_name}: {result.result_url}")
            elif result.result_status.value == "not_found":
                print(f"❌ {result.username} not found on {result.site_name}")
            elif result.result_status.value == "error":
                print(f"⚠️ Error checking {result.username} on {result.site_name}: {result.error}")

asyncio.run(main())
```

#### Asynchronous Example with Generator

For more efficient processing, use an asynchronous generator to handle results as they come in:

```python
import asyncio
from naminter import Naminter

async def main():
    wmn_data, wmn_schema = await load_wmn_data()
    
    async with Naminter(wmn_data, wmn_schema) as naminter:
        # Use as_generator=True for streaming results
        results = await naminter.check_usernames(["example_username"], as_generator=True)
        async for result in results:
            if result.result_status.value == "found":
                print(f"✅ {result.username} found on {result.site_name}: {result.result_url}")
            elif result.result_status.value == "not_found":
                print(f"❌ {result.username} not found on {result.site_name}")

asyncio.run(main())
```

#### Multiple Usernames and Advanced Configuration

```python
import asyncio
from naminter import Naminter
from naminter.core.models import BrowserImpersonation

async def main():
    wmn_data, wmn_schema = await load_wmn_data()
    
    # Advanced configuration with custom settings
    async with Naminter(
        wmn_data=wmn_data,
        wmn_schema=wmn_schema,
        max_tasks=100,
        timeout=15,
        impersonate=BrowserImpersonation.CHROME,
        verify_ssl=True,
        proxy="http://proxy:8080"
    ) as naminter:
        usernames = ["user1", "user2", "user3"]
        results = await naminter.check_usernames(usernames, fuzzy_mode=True)
        
        for result in results:
            if result.result_status.value == "found":
                print(f"✅ Found: {result.username} on {result.site_name}")
                print(f"   URL: {result.result_url}")
                print(f"   Response time: {result.elapsed:.2f}s")
            else:
                print(f"❌ Not found: {result.username} on {result.site_name}")

asyncio.run(main())
```

#### Self-Check and Validation

```python
import asyncio
from naminter import Naminter

async def main():
    wmn_data, wmn_schema = await load_wmn_data()
    
    async with Naminter(wmn_data, wmn_schema) as naminter:
        # Perform self-check to validate site configurations
        self_check_results = await naminter.self_check()
        
        for site_result in self_check_results:
            if site_result.error:
                print(f"❌ {site_result.site_name}: {site_result.error}")
            else:
                found_count = sum(1 for r in site_result.results if r.result_status.value == "found")
                total_count = len(site_result.results)
                print(f"✅ {site_result.site_name}: {found_count}/{total_count} known accounts found")

asyncio.run(main())
```

#### Getting WMN Information

```python
import asyncio
from naminter import Naminter

async def main():
    wmn_data, wmn_schema = await load_wmn_data()
    
    async with Naminter(wmn_data, wmn_schema) as naminter:
        # Get information about the loaded WMN data
        info = await naminter.get_wmn_info()
        print(f"Total sites: {info['sites_count']}")
        print(f"Categories: {', '.join(info['categories'])}")
        
        # List all available sites
        sites = naminter.list_sites()
        print(f"Available sites: {sites[:10]}...")  # Show first 10
        
        # List all categories
        categories = naminter.list_categories()
        print(f"All categories: {categories}")

asyncio.run(main())
```

## Command Line Options

### Basic Usage
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--username, -u`            | Username(s) to search                                      |
| `--site, -s`                | Specific site name(s) to check                             |
| `--version`                 | Show version information                                   |
| `--no-color`                | Disable colored output                                     |
| `--no-progressbar`          | Disable progress bar display                               |

### Input Lists
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--local-list`              | Path(s) to local file(s) containing list of sites to check |
| `--remote-list`             | URL(s) to fetch remote list(s) of sites to check           |
| `--skip-validation`         | Skip WhatsMyName schema validation for lists               |
| `--local-schema`            | Path to local WhatsMyName schema file                      |
| `--remote-schema`           | URL to fetch custom WhatsMyName schema                     |

### Self-Check
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--self-check`              | Perform self-check of the application                      |

### Category Filters
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--include-categories`      | Categories of sites to include in the search               |
| `--exclude-categories`      | Categories of sites to exclude from the search             |

### Network Options
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--proxy`                   | Proxy server to use for requests                           |
| `--timeout`                 | Maximum time in seconds to wait for each request (default: 30) |
| `--allow-redirects`         | Whether to follow URL redirects                             |
| `--verify-ssl`              | Whether to verify SSL certificates                          |
| `--impersonate, -i`         | Browser to impersonate in requests (chrome, chrome_android, safari, safari_ios, edge, firefox) |

### Concurrency & Debug
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--max-tasks`               | Maximum number of concurrent tasks (default: 50)           |
| `--fuzzy`                   | Enable fuzzy validation mode                                |
| `--log-level`               | Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)  |
| `--log-file`                | Path to log file for debug output                          |
| `--show-details`            | Show detailed information in console output                 |
| `--browse`                  | Open found profiles in web browser                         |

### Response Handling
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--save-response`           | Save HTTP response body for each result to files           |
| `--response-path`           | Custom directory path for saving response files            |
| `--open-response`           | Open saved response file in browser                        |

### Export Options
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--csv`                     | Export results to CSV file                                 |
| `--csv-path`                | Custom path for CSV export                                 |
| `--pdf`                     | Export results to PDF file                                 |
| `--pdf-path`                | Custom path for PDF export                                 |
| `--html`                    | Export results to HTML file                                |
| `--html-path`               | Custom path for HTML export                                |
| `--json`                    | Export results to JSON file                                |
| `--json-path`               | Custom path for JSON export                                |

### Result Filters
| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `--filter-all`              | Include all results in console and exports                 |
| `--filter-errors`           | Show only error results in console and exports             |
| `--filter-not-found`        | Show only not found results in console and exports         |
| `--filter-unknown`          | Show only unknown results in console and exports           |


## Contributing

Contributions are always welcome! Please submit a pull request with your improvements or open an issue to discuss.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
