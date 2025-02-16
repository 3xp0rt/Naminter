# 🔍 Naminter

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/3xp0rt/naminter?style=social)](https://github.com/3xp0rt/naminter)
[![PyPI Version](https://img.shields.io/pypi/v/naminter)](https://pypi.org/project/naminter/)
[![Downloads](https://img.shields.io/pypi/dm/naminter)](https://pypi.org/project/naminter/)

Naminter is a powerful, fast, and flexible username enumeration tool and Python package. Leveraging the comprehensive [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) list, Naminter efficiently enumerates usernames across hundreds of websites. With advanced features like browser impersonation, concurrent checking, and customizable filtering, it can be used both as a command-line tool and as a library in your Python projects.

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

- **Comprehensive Checks:** Uses the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset to support 600+ websites.
- **Browser Impersonation:** Simulate multiple browsers (e.g., Chrome, Safari, Edge) for optimal detection.
- **Real-Time Console Interface:** A dynamic progress tracker that updates in real time.
- **Concurrent Execution:** Fast, concurrent checks with a customizable number of tasks.
- **Fuzzy Matching Mode:** Utilize fuzzy matching for broader username detection.
- **Category Filtering:** Easily include or exclude websites based on categories.
- **Custom Lists:** Supports local and remote website lists in the WhatsMyName format.
- **Proxy Support:** Configure proxy settings to suit your environment.
- **Self-Check Mode:** Verify detection methods to ensure the best results.

## Installation

### From PyPI

Install Naminter with pip:

```bash
pip install naminter
```

### From Source

Clone the repository and install in editable mode:

```bash
git clone https://github.com/username/naminter.git
cd naminter
pip install -e .
```

## Usage

### Basic CLI Usage

Simply run:

```bash
naminter username
```

### Advanced CLI Options

Customize the checker with various command-line arguments:

```bash
naminter username \
    --max-tasks 50 \
    --timeout 30 \
    --impersonate edge \
    --include-categories social,tech \
    --proxy http://proxy:8080
```

### Using as a Python Package

Naminter can be used programmatically in Python projects to check the availability of usernames across various platforms. Below are examples demonstrating both synchronous and asynchronous usage of the Naminter library, including how to use it with a generator.

#### Synchronous Example

```python
import asyncio
from naminter import Naminter

async def main():
    async with Naminter() as naminter:
        await naminter.fetch_remote_list()
        results = await naminter.check_username("example_username")
        for result in results:
            print(result)

asyncio.run(main())
```

This will output results like:

```
SiteResult(site_name='TikTok', site_url='https://www.tiktok.com/@example_username?lang=en', category='social', check_status=<CheckStatus.FOUND: 'found'>, status_code=200, elapsed=4.04429395502666, error=None)
SiteResult(site_name='ebay_stores', site_url='https://www.ebay.com/str/example_username', category='shopping', check_status=<CheckStatus.NOT_FOUND: 'not_found'>, status_code=410, elapsed=3.7453646319918334, error=None)
```

#### Asynchronous Example with Generator

For more efficient processing, Naminter can be used with an asynchronous generator. This method allows you to handle results as they come in, without waiting for the entire process to complete.

```python
import asyncio
from naminter import Naminter

async def main():
    async with Naminter() as naminter:
        await naminter.fetch_remote_list()
        results = await naminter.check_username("example_username", as_generator=True)
        async for result in results:
            print(result)

asyncio.run(main())
```

This code will output similar results:

```
SiteResult(site_name='TikTok', site_url='https://www.tiktok.com/@example_username?lang=en', category='social', check_status=<CheckStatus.FOUND: 'found'>, status_code=200, elapsed=4.04429395502666, error=None)
SiteResult(site_name='ebay_stores', site_url='https://www.ebay.com/str/example_username', category='shopping', check_status=<CheckStatus.NOT_FOUND: 'not_found'>, status_code=410, elapsed=3.7453646319918334, error=None)
```

## Command Line Options

| Option                      | Description                                                |
|-----------------------------|------------------------------------------------------------|
| `username`                  | Username to check                                          |
| `-m, --max-tasks`           | Maximum concurrent tasks (default: 50)                     |
| `-t, --timeout`             | Request timeout in seconds (default: 30)                   |
| `-i, --impersonate`         | Browser to impersonate (none/chrome/chrome_android/safari/safari_ios/edge) |
| `-ic, --include-categories` | Categories to include                                      |
| `-ec, --exclude-categories` | Categories to exclude                                      |
| `-p, --proxy`               | Proxy URL                                                  |
| `-l, --local-list`          | Path to local website list                                 |
| `-r, --remote-url`          | URL to remote website list                                 |
| `-f, --fuzzy`               | Enable fuzzy matching mode                                 |
| `--allow-redirects`         | Allow HTTP redirects                                       |
| `--verify-ssl`              | Verify SSL certificates                                    |
| `--self-test`               | Run self-test mode                                         |
| `-b, --browse`              | Open found profiles in web browser                         |
| `--no-color`                | Disable colored output                                     |
| `-d, --debug`               | Enable debug output                                        |

## Contributing

Contributions are always welcome! Please submit a pull request with your improvements or open an issue to discuss.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.