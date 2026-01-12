# Constants

Public constants used throughout Naminter.

## Overview

This module provides public constants for URLs and configuration values that are commonly used when working with Naminter.

## Available Constants

### URLs

- **`WMN_REMOTE_URL`**: Default URL for the remote WhatsMyName dataset
- **`WMN_SCHEMA_URL`**: Default URL for the WhatsMyName JSON schema

These constants are exported from the main `naminter` package and can be imported directly.

## Usage

```python
from naminter import CurlCFFISession, WMN_REMOTE_URL, WMN_SCHEMA_URL

async with CurlCFFISession() as http_client:
    # Fetch data using the public constant
    wmn_data = (await http_client.get(WMN_REMOTE_URL)).json()
    wmn_schema = (await http_client.get(WMN_SCHEMA_URL)).json()
```

## Internal Constants

The `naminter.core.constants` module also contains internal constants used throughout the codebase for configuration, HTTP settings, and data structure keys. These are primarily for internal use and are not exported from the main package.

## API Reference

::: naminter.core.constants
