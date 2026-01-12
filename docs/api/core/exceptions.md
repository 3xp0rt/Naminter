# Exceptions

Exception classes used throughout Naminter for error handling.

## Overview

Naminter uses a hierarchical exception structure with `NaminterError` as the base exception class. All exceptions inherit from this base class, allowing for consistent error handling across the codebase.

## Core Exceptions

### Base Exception

::: naminter.core.exceptions.NaminterError

### Network/HTTP Errors

::: naminter.core.exceptions.HttpError
::: naminter.core.exceptions.HttpSessionError
::: naminter.core.exceptions.HttpTimeoutError
::: naminter.core.exceptions.HttpStatusError

### Data Processing Errors

::: naminter.core.exceptions.WMNDataError
::: naminter.core.exceptions.WMNUninitializedError
::: naminter.core.exceptions.WMNUnknownSiteError
::: naminter.core.exceptions.WMNUnknownCategoriesError
::: naminter.core.exceptions.WMNSchemaError
::: naminter.core.exceptions.WMNValidationError

## Common Exception Patterns

### Handling Network Errors

```python
from naminter import HttpError, HttpTimeoutError
from naminter.core.exceptions import HttpStatusError

try:
    # Network operation
    pass
except HttpTimeoutError:
    # Handle timeout specifically (e.g., retry with backoff)
    pass
except HttpStatusError as e:
    # Handle HTTP error status codes (access e.status_code, e.url)
    if e.status_code == 404:
        # Handle not found
        pass
except HttpError:
    # Handle any other HTTP error
    pass
```

### Handling Data Errors

```python
from naminter.core.exceptions import (
    WMNDataError,
    WMNUninitializedError,
    WMNUnknownSiteError,
    WMNValidationError,
)

try:
    # WMN data operation
    pass
except WMNUninitializedError:
    # Data not loaded
    pass
except WMNUnknownSiteError as e:
    # Access unknown site names
    print(f"Unknown sites: {e.site_names}")
except WMNValidationError as e:
    # Access validation errors
    for error in e.errors:
        print(f"Validation error: {error}")
except WMNDataError:
    # Handle any other data error
    pass
```
