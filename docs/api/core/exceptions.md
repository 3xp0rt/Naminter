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

### Data Processing Errors

::: naminter.core.exceptions.WMNDataError
::: naminter.core.exceptions.WMNUninitializedError
::: naminter.core.exceptions.WMNUnknownSiteError
::: naminter.core.exceptions.WMNUnknownCategoriesError
::: naminter.core.exceptions.WMNSchemaError
::: naminter.core.exceptions.WMNValidationError
::: naminter.core.exceptions.WMNArgumentError
::: naminter.core.exceptions.WMNEnumerationError
::: naminter.core.exceptions.WMNFormatError

## Common Exception Patterns

### Handling Network Errors

```python
from naminter.core.exceptions import HttpError, HttpSessionError

try:
    # Network operation
    pass
except HttpSessionError:
    # Handle session issues specifically
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
    for error in e.schema_errors:
        print(f"Schema error: {error}")
    for error in e.dataset_errors:
        print(f"Dataset error: {error}")
except WMNDataError:
    # Handle any other data error
    pass
```
