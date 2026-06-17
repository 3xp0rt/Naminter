# Constants

Public constants (see API Reference).

## Usage

```python
from naminter import CurlCFFISession, WMN_DATA_URL, WMN_SCHEMA_URL

async with CurlCFFISession() as http_client:
    # Fetch data using the public constant
    data = (await http_client.get(WMN_DATA_URL)).json()
    schema = (await http_client.get(WMN_SCHEMA_URL)).json()
```

## API Reference

::: naminter.core.constants
