# Formatter

Formats and sorts WhatsMyName JSON per schema (see API Reference).

## Basic Usage

```python
import json
from pathlib import Path
from naminter import WMNFormatter

# Load data and schema
with open("wmn-data.json", encoding="utf-8") as f:
    data = json.load(f)

with open("wmn-data-schema.json", encoding="utf-8") as f:
    schema = json.load(f)

# Read original data for comparison
input_path = Path("wmn-data.json")
original_data = input_path.read_text(encoding="utf-8")

# Create formatter with schema
formatter = WMNFormatter(schema)
# Format data (data is not modified)
formatted_data = formatter.format_data(data)

# Compare and write if changed
if original_data != formatted_data:
    output_path = Path("wmn-data-formatted.json")
    output_path.write_text(formatted_data, encoding="utf-8")
    print("File was formatted and saved")
else:
    print("File was already properly formatted")
```

## CLI Usage

The formatter is also available via the CLI:

```bash
naminter format \
    --local-schema wmn-data-schema.json \
    --local-data wmn-data.json \
    --output-data formatted-data.json
```

## API Reference

::: naminter.core.formatter.WMNFormatter
