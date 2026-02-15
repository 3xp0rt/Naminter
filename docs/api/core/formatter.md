# Formatter

Formatter for WhatsMyName JSON data.

## Overview

The `WMNFormatter` class provides functionality to format and sort WhatsMyName JSON data according to a JSON schema. It ensures consistent ordering of keys, alphabetical sorting of arrays, and proper formatting of site data.

## Basic Usage

```python
import json
from pathlib import Path
from naminter import WMNFormatter

# Load data and schema
with open("wmn-data.json", encoding="utf-8") as f:
    data = json.load(f)

with open("wmn-schema.json", encoding="utf-8") as f:
    schema = json.load(f)

# Read original content for comparison
input_path = Path("wmn-data.json")
original_content = input_path.read_text(encoding="utf-8")

# Create formatter with schema
formatter = WMNFormatter(schema)
# Format data (data is not modified)
formatted_content = formatter.format_dataset(data)

# Compare and write if changed
if original_content != formatted_content:
    output_path = Path("wmn-data-formatted.json")
    output_path.write_text(formatted_content, encoding="utf-8")
    print("File was formatted and saved")
else:
    print("File was already properly formatted")
```

## CLI Usage

The formatter is also available via the CLI:

```bash
naminter format \
    --local-schema schema.json \
    --local-data data.json \
    --output formatted-data.json
```

## API Reference

::: naminter.core.formatter.WMNFormatter
