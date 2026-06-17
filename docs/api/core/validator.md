# Validator

Validates WhatsMyName JSON against a JSON Schema (see API Reference).

## Basic Usage

```python
import json
from pathlib import Path
from naminter import WMNValidator

# Load data and schema
with open("wmn-data.json", encoding="utf-8") as f:
    data = json.load(f)

with open("wmn-data-schema.json", encoding="utf-8") as f:
    schema = json.load(f)

# Create validator with schema
validator = WMNValidator(schema)

# Validate against JSON schema
schema_errors = validator.validate_schema(data)

# Validate with custom data rules
data_errors = WMNValidator.validate_data(data)

if schema_errors or data_errors:
    print(f"Validation failed:")
    for error in schema_errors:
        print(f"  Schema: {error.path}: {error.message}")
    for error in data_errors:
        print(f"  Data: {error.path}: {error.message}")
else:
    print("Validation passed!")
```

## CLI Usage

The validator is also available via the CLI:

```bash
naminter validate \
    --local-schema wmn-data-schema.json \
    --local-data wmn-data.json
```

## API Reference

::: naminter.core.validator.WMNValidator
