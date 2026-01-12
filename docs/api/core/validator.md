# Validator

Validator for WhatsMyName JSON data.

## Overview

The `WMNValidator` class validates WhatsMyName JSON data against a JSON Schema. It uses the Draft7 JSON Schema validator to check data structure, types, and constraints.

## Basic Usage

```python
import json
from pathlib import Path
from naminter import WMNValidator

# Load data and schema
with open("wmn-data.json", encoding="utf-8") as f:
    data = json.load(f)

with open("wmn-schema.json", encoding="utf-8") as f:
    schema = json.load(f)

# Create validator with schema
validator = WMNValidator(schema)

# Validate data (data is not modified)
errors = validator.validate(data)

if errors:
    print(f"Validation failed with {len(errors)} errors:")
    for error in errors:
        print(f"  - {error.path}: {error.message}")
else:
    print("Validation passed!")
```

## CLI Usage

The validator is also available via the CLI:

```bash
naminter validate \
    --local-schema schema.json \
    --local-data data.json
```

## API Reference

::: naminter.core.validator.WMNValidator
