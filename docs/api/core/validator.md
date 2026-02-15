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

# Validate against JSON schema
schema_errors = validator.validate_schema(data)

# Validate with custom dataset rules
dataset_errors = WMNValidator.validate_dataset(data)

if schema_errors or dataset_errors:
    print(f"Validation failed:")
    for error in schema_errors:
        print(f"  Schema: {error.path}: {error.message}")
    for error in dataset_errors:
        print(f"  Dataset: {error.path}: {error.message}")
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
