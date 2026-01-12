# Models

Data models and types used throughout Naminter.

## Overview

This module defines the core data structures for:
- Enumeration results (`WMNResult`)
- Site datasets (`WMNDataset`)
- Validation modes (`WMNMode`)
- Summary statistics (`WMNSummary`)

## Common Models

- **`WMNResult`**: Represents the result of checking a username on a specific site
- **`WMNDataset`**: Container for WhatsMyName site data
- **`WMNMode`**: Enumeration mode (ALL for strict matching, ANY for permissive)
- **`WMNStatus`**: Status of enumeration (exists, missing, error, etc.)

## API Reference

::: naminter.core.models

