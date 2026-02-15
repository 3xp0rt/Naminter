# Models

Data models and types used throughout Naminter.

## Overview

This module defines the core data structures for:
- Enumeration results (`WMNResult`, `WMNTestResult`)
- HTTP responses (`WMNResponse`)
- Site data types (`WMNDataset`, `WMNSite`)
- Validation modes and statuses (`WMNMode`, `WMNStatus`)
- Summary statistics (`WMNSummary`)
- Validation errors (`WMNError`)

## Common Models

- **`WMNResult`**: Represents the result of checking a username on a specific site
- **`WMNTestResult`**: Aggregated result of testing a site's detection methods using known usernames
- **`WMNResponse`**: HTTP response abstraction used by session adapters
- **`WMNDataset`**: TypedDict defining the WhatsMyName dataset structure
- **`WMNSite`**: TypedDict defining a single site entry in the dataset
- **`WMNMode`**: Enumeration mode (ALL for strict matching, ANY for permissive)
- **`WMNStatus`**: Status of enumeration (exists, missing, error, etc.)
- **`WMNSummary`**: Summary statistics of the loaded dataset
- **`WMNError`**: Structured representation of a validation error

## API Reference

::: naminter.core.models

