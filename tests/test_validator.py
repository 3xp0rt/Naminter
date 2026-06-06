"""Tests for WMNValidator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from naminter.core.exceptions import WMNSchemaError
from naminter.core.validator import WMNValidator

if TYPE_CHECKING:
    from naminter.core.models import WMNDataset, WMNSite


def test_wmn_validator_rejects_empty_schema() -> None:
    with pytest.raises(WMNSchemaError, match="Schema cannot be empty"):
        WMNValidator({})


def test_wmn_validator_rejects_invalid_json_schema() -> None:
    bad_schema = {"type": "object", "properties": "not-an-object"}
    with pytest.raises(WMNSchemaError, match="Invalid JSON schema"):
        WMNValidator(bad_schema)


def test_validate_dataset_accepts_minimal_dataset(
    minimal_dataset: WMNDataset,
) -> None:
    assert WMNValidator.validate_dataset(minimal_dataset) == []


def test_validate_dataset_duplicate_site_names(
    minimal_dataset: WMNDataset,
    minimal_site: WMNSite,
) -> None:
    other = {**minimal_site, "name": "Dup"}
    dup = {**minimal_site, "name": "Dup"}
    data: dict[str, Any] = {
        **minimal_dataset,
        "sites": [other, dup],
    }
    errors = WMNValidator.validate_dataset(data)
    assert len(errors) == 2
    assert all("Duplicate site name" in e.message for e in errors)


def test_validate_dataset_license_must_be_list(
    minimal_dataset: WMNDataset,
) -> None:
    data = {**minimal_dataset, "license": "MIT"}
    errors = WMNValidator.validate_dataset(data)
    assert len(errors) == 1
    assert "license" in errors[0].path


def test_validate_schema_reports_missing_required(
    minimal_json_schema: dict[str, Any],
) -> None:
    validator = WMNValidator(minimal_json_schema)
    incomplete: dict[str, Any] = {
        "license": ["MIT"],
        "authors": ["a"],
        "categories": ["c"],
    }
    errors = validator.validate_schema(incomplete)
    assert errors


def test_validate_schema_empty_when_valid(
    minimal_json_schema: dict[str, Any],
    minimal_dataset: WMNDataset,
) -> None:
    validator = WMNValidator(minimal_json_schema)
    assert validator.validate_schema(minimal_dataset) == []
