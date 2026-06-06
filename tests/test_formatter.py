"""Tests for WMNFormatter."""

from __future__ import annotations

from typing import Any

import pytest

from naminter.core.exceptions import WMNFormatError, WMNSchemaError
from naminter.core.formatter import WMNFormatter


def test_format_dataset_sorts_and_orders(
    formatter_schema: dict[str, Any],
    minimal_dataset: dict[str, Any],
) -> None:
    z_site = {
        **minimal_dataset["sites"][0],
        "name": "Zebra",
        "headers": {"B": "2", "a": "1"},
    }
    a_site = {**minimal_dataset["sites"][0], "name": "apple"}
    data = {
        **minimal_dataset,
        "sites": [z_site, a_site],
        "authors": ["zebra", "alpha"],
    }
    fmt = WMNFormatter(formatter_schema)
    out = fmt.format_dataset(data)
    assert '"apple"' in out
    assert out.index("apple") < out.index("Zebra")
    assert '"a"' in out
    assert '"B"' in out
    assert out.index('"a"') < out.index('"B"')


def test_format_dataset_rejects_non_object_site(
    formatter_schema: dict[str, Any],
    minimal_dataset: dict[str, Any],
) -> None:
    fmt = WMNFormatter(formatter_schema)
    data = {**minimal_dataset, "sites": [[]]}
    with pytest.raises(WMNFormatError, match="must be an object"):
        fmt.format_dataset(data)


def test_get_site_key_order_missing_raises() -> None:
    bad = {"properties": {"sites": {"items": {}}}}
    fmt = WMNFormatter(bad)
    with pytest.raises(WMNSchemaError, match="Site schema properties not found"):
        fmt.format_dataset(
            {
                "license": ["MIT"],
                "authors": ["a"],
                "categories": ["c"],
                "sites": [],
            },
        )


def test_format_dataset_rejects_unknown_top_level_key(
    formatter_schema: dict[str, Any],
    minimal_dataset: dict[str, Any],
) -> None:
    fmt = WMNFormatter(formatter_schema)
    data = {**minimal_dataset, "extra_field": 1}
    with pytest.raises(WMNFormatError, match="Unknown keys found in dataset"):
        fmt.format_dataset(data)


def test_format_dataset_rejects_unknown_site_key(
    formatter_schema: dict[str, Any],
    minimal_dataset: dict[str, Any],
) -> None:
    fmt = WMNFormatter(formatter_schema)
    site = {**minimal_dataset["sites"][0], "unknown_site_key": True}
    data = {**minimal_dataset, "sites": [site]}
    with pytest.raises(WMNFormatError, match="Unknown keys found in site"):
        fmt.format_dataset(data)


def test_sort_site_headers_rejects_non_object(
    formatter_schema: dict[str, Any],
    minimal_dataset: dict[str, Any],
) -> None:
    fmt = WMNFormatter(formatter_schema)
    site = {**minimal_dataset["sites"][0], "headers": []}
    data = {**minimal_dataset, "sites": [site]}
    with pytest.raises(WMNFormatError, match="'headers' must be an object"):
        fmt.format_dataset(data)
