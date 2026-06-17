"""Tests for core exception types."""

from __future__ import annotations

from naminter.core.exceptions import (
    WMNUnknownCategoriesError,
    WMNUnknownSiteError,
    WMNValidationError,
)


def test_wmn_unknown_site_error_stores_names() -> None:
    err = WMNUnknownSiteError("bad", site_names=["a", "b"])
    assert err.site_names == ["a", "b"]


def test_wmn_unknown_site_error_default_names() -> None:
    err = WMNUnknownSiteError("bad")
    assert err.site_names == []


def test_wmn_unknown_categories_error_stores_categories() -> None:
    err = WMNUnknownCategoriesError("bad", categories=["x"])
    assert err.categories == ["x"]


def test_wmn_validation_error_stores_error_lists() -> None:
    err = WMNValidationError(
        "bad",
        schema_errors=[{"s": 1}],
        data_errors=[{"d": 2}],
    )
    assert err.schema_errors == [{"s": 1}]
    assert err.data_errors == [{"d": 2}]
