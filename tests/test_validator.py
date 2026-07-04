"""Tests for WMNValidator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from naminter.core.exceptions import WMNSchemaError, WMNValidationError
from naminter.core.main import Naminter
from naminter.core.validator import WMNValidator

if TYPE_CHECKING:
    from naminter.core.models import WMNData, WMNSite


def test_wmn_validator_rejects_empty_schema() -> None:
    with pytest.raises(WMNSchemaError, match="Schema cannot be empty"):
        WMNValidator({})


def test_wmn_validator_rejects_invalid_json_schema() -> None:
    bad_schema = {"type": "object", "properties": "not-an-object"}
    with pytest.raises(WMNSchemaError, match="Invalid JSON schema"):
        WMNValidator(bad_schema)


def test_validate_rules_accepts_minimal_data(
    minimal_data: WMNData,
) -> None:
    assert WMNValidator.validate_rules(minimal_data) == []


def test_validate_rules_duplicate_site_names(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    other = {**minimal_site, "name": "Dup"}
    dup = {**minimal_site, "name": "Dup"}
    data: dict[str, Any] = {
        **minimal_data,
        "sites": [other, dup],
    }
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 2
    assert all("Duplicate site name" in e.message for e in errors)


def test_validate_rules_license_must_be_list(
    minimal_data: WMNData,
) -> None:
    data = {**minimal_data, "license": "MIT"}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert "license" in errors[0].path


def test_validate_rules_sites_must_be_list(
    minimal_data: WMNData,
) -> None:
    data = {**minimal_data, "sites": "not-a-list"}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path == "$.sites"
    assert "must be array" in errors[0].message


def test_validate_rules_sites_required(
    minimal_data: WMNData,
) -> None:
    data = {key: value for key, value in minimal_data.items() if key != "sites"}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path == "$.sites"
    assert "Missing required key" in errors[0].message


def test_validate_rules_top_level_key_required(
    minimal_data: WMNData,
) -> None:
    data = {key: value for key, value in minimal_data.items() if key != "authors"}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path == "$.authors"
    assert "Missing required key" in errors[0].message


def test_validate_rules_site_items_must_be_objects(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    data: dict[str, Any] = {
        **minimal_data,
        "sites": [minimal_site, "not-a-site"],
    }
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path == "$.sites[1]"
    assert "must be object" in errors[0].message


def test_validate_rules_site_missing_keys_and_field_errors(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site}
    del site["e_code"]
    site["uri_check"] = 123
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    messages = [e.message for e in errors]
    assert any("Missing required keys" in m for m in messages)
    assert any("uri_check" in m for m in messages)
    assert any("e_code" in m for m in messages)


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
    minimal_data: WMNData,
) -> None:
    validator = WMNValidator(minimal_json_schema)
    assert validator.validate_schema(minimal_data) == []


def test_validate_runs_schema_and_rules(
    minimal_json_schema: dict[str, Any],
    minimal_data: WMNData,
) -> None:
    validator = WMNValidator(minimal_json_schema)
    schema_errors = validator.validate_schema(minimal_data)
    data_errors = WMNValidator.validate_rules(minimal_data)
    assert schema_errors == []
    assert data_errors == []


def test_validate_rules_without_schema_instance(
    minimal_data: WMNData,
) -> None:
    assert WMNValidator.validate_rules(minimal_data) == []


def test_naminter_validate_data_without_schema(
    minimal_data: WMNData,
) -> None:
    naminter = Naminter(MagicMock(), minimal_data, schema=None)
    naminter._validate_data()


def test_naminter_validate_data_without_schema_raises_on_invalid_data() -> None:
    naminter = Naminter(MagicMock(), {"license": "bad"}, schema=None)
    with pytest.raises(WMNValidationError, match="WMN validation failed"):
        naminter._validate_data()


def test_validate_rules_site_known_items_must_be_strings(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "known": ["alice", 1]}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".known[1]")
    assert "must be string" in errors[0].message


def test_validate_rules_site_strip_bad_char_must_be_string_or_none(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "strip_bad_char": 1}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".strip_bad_char")
    assert "must be string or None" in errors[0].message


def test_validate_rules_site_cat_must_be_string(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "cat": 123}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".cat")
    assert "must be string" in errors[0].message


def test_validate_rules_site_protection_items_must_be_strings(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "protection": ["cloudflare", 1]}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".protection[1]")
    assert "must be string" in errors[0].message


def test_validate_rules_site_valid_must_be_boolean(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "valid": "yes"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".valid")
    assert "must be boolean" in errors[0].message


def test_validate_rules_allows_invalid_cat_enum(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "cat": "not-a-category"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    assert WMNValidator.validate_rules(data) == []


def test_validate_schema_rejects_invalid_cat_enum(
    minimal_data: WMNData,
    minimal_site: WMNSite,
    wmn_data_schema: dict[str, Any],
) -> None:
    site = {**minimal_site, "cat": "not-a-category"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator(wmn_data_schema).validate_schema(data)
    assert errors
    assert any("cat" in e.path for e in errors)


def test_validate_rules_rejects_invalid_uri_check_scheme(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "uri_check": "ftp://example.com/{account}"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert errors
    assert any("uri_check" in e.path for e in errors)
    assert any("http or https" in e.message for e in errors)


def test_validate_rules_accepts_http_uri_check(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {
        **minimal_site,
        "uri_check": "http://example.com/user/{account}",
    }
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    assert WMNValidator.validate_rules(data) == []


def test_validate_rules_rejects_invalid_uri_pretty_scheme(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "uri_pretty": "ftp://example.com/{account}"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert errors
    assert any("uri_pretty" in e.path for e in errors)
    assert any("http or https" in e.message for e in errors)


def test_validate_schema_rejects_invalid_uri_check_pattern(
    minimal_data: WMNData,
    minimal_site: WMNSite,
    wmn_data_schema: dict[str, Any],
) -> None:
    site = {**minimal_site, "uri_check": "ftp://example.com/{account}"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator(wmn_data_schema).validate_schema(data)
    assert errors
    assert any("uri_check" in e.path for e in errors)


def test_validate_rules_rejects_missing_account_placeholder(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "uri_check": "https://example.com/user"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert errors
    assert any("uri_check" in e.path for e in errors)
    assert any("{account}" in e.message for e in errors)


def test_validate_schema_rejects_missing_account_placeholder(
    minimal_data: WMNData,
    minimal_site: WMNSite,
    wmn_data_schema: dict[str, Any],
) -> None:
    site = {**minimal_site, "uri_check": "https://example.com/user"}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator(wmn_data_schema).validate_schema(data)
    assert errors
    assert any("uri_check" in e.path for e in errors)


def test_validate_rules_allows_empty_known(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "known": []}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    assert WMNValidator.validate_rules(data) == []


def test_validate_schema_rejects_empty_known(
    minimal_data: WMNData,
    minimal_site: WMNSite,
    wmn_data_schema: dict[str, Any],
) -> None:
    site = {**minimal_site, "known": []}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator(wmn_data_schema).validate_schema(data)
    assert errors
    assert any("known" in e.path for e in errors)


def test_validate_rules_rejects_out_of_range_status_code(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "e_code": 999}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert errors
    assert any("e_code" in e.path for e in errors)


def test_validate_rules_rejects_bool_status_code(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "e_code": True}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path.endswith(".e_code")
    assert "must be integer" in errors[0].message


def test_validate_rules_rejects_post_body_without_headers(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {
        **minimal_site,
        "post_body": '{"username":"{account}"}',
    }
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator.validate_rules(data)
    assert errors
    assert any("headers is required" in e.message for e in errors)


def test_validate_rules_categories_must_be_string_array(
    minimal_data: WMNData,
) -> None:
    data = {**minimal_data, "categories": ["social", 1]}
    errors = WMNValidator.validate_rules(data)
    assert len(errors) == 1
    assert errors[0].path == "$.categories[1]"
    assert "must be string" in errors[0].message


def test_validate_rules_allows_custom_category_values(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    data: dict[str, Any] = {
        **minimal_data,
        "categories": ["custom-category"],
        "sites": [{**minimal_site, "cat": "custom-category"}],
    }
    assert WMNValidator.validate_rules(data) == []


def test_validate_rules_allows_custom_protection_values(
    minimal_data: WMNData,
    minimal_site: WMNSite,
) -> None:
    site = {**minimal_site, "protection": ["custom-protection"]}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    assert WMNValidator.validate_rules(data) == []


def test_validate_schema_rejects_out_of_range_status_code(
    minimal_data: WMNData,
    minimal_site: WMNSite,
    wmn_data_schema: dict[str, Any],
) -> None:
    site = {**minimal_site, "e_code": 999}
    data: dict[str, Any] = {**minimal_data, "sites": [site]}
    errors = WMNValidator(wmn_data_schema).validate_schema(data)
    assert errors
    assert any("e_code" in e.path for e in errors)
