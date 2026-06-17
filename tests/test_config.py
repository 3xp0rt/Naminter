"""Tests for NaminterConfig."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from naminter.cli.config import NaminterConfig
from naminter.cli.exceptions import ConfigurationError
from naminter.core.constants import WMN_DATA_URL
from naminter.core.models import WMNMode


def test_config_requires_username_unless_test() -> None:
    with pytest.raises(ConfigurationError, match="username"):
        NaminterConfig(usernames=[])


def test_config_allows_test_without_usernames() -> None:
    with patch("naminter.cli.config.display_warning"):
        c = NaminterConfig(usernames=[], test=True)
    assert c.test is True


def test_config_default_remote_data() -> None:
    with patch("naminter.cli.config.display_warning"):
        c = NaminterConfig(usernames=["a"], test=True)
    assert c.remote_data == WMN_DATA_URL


def test_config_conflicting_data_sources(tmp_path: Path) -> None:
    local = tmp_path / "wmn-data.json"
    local.write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Conflicting data sources"):
        NaminterConfig(
            usernames=["a"],
            local_data=local,
            remote_data="https://example.com/wmn-data.json",
        )


def test_config_conflicting_schema_sources(tmp_path: Path) -> None:
    schema = tmp_path / "wmn-data-schema.json"
    schema.write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Conflicting schema sources"):
        NaminterConfig(
            usernames=["a"],
            local_schema=schema,
            remote_schema="https://other.example/wmn-data-schema.json",
        )


def test_config_skip_validation_allows_custom_remote_schema(tmp_path: Path) -> None:
    schema = tmp_path / "s.json"
    schema.write_text("{}", encoding="utf-8")
    c = NaminterConfig(
        usernames=["a"],
        skip_validation=True,
        local_schema=schema,
        remote_schema="https://custom/wmn-data-schema.json",
    )
    assert c.skip_validation is True


def test_config_default_filter_exists() -> None:
    c = NaminterConfig(usernames=["a"])
    assert c.filter_exists is True


def test_config_impersonate_none_string() -> None:
    c = NaminterConfig(usernames=["a"], impersonate="none")
    assert c.impersonate is None


def test_config_extra_fp_json_object() -> None:
    c = NaminterConfig(usernames=["a"], extra_fp='{"foo": 1}')
    assert c.extra_fp == {"foo": 1}


def test_config_extra_fp_invalid_json() -> None:
    with pytest.raises(ConfigurationError, match="Invalid JSON"):
        NaminterConfig(usernames=["a"], extra_fp="not json")


def test_config_from_click_rename_keys() -> None:
    c = NaminterConfig.from_click(
        username=("a", "b"),
        site=("S1",),
        mode="all",
        no_color=False,
    )
    assert c.usernames == ["a", "b"]
    assert c.sites == ["S1"]
    assert c.mode == WMNMode.ALL


def test_config_export_formats(tmp_path: Path) -> None:
    out = tmp_path / "out.csv"
    c = NaminterConfig(
        usernames=["a"],
        csv_export=True,
        csv_path=out,
    )
    assert c.export_formats == {"csv": out}


def test_config_response_dir_path_when_disabled() -> None:
    c = NaminterConfig(usernames=["a"], save_response=False)
    assert c.response_dir_path is None


def test_config_response_dir_path_default_cwd() -> None:
    c = NaminterConfig(usernames=["a"], save_response=True)
    assert c.response_dir_path == Path.cwd()


def test_config_response_dir_path_custom(tmp_path: Path) -> None:
    rd = tmp_path / "responses"
    c = NaminterConfig(usernames=["a"], save_response=True, response_dir=rd)
    assert c.response_dir_path == rd


def test_config_from_click_renames_export_flags() -> None:
    c = NaminterConfig.from_click(
        username=("a",),
        csv=True,
        json=True,
        mode="all",
        no_color=False,
    )
    assert c.csv_export is True
    assert c.json_export is True


def test_config_from_click_include_categories_tuple() -> None:
    c = NaminterConfig.from_click(
        username=("a",),
        include_categories=("social",),
        mode="all",
        no_color=False,
    )
    assert c.include_categories == ["social"]


def test_config_extra_fp_whitespace_only_string() -> None:
    c = NaminterConfig(usernames=["a"], extra_fp="   ")
    assert c.extra_fp is None


def test_config_extra_fp_json_not_object() -> None:
    with pytest.raises(ConfigurationError, match="expected JSON object"):
        NaminterConfig(usernames=["a"], extra_fp="[]")
