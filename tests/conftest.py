"""Shared fixtures for Naminter tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import orjson
import pytest

if TYPE_CHECKING:
    from pathlib import Path

    from naminter.core.models import WMNData, WMNSite


@pytest.fixture
def minimal_site() -> WMNSite:
    """One valid WMN site entry for custom validation."""
    return {
        "name": "Example",
        "uri_check": "https://example.com/user/{account}",
        "e_code": 200,
        "e_string": "profile",
        "m_string": "not found",
        "m_code": 404,
        "known": ["alice"],
        "cat": "social",
    }


@pytest.fixture
def minimal_data(minimal_site: WMNSite) -> WMNData:
    """Minimal WMN-shaped data that passes custom validation."""
    return {
        "license": ["MIT"],
        "authors": ["author-one"],
        "categories": ["social"],
        "sites": [minimal_site],
    }


@pytest.fixture
def minimal_json_schema() -> dict[str, Any]:
    """Small JSON Schema sufficient to validate top-level WMN data keys."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["license", "authors", "categories", "sites"],
        "additionalProperties": True,
        "properties": {
            "license": {"type": "array", "items": {"type": "string"}},
            "authors": {"type": "array", "items": {"type": "string"}},
            "categories": {"type": "array", "items": {"type": "string"}},
            "sites": {"type": "array"},
        },
    }


@pytest.fixture
def formatter_schema() -> dict[str, Any]:
    """Schema fragment with site property order for WMNFormatter."""
    return {
        "properties": {
            "sites": {
                "items": {
                    "properties": {
                        "name": {"type": "string"},
                        "uri_check": {"type": "string"},
                        "cat": {"type": "string"},
                        "e_code": {"type": "integer"},
                        "e_string": {"type": "string"},
                        "m_string": {"type": "string"},
                        "m_code": {"type": "integer"},
                        "known": {"type": "array"},
                        "headers": {"type": "object"},
                    },
                },
            },
        },
    }


@pytest.fixture
def wmn_files(
    tmp_path: Path,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> tuple[Path, Path]:
    """On-disk WMN data + JSON Schema files for CLI tests."""
    data = tmp_path / "wmn-data.json"
    schema = tmp_path / "wmn-data-schema.json"
    data.write_bytes(orjson.dumps(minimal_data))
    schema.write_bytes(orjson.dumps(minimal_json_schema))
    return data, schema


@pytest.fixture
def http_session() -> MagicMock:
    """Mock HTTP session with async open/close/request hooks."""
    session = MagicMock()
    session.open = AsyncMock()
    session.close = AsyncMock()
    session.request = AsyncMock()
    return session
