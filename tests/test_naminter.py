"""Tests for Naminter core orchestration."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest

from naminter.core.constants import SITE_KEY_VALID, WMN_KEY_SITES
from naminter.core.exceptions import (
    HttpSessionError,
    WMNArgumentError,
    WMNUnknownCategoriesError,
    WMNUnknownSiteError,
)
from naminter.core.main import Naminter
from naminter.core.models import WMNData, WMNMode, WMNResponse, WMNSite, WMNStatus

if TYPE_CHECKING:
    from unittest.mock import MagicMock


@pytest.mark.asyncio
async def test_naminter_open_propagates_http_session_error(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    http_session.open.side_effect = HttpSessionError("boom")
    n = Naminter(http_session, minimal_data, minimal_json_schema)
    with pytest.raises(HttpSessionError, match="boom"):
        await n.open()


@pytest.mark.asyncio
async def test_naminter_summary_counts_sites(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        summary = n.summary()
    assert summary.sites_count == 1


@pytest.mark.asyncio
async def test_enumerate_site_skips_invalid_site(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
    minimal_site: WMNSite,
) -> None:
    site: WMNSite = {**minimal_site, SITE_KEY_VALID: False}
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        result = await n.enumerate_site(site, "u", mode=WMNMode.ALL)
    assert result.status == WMNStatus.NOT_VALID
    http_session.request.assert_not_called()


@pytest.mark.asyncio
async def test_enumerate_site_success(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
    minimal_site: WMNSite,
) -> None:
    http_session.request.return_value = WMNResponse(
        status_code=minimal_site["e_code"],
        text=f"page {minimal_site['e_string']}",
        elapsed=timedelta(seconds=0),
    )
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        result = await n.enumerate_site(
            minimal_site,
            "alice",
            mode=WMNMode.ALL,
        )
    assert result.status == WMNStatus.EXISTS
    http_session.request.assert_called_once()


@pytest.mark.asyncio
async def test_filter_unknown_site_raises(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        with pytest.raises(WMNUnknownSiteError, match="Unknown site"):
            n.summary(site_names=["NopeSite"])


@pytest.mark.asyncio
async def test_filter_unknown_category_raises(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        with pytest.raises(WMNUnknownCategoriesError, match="Unknown categories"):
            n.summary(include_categories=["not-a-real-category"])


@pytest.mark.asyncio
async def test_enumerate_usernames_empty_raises(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        gen = n.enumerate_usernames([])
        with pytest.raises(WMNArgumentError, match="At least one username"):
            await anext(gen)


@pytest.mark.asyncio
async def test_enumerate_usernames_yields_result(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
    minimal_site: WMNSite,
) -> None:
    http_session.request.return_value = WMNResponse(
        status_code=minimal_site["e_code"],
        text=f"x {minimal_site['e_string']}",
        elapsed=timedelta(seconds=0),
    )
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        results = [
            r
            async for r in n.enumerate_usernames(
                ["alice"],
                site_names=[minimal_site["name"]],
            )
        ]
    assert len(results) == 1
    assert results[0].status == WMNStatus.EXISTS


@pytest.mark.asyncio
async def test_summary_filters_when_include_subset_of_exclude(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        summary = n.summary(
            include_categories=["social"],
            exclude_categories=["social", "gaming"],
        )
    assert summary.sites_count == 0


@pytest.mark.asyncio
async def test_test_enumeration_yields_per_site(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
    minimal_site: WMNSite,
) -> None:
    http_session.request.return_value = WMNResponse(
        status_code=minimal_site["e_code"],
        text=f"x {minimal_site['e_string']}",
        elapsed=timedelta(seconds=0),
    )
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        out = [r async for r in n.test_enumeration()]
    assert len(out) == 1
    assert out[0].name == minimal_site["name"]
    assert out[0].results is not None
    assert len(out[0].results) == len(minimal_site["known"])


@pytest.mark.asyncio
async def test_enumerate_usernames_no_matching_sites_is_empty(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    dead = {**minimal_data, WMN_KEY_SITES: []}
    async with Naminter(http_session, dead, minimal_json_schema) as n:
        got = [r async for r in n.enumerate_usernames(["a"])]
    assert got == []
