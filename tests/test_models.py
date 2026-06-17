"""Tests for core data models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from naminter.core.models import (
    WMNMode,
    WMNResponse,
    WMNResult,
    WMNSite,
    WMNStatus,
    WMNSummary,
    WMNTestResult,
)


def test_wmn_result_from_response_all_mode_exists(
    minimal_site: WMNSite,
) -> None:
    response = WMNResponse(
        status_code=minimal_site["e_code"],
        text=f"welcome {minimal_site['e_string']} page",
        elapsed=timedelta(seconds=1),
        headers={"X-Test": "1"},
    )
    result = WMNResult.from_response(
        username="u",
        uri_check="https://example.com",
        uri_pretty=None,
        response=response,
        site=minimal_site,
        mode=WMNMode.ALL,
    )
    assert result.status == WMNStatus.EXISTS
    assert result.status_code == minimal_site["e_code"]


def test_wmn_result_from_response_conflicting(minimal_site: WMNSite) -> None:
    text = f"{minimal_site['e_string']} and {minimal_site['m_string']}"
    response = WMNResponse(
        status_code=minimal_site["e_code"],
        text=text,
        elapsed=timedelta(seconds=0),
    )
    result = WMNResult.from_response(
        username="u",
        uri_check="https://example.com",
        uri_pretty=None,
        response=response,
        site=minimal_site,
        mode=WMNMode.ANY,
    )
    assert result.status == WMNStatus.CONFLICTING


def test_wmn_result_from_response_exclude_text(minimal_site: WMNSite) -> None:
    response = WMNResponse(
        status_code=minimal_site["e_code"],
        text="body",
        elapsed=timedelta(seconds=0),
    )
    result = WMNResult.from_response(
        username="u",
        uri_check="https://example.com",
        uri_pretty=None,
        response=response,
        site=minimal_site,
        mode=WMNMode.ALL,
        exclude_text=True,
    )
    assert result.text is None


def test_wmn_result_to_dict_excludes_none() -> None:
    fixed = datetime(2020, 1, 1, tzinfo=UTC)
    result = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.MISSING,
        created_at=fixed,
    )
    d = result.to_dict(exclude_none=True)
    assert "uri_check" not in d
    assert d["status"] == "missing"
    assert d["created_at"] == fixed.isoformat()


def test_wmn_result_from_error(minimal_site: WMNSite) -> None:
    r = WMNResult.from_error(
        username="bob",
        message="timeout",
        site=minimal_site,
        uri_check="https://x",
    )
    assert r.status == WMNStatus.ERROR
    assert r.error == "timeout"
    assert r.uri_check == "https://x"


def test_wmn_result_from_not_valid(minimal_site: WMNSite) -> None:
    r = WMNResult.from_not_valid(
        username="bob",
        site=minimal_site,
    )
    assert r.status == WMNStatus.NOT_VALID


def test_wmn_response_json() -> None:
    r = WMNResponse(
        status_code=200,
        text='{"ok": true}',
        elapsed=timedelta(seconds=0),
    )
    assert r.json() == {"ok": True}


def test_wmn_summary_to_dict() -> None:
    s = WMNSummary(
        license=("MIT",),
        authors=("a",),
        site_names=("S",),
        sites_count=1,
        categories=("social",),
        categories_count=1,
        known_count=2,
    )
    d = s.to_dict()
    assert d["sites_count"] == 1
    assert d["license"] == ["MIT"]


def test_wmn_test_result_aggregate_single_status(minimal_site: WMNSite) -> None:
    inner = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[inner])
    assert tr.status == WMNStatus.EXISTS


def test_wmn_test_result_error_message(minimal_site: WMNSite) -> None:
    tr = WMNTestResult.from_site(minimal_site, error="failed")
    assert tr.status == WMNStatus.ERROR


def test_wmn_result_partial_exists(minimal_site: WMNSite) -> None:
    response = WMNResponse(
        status_code=minimal_site["e_code"],
        text="no expected substring",
        elapsed=timedelta(seconds=0),
    )
    result = WMNResult.from_response(
        username="u",
        uri_check="https://example.com",
        uri_pretty=None,
        response=response,
        site=minimal_site,
        mode=WMNMode.ALL,
    )
    assert result.status == WMNStatus.PARTIAL_EXISTS


def test_wmn_test_result_conflicting_aggregate(minimal_site: WMNSite) -> None:
    a = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    b = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.MISSING,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[a, b])
    assert tr.status == WMNStatus.CONFLICTING


def test_wmn_test_result_mixed_unknown_and_exists(minimal_site: WMNSite) -> None:
    a = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.UNKNOWN,
    )
    b = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[a, b])
    assert tr.status == WMNStatus.UNKNOWN


def test_wmn_test_result_to_dict_nested(minimal_site: WMNSite) -> None:
    inner = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[inner])
    d = tr.to_dict()
    assert d["status"] == "exists"
    assert len(d["results"]) == 1
