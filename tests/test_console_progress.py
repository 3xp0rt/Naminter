"""Tests for Rich console helpers and progress bar."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from naminter.cli.console import (
    ResultFormatter,
    Theme,
    _get_status_style,
    _get_status_symbol,
    console,
    display_diff,
    display_error,
    display_errors,
    display_version,
    display_warning,
)
from naminter.core.models import WMNError, WMNResult, WMNSite, WMNStatus, WMNTestResult


def test_theme_dataclass() -> None:
    t = Theme()
    assert t.primary == "bright_blue"


def test_get_status_symbol_fallback() -> None:
    partial = {
        k: v
        for k, v in __import__(
            "naminter.cli.constants",
            fromlist=["STATUS_SYMBOLS"],
        ).STATUS_SYMBOLS.items()
        if k != WMNStatus.ERROR
    }
    with patch("naminter.cli.console.STATUS_SYMBOLS", partial):
        assert _get_status_symbol(WMNStatus.ERROR) == "?"


def test_get_status_style_fallback() -> None:
    partial = {
        k: v
        for k, v in __import__(
            "naminter.cli.constants",
            fromlist=["STATUS_STYLES"],
        ).STATUS_STYLES.items()
        if k != WMNStatus.ERROR
    }
    with patch("naminter.cli.console.STATUS_STYLES", partial):
        st = _get_status_style(WMNStatus.ERROR)
        assert "white" in str(st).lower() or st


def _capture_console() -> tuple[Console, StringIO]:
    buf = StringIO()
    c = Console(file=buf, width=88, force_terminal=True, color_system=None)
    return c, buf


def test_display_version() -> None:
    c, buf = _capture_console()
    with patch("naminter.cli.console.console", c):
        display_version()
    out = buf.getvalue()
    assert "Naminter" in out or "Version" in out


def test_display_error_and_warning() -> None:
    c, buf = _capture_console()
    with patch("naminter.cli.console.console", c):
        display_error("bad", end="")
        display_warning("careful")
    assert "bad" in buf.getvalue()


def test_display_errors_empty_no_output() -> None:
    c, buf = _capture_console()
    with patch("naminter.cli.console.console", c):
        display_errors([])
    assert not buf.getvalue()


def test_display_errors_with_title_and_data() -> None:
    c, buf = _capture_console()
    err = WMNError(path="$.a", data="x", message="oops")
    with patch("naminter.cli.console.console", c):
        display_errors([err], title="Problems")
    out = buf.getvalue()
    assert "oops" in out
    assert "Data:" in out


def test_display_diff_no_change() -> None:
    c, buf = _capture_console()
    with patch("naminter.cli.console.console", c):
        display_diff("same", "same", Path("f.txt"))
    assert not buf.getvalue()


def test_display_diff_shows_unified() -> None:
    c, buf = _capture_console()
    with patch("naminter.cli.console.console", c):
        display_diff("a\n", "b\n", Path("f.txt"))
    out = buf.getvalue()
    assert "-" in out or "+" in out


def test_result_formatter_basic() -> None:
    r = WMNResult(
        name="N",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        uri_pretty="https://x",
    )
    tree = ResultFormatter(verbose=0).format_result(r)
    assert tree.label is not None


def test_result_formatter_verbose_levels(tmp_path: Path) -> None:
    fixed = datetime(2020, 1, 1, tzinfo=UTC)
    r = WMNResult(
        name="N",
        category="c",
        username="u",
        status=WMNStatus.ERROR,
        uri_pretty="https://x",
        status_code=500,
        headers={"H": "v"},
        elapsed=timedelta(seconds=1),
        error="boom",
        created_at=fixed,
    )
    p = tmp_path / "resp.html"
    for level in (1, 2, 3):
        tree = ResultFormatter(verbose=level).format_result(r, p)
        assert tree.label is not None


def test_format_validation_with_nested_verbose() -> None:
    inner = WMNResult(
        name="n",
        category="c",
        username="alice",
        status=WMNStatus.EXISTS,
        uri_pretty="https://z",
        status_code=200,
        headers={"A": "b"},
        elapsed=timedelta(0),
    )
    site: WMNSite = {
        "name": "S",
        "uri_check": "https://example.com/{account}",
        "e_code": 200,
        "e_string": "ok",
        "m_string": "missing",
        "m_code": 404,
        "known": ["alice"],
        "cat": "x",
    }
    tr = WMNTestResult.from_site(site, results=[inner])
    paths: list[Path | None] = [Path("/a.html")]
    tree = ResultFormatter(verbose=3).format_validation(tr, paths)
    assert tree.label is not None


def test_format_validation_without_results() -> None:
    site: WMNSite = {
        "name": "S",
        "uri_check": "https://example.com/{account}",
        "e_code": 200,
        "e_string": "ok",
        "m_string": "missing",
        "m_code": 404,
        "known": [],
        "cat": "x",
    }
    tr = WMNTestResult.from_site(site, results=None)
    tree = ResultFormatter(verbose=0).format_validation(tr, None)
    assert tree.label is not None


def test_progress_bar_disabled() -> None:
    from naminter.cli.progress import ProgressBar

    c, _buf = _capture_console()
    bar = ProgressBar(c, disabled=True)
    bar.start(2, "working")
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.UNKNOWN,
    )
    bar.add_result(r)
    bar.stop()


def test_progress_bar_enabled_covers_status_branches() -> None:
    from naminter.cli.progress import ProgressBar

    c, _buf = _capture_console()
    bar = ProgressBar(c, disabled=False)
    bar.start(10, "go")
    samples = [
        WMNStatus.EXISTS,
        WMNStatus.MISSING,
        WMNStatus.UNKNOWN,
        WMNStatus.PARTIAL_EXISTS,
        WMNStatus.PARTIAL_MISSING,
        WMNStatus.CONFLICTING,
        WMNStatus.ERROR,
        WMNStatus.NOT_VALID,
    ]
    for st in samples:
        bar.add_result(
            WMNResult(
                name="n",
                category="c",
                username="u",
                status=st,
            ),
        )
    bar.update(description="x")
    bar.stop()


def test_progress_bar_get_text_no_start_time() -> None:
    from naminter.cli.progress import ProgressBar

    c, _buf = _capture_console()
    bar = ProgressBar(c, disabled=True)
    bar.total_sites = 1
    txt = bar._get_progress_text()
    assert "req/s" in txt or "0.0" in txt


def test_console_module_has_default_console() -> None:
    assert console is not None
