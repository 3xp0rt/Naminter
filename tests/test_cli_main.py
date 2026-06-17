"""Tests for naminter.cli.main (Click entry, NaminterCLI, error handler)."""

from __future__ import annotations

import asyncio
import logging
from logging import FileHandler
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import click
from click.testing import CliRunner
import orjson
import pytest

from naminter.cli.config import NaminterConfig
from naminter.cli.exceptions import BrowserError
from naminter.cli.main import NaminterCLI, cli_error_handler, entry_point, main
from naminter.core.exceptions import WMNValidationError
from naminter.core.models import (
    WMNError,
    WMNResult,
    WMNSite,
    WMNStatus,
    WMNTestResult,
)


def _sync_uvloop(coro: Any) -> Any:
    return asyncio.run(coro)


class _FakeCurlCM:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def __aenter__(self) -> MagicMock:
        return MagicMock()

    async def __aexit__(self, *args: object) -> None:
        pass


def test_entry_point_invokes_main() -> None:
    with patch("naminter.cli.main.main") as m:
        entry_point()
    m.assert_called_once()


def test_naminter_cli_filter_result_respects_filters() -> None:
    c = NaminterConfig(usernames=["a"], filter_all=True)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.MISSING,
    )
    assert cli._filter_result(r) is True

    c2 = NaminterConfig(usernames=["a"], filter_exists=True, filter_missing=False)
    cli2 = NaminterCLI(c2)
    assert cli2._filter_result(r) is False


@pytest.mark.asyncio
async def test_save_response_skips_without_text_or_dir() -> None:
    c = NaminterConfig(usernames=["a"], save_response=True)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        text=None,
    )
    assert await cli._save_response(r) is None


@pytest.mark.asyncio
async def test_save_response_writes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rd = tmp_path / "resp"
    rd.mkdir()
    c = NaminterConfig(usernames=["a"], save_response=True, response_dir=rd)
    monkeypatch.setattr(
        "naminter.cli.main.NaminterCLI._setup_response_dir", lambda _self: rd
    )
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        text="<html/>",
    )
    out = await cli._save_response(r)
    assert out is not None
    assert out.read_text(encoding="utf-8") == "<html/>"


@pytest.mark.asyncio
async def test_open_in_browser_browse_and_response_paths(tmp_path: Path) -> None:
    c = NaminterConfig(usernames=["a"], browse=True, open_response=True)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        uri_pretty="https://example.com",
    )
    p = tmp_path / "fake.html"
    with patch("naminter.cli.main.open_url", new_callable=AsyncMock) as ou:
        await cli._open_in_browser(r, p)
    assert ou.await_count == 2


@pytest.mark.asyncio
async def test_open_in_browser_swallows_browser_error() -> None:
    c = NaminterConfig(usernames=["a"], browse=True)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        uri_pretty="https://example.com",
    )
    with (
        patch("naminter.cli.main.open_url", new_callable=AsyncMock) as ou,
        patch("naminter.cli.main.display_error") as de,
    ):
        ou.side_effect = BrowserError("no browser")
        await cli._open_in_browser(r, None)
    de.assert_called()


@pytest.mark.asyncio
async def test_run_check_records_result(
    wmn_files: tuple[Path, Path],
    minimal_site: dict[str, Any],
) -> None:
    data_path, schema_path = wmn_files

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(sites_count=1, known_count=1)

        async def enumerate_usernames(self, **kwargs: object):
            yield WMNResult(
                name=minimal_site["name"],
                category=minimal_site["cat"],
                username="alice",
                status=WMNStatus.EXISTS,
                uri_pretty="https://e.test",
            )

        async def test_enumeration(self, **kwargs: object):
            if False:
                yield  # pragma: no cover

    c = NaminterConfig(
        usernames=["alice"],
        local_data=data_path,
        local_schema=schema_path,
        no_progressbar=True,
        filter_all=True,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        cli = NaminterCLI(c)
        await cli.run()


@pytest.mark.asyncio
async def test_run_validation_path(
    wmn_files: tuple[Path, Path],
    minimal_site: WMNSite,
) -> None:
    data_path, schema_path = wmn_files

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(sites_count=1, known_count=1)

        async def enumerate_usernames(self, **kwargs: object):
            if False:
                yield  # pragma: no cover

        async def test_enumeration(self, **kwargs: object):
            inner = WMNResult(
                name=minimal_site["name"],
                category=minimal_site["cat"],
                username="alice",
                status=WMNStatus.EXISTS,
            )
            yield WMNTestResult.from_site(minimal_site, results=[inner])

    c = NaminterConfig(
        usernames=["alice"],
        test=True,
        local_data=data_path,
        local_schema=schema_path,
        no_progressbar=True,
        filter_all=True,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        cli = NaminterCLI(c)
        await cli.run()


@pytest.mark.asyncio
async def test_run_with_exports_calls_exporter(
    wmn_files: tuple[Path, Path],
    minimal_site: dict[str, Any],
    tmp_path: Path,
) -> None:
    data_path, schema_path = wmn_files
    out_csv = tmp_path / "out.csv"

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(sites_count=1, known_count=1)

        async def enumerate_usernames(self, **kwargs: object):
            yield WMNResult(
                name=minimal_site["name"],
                category=minimal_site["cat"],
                username="alice",
                status=WMNStatus.EXISTS,
                uri_pretty="https://e.test",
            )

    c = NaminterConfig(
        usernames=["alice"],
        local_data=data_path,
        local_schema=schema_path,
        no_progressbar=True,
        filter_all=True,
        csv_export=True,
        csv_path=out_csv,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        cli = NaminterCLI(c)
        await cli.run()
    assert out_csv.exists()


@pytest.mark.asyncio
async def test_run_remote_data_branch(
    tmp_path: Path,
    minimal_data: dict[str, Any],
    minimal_json_schema: dict[str, Any],
    minimal_site: dict[str, Any],
) -> None:
    schema_path = tmp_path / "wmn-data-schema.json"
    schema_path.write_bytes(orjson.dumps(minimal_json_schema))

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(sites_count=0, known_count=0)

        async def enumerate_usernames(self, **kwargs: object):
            if False:
                yield  # pragma: no cover

    async def fake_fetch(_client: object, url: str) -> dict[str, Any]:
        assert "http" in url
        return minimal_data

    c = NaminterConfig(
        usernames=["alice"],
        remote_data="https://example.com/wmn.json",
        local_schema=schema_path,
        no_progressbar=True,
        filter_all=True,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.fetch_json", new_callable=AsyncMock) as ff,
        patch("naminter.cli.main.console.print"),
    ):
        ff.side_effect = fake_fetch
        cli = NaminterCLI(c)
        await cli.run()


def test_setup_logging_writes_file(tmp_path: Path) -> None:
    logf = tmp_path / "a.log"
    c = NaminterConfig(usernames=["a"], log_file=str(logf), log_level="INFO")
    NaminterCLI.setup_logging(c)
    logging.getLogger("naminter").info("x")
    assert logf.read_text(encoding="utf-8")


def test_setup_logging_mkdir_failure(tmp_path: Path) -> None:
    logf = tmp_path / "d/a.log"
    with patch.object(Path, "mkdir", side_effect=PermissionError("nope")):
        c = NaminterConfig(usernames=["a"], log_file=str(logf))
        with pytest.raises(OSError, match="Failed to create log directory"):
            NaminterCLI.setup_logging(c)


def test_setup_logging_file_handler_failure(tmp_path: Path) -> None:
    class _Boom(FileHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            msg = "nope"
            raise OSError(msg)

    logf = tmp_path / "a.log"
    logf.parent.mkdir(parents=True, exist_ok=True)
    with patch("naminter.cli.main.logging.FileHandler", _Boom):
        c = NaminterConfig(usernames=["a"], log_file=str(logf))
        with pytest.raises(OSError, match="Failed to create log file"):
            NaminterCLI.setup_logging(c)


def test_setup_response_dir_permission_error(tmp_path: Path) -> None:
    c = NaminterConfig(
        usernames=["a"],
        save_response=True,
        response_dir=tmp_path / "responses",
    )
    with (
        patch.object(Path, "mkdir", side_effect=PermissionError("nope")),
        patch("naminter.cli.main.display_warning") as dw,
    ):
        cli = NaminterCLI(c)
    assert cli._response_dir is None
    dw.assert_called()


def test_cli_main_invocation_smoke(wmn_files: tuple[Path, Path]) -> None:
    data_path, schema_path = wmn_files

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(sites_count=0, known_count=0)

        async def enumerate_usernames(self, **kwargs: object):
            if False:
                yield  # pragma: no cover

    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        r = runner.invoke(
            main,
            [
                "--username",
                "alice",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
                "--no-progressbar",
                "--filter-all",
            ],
        )
    assert r.exit_code == 0


def test_validate_command_ok(wmn_files: tuple[Path, Path]) -> None:
    data_path, schema_path = wmn_files
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.console.print"),
    ):
        r = runner.invoke(
            main,
            [
                "validate",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r.exit_code == 0


def test_validate_command_errors_exit(wmn_files: tuple[Path, Path]) -> None:
    _, schema_path = wmn_files
    bad = schema_path.parent / "bad.json"
    bad.write_bytes(orjson.dumps({"license": "not-list"}))
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.display_errors"),
        patch("naminter.cli.main.console.print"),
    ):
        r = runner.invoke(
            main,
            [
                "validate",
                "--local-data",
                str(bad),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r.exit_code == 1


def test_format_command_runs(wmn_files: tuple[Path, Path]) -> None:
    data_path, schema_path = wmn_files
    ds = data_path.read_text(encoding="utf-8")
    sc = schema_path.read_text(encoding="utf-8")
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.display_diff"),
        patch("naminter.cli.main.WMNFormatter") as mock_fmt,
    ):
        inst = MagicMock()
        inst.format_data.return_value = ds
        inst.format_schema.return_value = sc
        mock_fmt.return_value = inst
        r = runner.invoke(
            main,
            [
                "format",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r.exit_code == 0


def test_format_command_invalid_json(
    tmp_path: Path, wmn_files: tuple[Path, Path]
) -> None:
    _, schema_path = wmn_files
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uvloop),
        patch("naminter.cli.main.display_error") as de,
    ):
        r = runner.invoke(
            main,
            [
                "format",
                "--local-data",
                str(bad),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r.exit_code == 1
    de.assert_called()


def test_cli_error_handler_validation_error() -> None:
    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        msg = "bad"
        raise WMNValidationError(
            msg,
            schema_errors=[WMNError(path="$.x", data="d", message="msg")],
        )

    runner = CliRunner()
    with patch("naminter.cli.main.display_errors"):
        r = runner.invoke(_cmd, [])
    assert r.exit_code == 1


def test_cli_error_handler_keyboard_interrupt() -> None:
    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        raise KeyboardInterrupt

    runner = CliRunner()
    r = runner.invoke(_cmd, [])
    assert r.exit_code == 130


def test_cli_error_handler_unexpected() -> None:
    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        msg = "boom"
        raise RuntimeError(msg)

    runner = CliRunner()
    r = runner.invoke(_cmd, [])
    assert r.exit_code == 1
