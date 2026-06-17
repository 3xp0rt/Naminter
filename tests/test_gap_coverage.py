"""Targeted tests for remaining coverage gaps."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch
import webbrowser

from click.testing import CliRunner
import orjson
import pytest
from rich.console import Console

from naminter.cli.config import NaminterConfig
from naminter.cli.exceptions import BrowserError, FileError
from naminter.cli.exporters import Exporter
from naminter.cli.main import NaminterCLI, cli_error_handler, main
from naminter.cli.utils import fetch_json, open_url, read_file, write_file
from naminter.core.exceptions import WMNSchemaError
from naminter.core.formatter import WMNFormatError, WMNFormatter
from naminter.core.main import Naminter
from naminter.core.models import (
    WMNData,
    WMNMode,
    WMNResponse,
    WMNResult,
    WMNSite,
    WMNStatus,
    WMNTestResult,
)
from naminter.core.validator import WMNValidator

if TYPE_CHECKING:
    from collections.abc import Callable


def test_display_errors_blank_title_uses_empty_root() -> None:
    from naminter.cli.console import display_errors
    from naminter.core.models import WMNError

    buf = StringIO()
    con = Console(file=buf, width=88, force_terminal=True, color_system=None)
    err = WMNError(path="p", data=None, message="m")
    with patch("naminter.cli.console.console", con):
        display_errors([err], title="")
    assert "m" in buf.getvalue()


def test_display_diff_non_special_line_style() -> None:
    from naminter.cli.console import display_diff

    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=True, color_system=None)
    with patch("naminter.cli.console.console", con):
        display_diff("a\nb\n", "a\nc\n", Path("f.txt"))
    out = buf.getvalue()
    assert out


@pytest.mark.asyncio
async def test_exporter_csv_type_error(tmp_path: Path) -> None:
    import csv

    from naminter.cli.exceptions import ExportError

    ex = Exporter()

    def boom(*_a: object, **_k: object) -> None:
        msg = "bad"
        raise TypeError(msg)

    with (
        patch.object(csv.DictWriter, "writerows", boom),
        pytest.raises(ExportError, match="CSV data error"),
    ):
        await ex.export(
            [
                WMNResult(
                    name="n",
                    category="c",
                    username="u",
                    status=WMNStatus.EXISTS,
                ),
            ],
            {"csv": tmp_path / "o.csv"},
        )


@pytest.mark.asyncio
async def test_read_file_unicode_and_os_error(tmp_path: Path) -> None:
    from naminter.cli.exceptions import FileError

    p = tmp_path / "x.txt"

    class _CM:
        async def __aenter__(self) -> _CM:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        async def read(self) -> str:
            msg = "utf-8"
            raise UnicodeDecodeError(msg, b"\xff", 0, 1, "invalid")

    with (
        patch("naminter.cli.utils.aiofiles.open", return_value=_CM()),
        pytest.raises(FileError, match="Encoding error"),
    ):
        await read_file(p)

    class _CM2:
        async def __aenter__(self) -> _CM2:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        async def read(self) -> str:
            msg = "io"
            raise OSError(msg)

    with (
        patch("naminter.cli.utils.aiofiles.open", return_value=_CM2()),
        pytest.raises(FileError, match="OS error reading"),
    ):
        await read_file(p)


@pytest.mark.asyncio
async def test_read_file_permission_error(tmp_path: Path) -> None:
    from naminter.cli.exceptions import FileError

    p = tmp_path / "a.txt"
    p.write_text("x", encoding="utf-8")
    with (
        patch("naminter.cli.utils.aiofiles.open", side_effect=PermissionError("nope")),
        pytest.raises(FileError, match="Permission denied"),
    ):
        await read_file(p)


@pytest.mark.asyncio
async def test_write_file_mkdir_and_encode_errors(tmp_path: Path) -> None:
    from naminter.cli.exceptions import FileError

    p = tmp_path / "a.txt"
    with (
        patch.object(Path, "mkdir", side_effect=FileExistsError("exists")),
        pytest.raises(FileError, match="Cannot create directory"),
    ):
        await write_file(p, "hi")

    with (
        patch.object(Path, "mkdir", side_effect=PermissionError("p")),
        pytest.raises(FileError, match="Permission denied creating directory"),
    ):
        await write_file(tmp_path / "b.txt", "x")

    with (
        patch.object(Path, "mkdir", side_effect=OSError("o")),
        pytest.raises(FileError, match="OS error creating directory"),
    ):
        await write_file(tmp_path / "c.txt", "x")

    p2 = tmp_path / "out.txt"
    with pytest.raises(FileError, match="Encoding error writing"):
        await write_file(p2, "\ud800")

    p3 = tmp_path / "osw.txt"

    class _WCM:
        async def __aenter__(self) -> _WCM:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        async def write(self, *_a: object) -> None:
            msg = "w"
            raise OSError(msg)

    with (
        patch("naminter.cli.utils.aiofiles.open", return_value=_WCM()),
        pytest.raises(FileError, match="OS error writing"),
    ):
        await write_file(p3, "text")


@pytest.mark.asyncio
async def test_write_file_empty_path_and_permission(tmp_path: Path) -> None:
    from naminter.cli.exceptions import FileError, ValidationError

    with pytest.raises(ValidationError):
        await write_file("", "x")

    p = tmp_path / "w.txt"
    with (
        patch("naminter.cli.utils.aiofiles.open", side_effect=PermissionError("n")),
        pytest.raises(FileError, match="Permission denied writing"),
    ):
        await write_file(p, "hi")


@pytest.mark.asyncio
async def test_fetch_json_bad_json_body() -> None:
    from naminter.cli.exceptions import NetworkError

    client = MagicMock()
    client.get = AsyncMock(
        return_value=WMNResponse(
            status_code=200,
            text="not-json",
            elapsed=timedelta(0),
        ),
    )
    with pytest.raises(NetworkError, match="Failed to parse JSON"):
        await fetch_json(client, "https://x")


@pytest.mark.asyncio
async def test_open_url_accepts_path(tmp_path: Path) -> None:
    f = tmp_path / "page.html"
    f.write_text("x", encoding="utf-8")

    async def to_thread(
        func: Callable[..., Any],
        /,
        *args: object,
        **kwargs: object,
    ) -> Any:
        return func(*args, **kwargs)

    with (
        patch("naminter.cli.utils.asyncio.to_thread", new=to_thread),
        patch("naminter.cli.utils.webbrowser.open", return_value=True),
    ):
        await open_url(f)


@pytest.mark.asyncio
async def test_open_url_path_empty_uri_and_browser_errors() -> None:
    from naminter.cli.exceptions import BrowserError, ValidationError

    with pytest.raises(ValidationError):
        await open_url("   ")

    async def to_thread_browser_err(
        func: Callable[..., Any],
        /,
        *args: object,
        **kwargs: object,
    ) -> Any:
        msg = "b"
        raise webbrowser.Error(msg)

    with (
        patch("naminter.cli.utils.asyncio.to_thread", new=to_thread_browser_err),
        pytest.raises(BrowserError, match="Browser error"),
    ):
        await open_url("https://z")

    async def to_thread_os_err(
        func: Callable[..., Any],
        /,
        *args: object,
        **kwargs: object,
    ) -> Any:
        msg = "o"
        raise OSError(msg)

    with (
        patch("naminter.cli.utils.asyncio.to_thread", new=to_thread_os_err),
        pytest.raises(BrowserError, match="OS error opening browser"),
    ):
        await open_url("https://z")


def test_wmn_result_missing_and_partial_missing(
    minimal_site: WMNSite,
) -> None:
    r = WMNResponse(
        status_code=minimal_site["m_code"],
        text=f"body {minimal_site['m_string']}",
        elapsed=timedelta(0),
    )
    m = WMNResult.from_response(
        username="u",
        uri_check="https://x",
        uri_pretty=None,
        response=r,
        site=minimal_site,
        mode=WMNMode.ALL,
    )
    assert m.status == WMNStatus.MISSING

    r2 = WMNResponse(
        status_code=minimal_site["m_code"],
        text="x",
        elapsed=timedelta(0),
    )
    pm = WMNResult.from_response(
        username="u",
        uri_check="https://x",
        uri_pretty=None,
        response=r2,
        site=minimal_site,
        mode=WMNMode.ALL,
    )
    assert pm.status == WMNStatus.PARTIAL_MISSING


def test_wmn_test_result_error_status_and_partial_missing_agg(
    minimal_site: WMNSite,
) -> None:
    a = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.ERROR,
    )
    b = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[a, b])
    assert tr.status == WMNStatus.ERROR

    u = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.UNKNOWN,
    )
    pm = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.PARTIAL_MISSING,
    )
    tr2 = WMNTestResult.from_site(minimal_site, results=[u, pm])
    assert tr2.status == WMNStatus.PARTIAL_MISSING


def test_validator_preview_failure() -> None:
    class Unserializable:
        def __repr__(self) -> str:
            return "U"

    with patch("naminter.core.validator.orjson.dumps", side_effect=TypeError("nope")):
        assert WMNValidator._preview(Unserializable()) is None


def test_validator_init_wraps_generic_exception() -> None:
    with (
        patch(
            "naminter.core.validator.validator_for", side_effect=RuntimeError("weird")
        ),
        pytest.raises(WMNSchemaError, match="Failed to initialize"),
    ):
        WMNValidator({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
        })


def test_formatter_branches(
    formatter_schema: dict[str, Any],
    minimal_data: WMNData,
) -> None:
    fmt = WMNFormatter(formatter_schema)
    with pytest.raises(WMNFormatError):
        fmt.format_data({**minimal_data, "authors": "bad"})
    with pytest.raises(WMNFormatError):
        fmt.format_data({**minimal_data, "authors": []})
    with pytest.raises(WMNFormatError):
        fmt.format_data({**minimal_data, "authors": [1]})
    with pytest.raises(WMNFormatError):
        fmt.format_data({**minimal_data, "authors": [" "]})

    bad_schema = {
        "properties": {"sites": {"items": {"properties": {"name": {"type": "string"}}}}}
    }
    bf = WMNFormatter(bad_schema)
    with pytest.raises(WMNFormatError):
        bf.format_data({
            **minimal_data,
            "sites": [{"extra_unknown": 1, "name": "n"}],
        })


@pytest.mark.asyncio
async def test_naminter_bad_schema_in_constructor() -> None:
    http = MagicMock()
    bad_schema = {"$schema": "http://json-schema.org/draft-07/schema#", "type": 123}
    with pytest.raises(WMNSchemaError):
        Naminter(http, None, bad_schema)


@pytest.mark.asyncio
async def test_naminter_enumerate_strip_bad_char_invalid(
    http_session: MagicMock,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
    minimal_site: WMNSite,
) -> None:
    bad_site = {**minimal_site, "strip_bad_char": 42}
    async with Naminter(http_session, minimal_data, minimal_json_schema) as n:
        r = await n.enumerate_site(bad_site, "u")  # type: ignore[arg-type]
    assert r.status == WMNStatus.ERROR


class _FakeCurlCM:
    def __init__(self, *a: object, **k: object) -> None:
        pass

    async def __aenter__(self) -> MagicMock:
        return MagicMock()

    async def __aexit__(self, *a: object) -> None:
        pass


def _sync_uv(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_cli_run_remote_data_not_dict(
    tmp_path: Path,
    minimal_json_schema: dict[str, Any],
) -> None:
    schema_path = tmp_path / "s.json"
    schema_path.write_bytes(orjson.dumps(minimal_json_schema))

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **k: object) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(sites_count=0, known_count=0)

    c = NaminterConfig(
        usernames=["a"],
        remote_data="https://x",
        local_schema=schema_path,
        no_progressbar=True,
    )
    from naminter.cli.exceptions import FileError

    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.fetch_json", new_callable=AsyncMock, return_value=[]),
    ):
        cli = NaminterCLI(c)
        with pytest.raises(FileError, match="Remote data must be a JSON object"):
            await cli.run()


@pytest.mark.asyncio
async def test_cli_run_remote_schema_not_dict(
    tmp_path: Path,
    minimal_data: WMNData,
) -> None:
    data_path = tmp_path / "d.json"
    data_path.write_bytes(orjson.dumps(minimal_data))

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

    c = NaminterConfig(
        usernames=["a"],
        local_data=data_path,
        remote_schema="https://schema",
        no_progressbar=True,
    )
    from naminter.cli.exceptions import FileError

    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.fetch_json", new_callable=AsyncMock, return_value=[]),
    ):
        cli = NaminterCLI(c)
        with pytest.raises(FileError, match="Remote schema must be a JSON object"):
            await cli.run()


def test_cli_error_handler_data_errors_branch() -> None:
    import click

    from naminter.core.exceptions import WMNValidationError
    from naminter.core.models import WMNError

    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        msg = "bad"
        raise WMNValidationError(
            msg,
            data_errors=[WMNError(path="p", data="d", message="m")],
        )

    runner = CliRunner()
    with patch("naminter.cli.main.display_errors"):
        r = runner.invoke(_cmd, [])
    assert r.exit_code == 1


@pytest.mark.asyncio
async def test_setup_response_dir_oserror_on_mkdir() -> None:
    c = NaminterConfig(usernames=["a"], save_response=True)
    with patch.object(Path, "mkdir", side_effect=OSError("fs")):
        with patch("naminter.cli.main.display_warning") as dw:
            cli = NaminterCLI(c)
        assert cli._response_dir is None
        dw.assert_called()


def test_setup_logging_removes_previous_file_handlers(tmp_path: Path) -> None:
    logf = tmp_path / "a.log"
    c = NaminterConfig(usernames=["a"], log_file=str(logf))
    NaminterCLI.setup_logging(c)
    NaminterCLI.setup_logging(c)


@pytest.mark.asyncio
async def test_run_remote_schema_fetch_not_dict(
    tmp_path: Path,
    minimal_data: WMNData,
) -> None:
    data_path = tmp_path / "d.json"
    data_path.write_bytes(orjson.dumps(minimal_data))

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

    c = NaminterConfig(
        usernames=["a"],
        local_data=data_path,
        remote_schema="https://schema-only",
        no_progressbar=True,
    )
    from naminter.cli.exceptions import FileError

    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.fetch_json", new_callable=AsyncMock, return_value=[]),
    ):
        cli = NaminterCLI(c)
        with pytest.raises(FileError, match="Remote schema must be a JSON object"):
            await cli.run()


@pytest.mark.asyncio
async def test_run_check_format_result_raises_file_error(
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

        def summary(self, **kwargs: object) -> Any:
            from types import SimpleNamespace

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
    )
    from naminter.cli.exceptions import FileError

    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
        patch.object(
            __import__(
                "naminter.cli.console",
                fromlist=["ResultFormatter"],
            ).ResultFormatter,
            "format_result",
            side_effect=FileError("fmt"),
        ),
        patch("naminter.cli.main.display_error") as de,
    ):
        cli = NaminterCLI(c)
        await cli.run()
    de.assert_called()


@pytest.mark.asyncio
async def test_run_validation_early_exit_zero_tests(
    wmn_files: tuple[Path, Path],
) -> None:
    data_path, schema_path = wmn_files

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(sites_count=1, known_count=0)

    c = NaminterConfig(
        usernames=["a"],
        test=True,
        local_data=data_path,
        local_schema=schema_path,
        no_progressbar=True,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        cli = NaminterCLI(c)
        await cli.run()


@pytest.mark.asyncio
async def test_run_validation_format_raises(
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

        def summary(self, **kwargs: object) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(sites_count=1, known_count=1)

        async def test_enumeration(self, **kwargs: object):
            inner = WMNResult(
                name=minimal_site["name"],
                category=minimal_site["cat"],
                username="alice",
                status=WMNStatus.EXISTS,
            )
            yield WMNTestResult.from_site(minimal_site, results=[inner])

    c = NaminterConfig(
        usernames=["a"],
        test=True,
        local_data=data_path,
        local_schema=schema_path,
        no_progressbar=True,
        filter_all=True,
    )
    from naminter.cli.exceptions import FileError

    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
        patch.object(
            __import__(
                "naminter.cli.console",
                fromlist=["ResultFormatter"],
            ).ResultFormatter,
            "format_validation",
            side_effect=FileError("fmt"),
        ),
        patch("naminter.cli.main.display_error") as de,
    ):
        cli = NaminterCLI(c)
        await cli.run()
    de.assert_called()


@pytest.mark.asyncio
async def test_open_in_browser_response_file_browser_error(tmp_path: Path) -> None:
    c = NaminterConfig(usernames=["a"], open_response=True)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
    )
    p = tmp_path / "a.html"
    p.write_text("x", encoding="utf-8")
    with (
        patch("naminter.cli.main.open_url", new_callable=AsyncMock) as ou,
        patch("naminter.cli.main.display_error") as de,
    ):
        ou.side_effect = BrowserError("x")
        await cli._open_in_browser(r, p)
    de.assert_called()


@pytest.mark.asyncio
async def test_save_response_write_failure_displays_error(tmp_path: Path) -> None:
    rd = tmp_path / "r"
    rd.mkdir()
    c = NaminterConfig(usernames=["a"], save_response=True, response_dir=rd)
    cli = NaminterCLI(c)
    r = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.EXISTS,
        text="body",
    )
    with (
        patch("naminter.cli.main.write_file", new_callable=AsyncMock) as wf,
        patch("naminter.cli.main.display_error") as de,
    ):
        wf.side_effect = FileError("w")
        out = await cli._save_response(r)
    assert out is None
    de.assert_called()


@pytest.mark.asyncio
async def test_run_loads_remote_schema_dict(
    tmp_path: Path,
    minimal_data: WMNData,
    minimal_json_schema: dict[str, Any],
) -> None:
    data_path = tmp_path / "d.json"
    data_path.write_bytes(orjson.dumps(minimal_data))

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **kwargs: object) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(sites_count=0, known_count=0)

    c = NaminterConfig(
        usernames=["a"],
        local_data=data_path,
        local_schema=None,
        remote_schema="https://example.com/wmn-data-schema.json",
        no_progressbar=True,
    )
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch(
            "naminter.cli.main.fetch_json",
            new_callable=AsyncMock,
            return_value=minimal_json_schema,
        ),
        patch("naminter.cli.main.console.print"),
    ):
        cli = NaminterCLI(c)
        await cli.run()


def test_cli_error_handler_schema_errors_branch() -> None:
    import click

    from naminter.core.exceptions import WMNValidationError

    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        from naminter.core.models import WMNError

        msg = "bad"
        raise WMNValidationError(
            msg,
            schema_errors=[WMNError(path="p", data="d", message="m")],
        )

    runner = CliRunner()
    with patch("naminter.cli.main.display_errors"):
        r = runner.invoke(_cmd, [])
    assert r.exit_code == 1


def test_cli_error_handler_invoked_directly_covers_display_paths() -> None:
    import naminter.cli.main as cli_main
    from naminter.core.models import WMNError

    ctx = MagicMock()
    ctx.exit.side_effect = SystemExit(1)

    @cli_error_handler
    def _inner(c: object) -> None:
        msg = "bad"
        raise cli_main.WMNValidationError(
            msg,
            schema_errors=[WMNError(path="s", data=None, message="sm")],
            data_errors=[WMNError(path="d", data=None, message="dm")],
        )

    with (
        patch("naminter.cli.main.display_error") as de,
        patch("naminter.cli.main.display_errors") as des,
        pytest.raises(SystemExit),
    ):
        _inner(ctx)
    de.assert_called()
    assert des.call_count >= 2


def test_cli_error_handler_schema_and_data_errors() -> None:
    import click

    from naminter.core.exceptions import WMNValidationError
    from naminter.core.models import WMNError

    @click.command()
    @click.pass_context
    @cli_error_handler
    def _cmd(ctx: click.Context) -> None:
        msg = "bad"
        raise WMNValidationError(
            msg,
            schema_errors=[WMNError(path="s", data=None, message="sm")],
            data_errors=[WMNError(path="d", data=None, message="dm")],
        )

    runner = CliRunner()
    with patch("naminter.cli.main.display_errors"):
        r = runner.invoke(_cmd, [])
    assert r.exit_code == 1


def test_validate_no_color(wmn_files: tuple[Path, Path]) -> None:
    data_path, schema_path = wmn_files
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.console.print"),
    ):
        r1 = runner.invoke(
            main,
            [
                "validate",
                "--no-color",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r1.exit_code == 0


def test_format_no_color(
    tmp_path: Path,
    formatter_schema: dict[str, Any],
    minimal_data: WMNData,
) -> None:
    schema_path = tmp_path / "wmn-data-schema.json"
    data_path = tmp_path / "wmn-data.json"
    schema_path.write_bytes(orjson.dumps(formatter_schema))
    data_path.write_bytes(orjson.dumps(minimal_data))
    runner = CliRunner()
    with patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv):
        r = runner.invoke(
            main,
            [
                "format",
                "--no-color",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
            ],
        )
    assert r.exit_code == 0


def test_format_command_invalid_schema_json(
    tmp_path: Path, wmn_files: tuple[Path, Path]
) -> None:
    data_path, _schema_ok = wmn_files
    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text("{", encoding="utf-8")
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.display_error") as de,
    ):
        r = runner.invoke(
            main,
            [
                "format",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(bad_schema),
            ],
        )
    assert r.exit_code == 1
    de.assert_called()


def test_format_command_writes_when_output_differs(
    tmp_path: Path,
    formatter_schema: dict[str, Any],
    minimal_data: WMNData,
) -> None:
    schema_path = tmp_path / "wmn-data-schema.json"
    data_path = tmp_path / "wmn-data.json"
    schema_path.write_bytes(orjson.dumps(formatter_schema))
    data_path.write_bytes(orjson.dumps(minimal_data))
    ds = data_path.read_text(encoding="utf-8")
    sc = schema_path.read_text(encoding="utf-8")
    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.WMNFormatter") as mock_fmt,
        patch("naminter.cli.main.write_file", new_callable=AsyncMock) as wf,
        patch("naminter.cli.main.display_diff") as dd,
    ):
        inst = MagicMock()
        inst.format_data.return_value = ds + "\n"
        inst.format_schema.return_value = sc + "\n"
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
    assert wf.await_count >= 1
    assert dd.call_count >= 1


def test_wmn_result_determine_unknown() -> None:
    assert (
        WMNResult._determine_status(
            condition_exists=False,
            condition_missing=False,
            partial_exists=False,
            partial_missing=False,
        )
        == WMNStatus.UNKNOWN
    )


def test_wmn_test_result_partial_exists_over_unknown(
    minimal_site: WMNSite,
) -> None:
    u = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.UNKNOWN,
    )
    pe = WMNResult(
        name="n",
        category="c",
        username="u",
        status=WMNStatus.PARTIAL_EXISTS,
    )
    tr = WMNTestResult.from_site(minimal_site, results=[u, pe])
    assert tr.status == WMNStatus.PARTIAL_EXISTS


def test_main_no_color_flag(wmn_files: tuple[Path, Path]) -> None:
    data_path, schema_path = wmn_files

    class _FN:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        async def __aenter__(self) -> _FN:
            return self

        async def __aexit__(self, *a: object) -> None:
            pass

        def summary(self, **k: object) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(sites_count=0, known_count=0)

    runner = CliRunner()
    with (
        patch("naminter.cli.main.uvloop.run", side_effect=_sync_uv),
        patch("naminter.cli.main.CurlCFFISession", _FakeCurlCM),
        patch("naminter.cli.main.Naminter", _FN),
        patch("naminter.cli.main.console.print"),
    ):
        r = runner.invoke(
            main,
            [
                "--no-color",
                "--username",
                "a",
                "--local-data",
                str(data_path),
                "--local-schema",
                str(schema_path),
                "--no-progressbar",
            ],
        )
    assert r.exit_code == 0
