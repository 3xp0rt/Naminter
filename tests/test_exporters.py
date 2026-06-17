"""Tests for naminter.cli.exporters.Exporter."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import jinja2
import orjson
import pytest

from naminter.cli.exceptions import ExportError, FileError
from naminter.cli.exporters import Exporter
import naminter.core.models as core_models
from naminter.core.models import WMNResult, WMNStatus

if TYPE_CHECKING:
    from collections.abc import Sequence


def _one_result() -> WMNResult:
    return core_models.WMNResult(
        name="Site",
        category="social",
        username="u",
        status=WMNStatus.EXISTS,
        status_code=200,
        uri_pretty="https://example.com/u",
    )


@pytest.mark.asyncio
async def test_export_raises_when_no_results(tmp_path: Path) -> None:
    ex = Exporter()
    with pytest.raises(ExportError, match="No results to export"):
        await ex.export([], {"csv": tmp_path / "o.csv"})


@pytest.mark.asyncio
async def test_export_raises_when_to_dict_fails() -> None:
    ex = Exporter()
    bad = MagicMock()
    bad.to_dict = MagicMock(side_effect=TypeError("nope"))
    with pytest.raises(ExportError, match="Failed to convert results"):
        await ex.export([bad], {"csv": Path("x.csv")})


@pytest.mark.asyncio
async def test_export_csv_json_html_pdf(tmp_path: Path) -> None:
    ex = Exporter(usernames=["u"])
    r = _one_result()
    out_csv = tmp_path / "a.csv"
    out_json = tmp_path / "a.json"
    out_html = tmp_path / "a.html"
    out_pdf = tmp_path / "a.pdf"
    fmts = {
        "csv": out_csv,
        "json": out_json,
        "html": out_html,
        "pdf": out_pdf,
    }
    await ex.export([r], fmts)
    assert out_csv.read_text(encoding="utf-8")
    assert orjson.loads(out_json.read_text(encoding="utf-8"))
    assert "<html" in out_html.read_text(encoding="utf-8").lower()
    assert out_pdf.stat().st_size > 0


@pytest.mark.asyncio
async def test_export_csv_no_fieldnames_raises(tmp_path: Path) -> None:
    ex = Exporter()

    class EmptyDictResult:
        def to_dict(self, **_kwargs: object) -> dict[str, Any]:
            return {}

    with pytest.raises(ExportError, match="no fields found"):
        await ex.export(
            [EmptyDictResult()],  # type: ignore[list-item]
            {"csv": tmp_path / "o.csv"},
        )


@pytest.mark.asyncio
async def test_export_csv_wraps_file_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
        wf.side_effect = FileError("denied")
        with pytest.raises(ExportError, match="File access error during CSV"):
            await ex.export([_one_result()], {"csv": tmp_path / "o.csv"})


@pytest.mark.asyncio
async def test_export_csv_wraps_csv_error(tmp_path: Path) -> None:
    ex = Exporter()

    def boom(*_a: object, **_k: object) -> None:
        msg = "bad row"
        raise csv.Error(msg)

    with (
        patch.object(csv.DictWriter, "writerows", boom),
        pytest.raises(ExportError, match="CSV serialization error"),
    ):
        await ex.export([_one_result()], {"csv": tmp_path / "o.csv"})


@pytest.mark.asyncio
async def test_export_json_wraps_file_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
        wf.side_effect = FileError("x")
        with pytest.raises(ExportError, match="File access error during JSON"):
            await ex.export([_one_result()], {"json": tmp_path / "o.json"})


@pytest.mark.asyncio
async def test_export_json_wraps_encode_error(tmp_path: Path) -> None:
    ex = Exporter()

    def bad_dumps(*_a: object, **_k: object) -> bytes:
        msg = "enc"
        raise TypeError(msg)

    with (
        patch("naminter.cli.exporters.orjson.dumps", bad_dumps),
        pytest.raises(ExportError, match="JSON serialization error"),
    ):
        await ex.export([_one_result()], {"json": tmp_path / "o.json"})


@pytest.mark.asyncio
async def test_export_html_template_read_file_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.read_file", new_callable=AsyncMock) as rf:
        rf.side_effect = FileError("missing template")
        with pytest.raises(ExportError, match="loading HTML template"):
            await ex.export([_one_result()], {"html": tmp_path / "o.html"})


@pytest.mark.asyncio
async def test_export_html_template_unexpected_load_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.read_file", new_callable=AsyncMock) as rf:
        rf.side_effect = RuntimeError("weird")
        with pytest.raises(ExportError, match="Unexpected error loading HTML"):
            await ex.export([_one_result()], {"html": tmp_path / "o.html"})


@pytest.mark.asyncio
async def test_export_html_jinja_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.jinja2.Environment") as mock_env_cls:
        mock_env = MagicMock()
        mock_env.from_string.side_effect = jinja2.TemplateError("bad")
        mock_env_cls.return_value = mock_env
        with pytest.raises(ExportError, match="Template rendering error"):
            await ex.export([_one_result()], {"html": tmp_path / "o.html"})


@pytest.mark.asyncio
async def test_export_html_write_file_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
        wf.side_effect = FileError("write fail")
        with pytest.raises(ExportError, match="File access error during HTML"):
            await ex.export([_one_result()], {"html": tmp_path / "o.html"})


@pytest.mark.asyncio
async def test_export_pdf_generation_error(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.HTML") as mock_html:
        mock_html.return_value.write_pdf.side_effect = RuntimeError("pdf")
        with pytest.raises(ExportError, match="PDF generation error"):
            await ex.export([_one_result()], {"pdf": tmp_path / "o.pdf"})


@pytest.mark.asyncio
async def test_export_pdf_empty_bytes(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.HTML") as mock_html:
        mock_html.return_value.write_pdf.return_value = None
        with pytest.raises(ExportError, match="empty content"):
            await ex.export([_one_result()], {"pdf": tmp_path / "o.pdf"})


@pytest.mark.asyncio
async def test_export_pdf_write_errors(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.HTML") as mock_html:
        mock_html.return_value.write_pdf.return_value = b"%PDF"
        with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
            wf.side_effect = FileError("w")
            with pytest.raises(ExportError, match="File access error writing PDF"):
                await ex.export([_one_result()], {"pdf": tmp_path / "o.pdf"})
            wf.side_effect = OSError("o")
            with pytest.raises(ExportError, match="Unexpected error writing PDF"):
                await ex.export([_one_result()], {"pdf": tmp_path / "o2.pdf"})


def test_resolve_path_custom_and_auto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert Exporter._resolve_path("csv", Path("x.csv")) == Path("x.csv")
    p = Exporter._resolve_path("json", None)
    assert p.parent == tmp_path
    assert p.name.startswith("results_")
    assert p.suffix == ".json"


@pytest.mark.asyncio
async def test_export_json_unexpected_exception(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
        wf.side_effect = RuntimeError("surprise")
        with pytest.raises(ExportError, match="Unexpected error during JSON"):
            await ex.export([_one_result()], {"json": tmp_path / "bad.json"})


@pytest.mark.asyncio
async def test_export_csv_unexpected_exception(tmp_path: Path) -> None:
    ex = Exporter()
    with patch("naminter.cli.exporters.write_file", new_callable=AsyncMock) as wf:
        wf.side_effect = RuntimeError("surprise")
        with pytest.raises(ExportError, match="Unexpected error during CSV"):
            await ex.export([_one_result()], {"csv": tmp_path / "o.csv"})


@pytest.mark.asyncio
async def test_export_html_unexpected_after_generate(tmp_path: Path) -> None:
    ex = Exporter()

    async def good_html(_results: Sequence[Any]) -> str:
        return "<html><body>x</body></html>"

    with (
        patch.object(Exporter, "_generate_html", good_html),
        patch(
            "naminter.cli.exporters.write_file",
            new_callable=AsyncMock,
            side_effect=RuntimeError("surprise"),
        ),
        pytest.raises(ExportError, match="Unexpected error during HTML"),
    ):
        await ex.export([_one_result()], {"html": tmp_path / "o.html"})
