"""Result exporters for CSV, JSON, HTML, and PDF formats."""

from collections.abc import Mapping, Sequence
import csv
from datetime import UTC, datetime
import importlib.resources
from io import StringIO
from pathlib import Path
from typing import Any, Literal, Protocol, get_args

import jinja2
import orjson
from weasyprint import HTML  # type: ignore[import-untyped]

from naminter import __version__
from naminter.cli.constants import HTML_FIELDS_ORDER
from naminter.cli.exceptions import ExportError, FileError
from naminter.cli.utils import read_file, write_file
from naminter.core.constants import EMPTY_STRING
from naminter.core.models import WMNResult, WMNTestResult

FormatName = Literal["json", "csv", "html", "pdf"]
ResultDict = dict[str, Any]


class ExportMethod(Protocol):
    """Protocol for export method callables."""

    async def __call__(self, results: list[ResultDict], output_path: Path) -> None:
        """Export results to the specified output path.

        Args:
            results: List of result dictionaries to export.
            output_path: Path where the exported file will be written.
        """
        ...


class Exporter:
    """Unified exporter for CSV, JSON, HTML, and PDF formats."""

    def __init__(self, usernames: list[str] | None = None) -> None:
        """Initialize exporter with optional usernames for report metadata.

        Args:
            usernames: List of usernames to include in export reports.
        """
        self.usernames = usernames or []
        self.export_methods: dict[FormatName, ExportMethod] = {
            "csv": self._export_csv,
            "json": self._export_json,
            "html": self._export_html,
            "pdf": self._export_pdf,
        }

    async def export(
        self,
        results: Sequence[WMNResult | WMNTestResult],
        formats: Mapping[str, str | Path | None],
    ) -> None:
        """Export results in the given formats.

        Args:
            results: Sequence of results to export.
            formats: Mapping of format names to output paths (None for auto).

        Raises:
            ExportError: If export operation fails.
        """
        if not results:
            msg = "No results to export"
            raise ExportError(msg)

        try:
            dict_results = [result.to_dict(exclude_text=True) for result in results]
        except (AttributeError, TypeError, ValueError) as e:
            msg = f"Failed to convert results to dictionary format: {e}"
            raise ExportError(msg) from e

        for format_name in get_args(FormatName):
            if format_name not in formats:
                continue

            path = formats[format_name]
            out_path = self._resolve_path(format_name, path)

            await self.export_methods[format_name](dict_results, out_path)

    @staticmethod
    async def _export_csv(results: list[ResultDict], output_path: Path) -> None:
        """Export results to CSV format.

        Args:
            results: List of result dictionaries to export.
            output_path: Path where CSV file will be written.

        Raises:
            ExportError: If CSV serialization fails or unexpected error occurs.
        """
        fieldnames = list(dict.fromkeys(key for result in results for key in result))

        if not fieldnames:
            msg = "CSV data error: no fields found in results"
            raise ExportError(msg)

        try:
            with StringIO(newline=EMPTY_STRING) as csv_buffer:
                writer = csv.DictWriter(
                    csv_buffer,
                    fieldnames=fieldnames,
                    lineterminator="\n",
                    extrasaction="raise",
                )
                writer.writeheader()
                writer.writerows(results)
                csv_content = csv_buffer.getvalue()

            await write_file(output_path, csv_content)
        except FileError as e:
            msg = f"File access error during CSV export: {e}"
            raise ExportError(msg) from e
        except csv.Error as e:
            msg = f"CSV serialization error: {e}"
            raise ExportError(msg) from e
        except (TypeError, ValueError, AttributeError, KeyError) as e:
            msg = f"CSV data error: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during CSV export: {e}"
            raise ExportError(msg) from e

    @staticmethod
    async def _export_json(results: list[ResultDict], output_path: Path) -> None:
        """Export results to JSON format.

        Args:
            results: List of result dictionaries to export.
            output_path: Path where JSON file will be written.

        Raises:
            ExportError: If JSON serialization fails or unexpected error occurs.
        """
        try:
            json_content = orjson.dumps(results, option=orjson.OPT_INDENT_2).decode(
                "utf-8"
            )
            await write_file(output_path, json_content)
        except FileError as e:
            msg = f"File access error during JSON export: {e}"
            raise ExportError(msg) from e
        except (TypeError, ValueError, RecursionError, orjson.JSONEncodeError) as e:
            msg = f"JSON serialization error: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during JSON export: {e}"
            raise ExportError(msg) from e

    async def _generate_html(self, results: list[ResultDict]) -> str:
        """Generate HTML report from results.

        Args:
            results: List of result dictionaries to format as HTML.

        Returns:
            str: Generated HTML string.

        Raises:
            ExportError: If template loading or rendering fails.
        """
        for item in results:
            item["url"] = item.get("uri_pretty")

        grouped: dict[str, list[ResultDict]] = {}
        for item in results:
            cat = item.get("category") or "uncategorized"
            grouped.setdefault(cat, []).append(item)

        available_fields = {key for item in results for key in item}
        display_fields = [
            field for field in HTML_FIELDS_ORDER if field in available_fields
        ]

        try:
            template_resource = importlib.resources.files(
                "naminter.cli.templates",
            ).joinpath("report.html")
            with importlib.resources.as_file(template_resource) as template_path:
                template_source = await read_file(template_path)
        except FileError as e:
            msg = f"File access error loading HTML template: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error loading HTML template: {e}"
            raise ExportError(msg) from e

        try:
            env = jinja2.Environment(
                autoescape=jinja2.select_autoescape(["html", "xml"]),
            )
            template = env.from_string(template_source)
            return template.render(
                grouped_results=grouped,
                display_fields=display_fields,
                usernames=self.usernames,
                version=__version__,
                current_time=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S %Z"),
                total_count=len(results),
                category_count=len(grouped),
            )
        except jinja2.TemplateError as e:
            msg = f"Template rendering error: {e}"
            raise ExportError(msg) from e

    async def _export_html(self, results: list[ResultDict], output_path: Path) -> None:
        """Export results to HTML format.

        Args:
            results: List of result dictionaries to export.
            output_path: Path where HTML file will be written.

        Raises:
            ExportError: If template rendering or file writing fails.
        """
        try:
            html = await self._generate_html(results)
            await write_file(output_path, html)
        except FileError as e:
            msg = f"File access error during HTML export: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during HTML export: {e}"
            raise ExportError(msg) from e

    async def _export_pdf(self, results: list[ResultDict], output_path: Path) -> None:
        """Export results to PDF format.

        Args:
            results: List of result dictionaries to export.
            output_path: Path where PDF file will be written.

        Raises:
            ExportError: If PDF generation fails or unexpected error occurs.
        """
        try:
            html = await self._generate_html(results)
            weasyprint_html = HTML(string=html)
            pdf_bytes: bytes | None = weasyprint_html.write_pdf()
        except Exception as e:
            msg = f"PDF generation error: {e}"
            raise ExportError(msg) from e

        if pdf_bytes is None:
            msg = "PDF generation returned empty content"
            raise ExportError(msg)

        try:
            await write_file(output_path, pdf_bytes)
        except FileError as e:
            msg = f"File access error writing PDF: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error writing PDF: {e}"
            raise ExportError(msg) from e

    @staticmethod
    def _resolve_path(format_name: FormatName, custom: str | Path | None) -> Path:
        """Resolve output path for export format.

        Args:
            format_name: Export format name (csv, json, html, pdf).
            custom: Custom path if provided, None for auto-generated path.

        Returns:
            Path: Resolved Path object for the output file.
        """
        if custom:
            return Path(custom)

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}_UTC.{format_name}"
        return Path.cwd() / filename
