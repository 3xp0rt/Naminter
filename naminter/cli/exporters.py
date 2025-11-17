import csv
import importlib.resources
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

import jinja2
from weasyprint import HTML

from naminter import __version__
from naminter.cli.constants import SUPPORTED_FORMATS
from naminter.core.constants import (
    DEFAULT_JSON_ENCODING,
    DEFAULT_JSON_ENSURE_ASCII,
    DEFAULT_JSON_INDENT,
    EMPTY_STRING,
)
from naminter.core.models import WMNResult, WMNValidationResult

from .exceptions import ConfigurationError, ExportError, FileIOError

FormatName = Literal["csv", "json", "html", "pdf"]
ResultDict = dict[str, Any]


class ExportMethod(Protocol):
    """Protocol for export method callables."""

    def __call__(self, results: list[ResultDict], output_path: Path) -> None: ...


class Exporter:
    """
    Unified exporter for CSV, JSON, HTML, and PDF formats.
    """

    def __init__(self, usernames: list[str] | None = None) -> None:
        self.usernames = usernames or []
        self.export_methods: dict[FormatName, ExportMethod] = {
            "csv": self._export_csv,
            "json": self._export_json,
            "html": self._export_html,
            "pdf": self._export_pdf,
        }

    def export(
        self,
        results: list[WMNResult | WMNValidationResult],
        formats: dict[FormatName, str | Path | None],
    ) -> None:
        """
        Export results in the given formats.
        """
        if not results:
            msg = "No results to export"
            raise ExportError(msg)

        dict_results = [
            result.to_dict(exclude_response_text=True) for result in results
        ]

        for format_name, path in formats.items():
            if format_name not in SUPPORTED_FORMATS:
                msg = f"Unsupported export format: {format_name}"
                raise ExportError(msg)

            try:
                out_path = self._resolve_path(format_name, path)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                self.export_methods[format_name](dict_results, out_path)
            except FileIOError as e:
                msg = f"File access error during {format_name} export: {e}"
                raise ExportError(msg) from e
            except Exception as e:
                msg = f"Unexpected error exporting {format_name}: {e}"
                raise ExportError(msg) from e

    @staticmethod
    def _export_csv(results: list[ResultDict], output_path: Path) -> None:
        """Export results to CSV format."""
        fieldnames: list[str] = []
        seen: set[str] = set()
        for result in results:
            for key in result:
                if key not in seen:
                    fieldnames.append(key)
                    seen.add(key)

        try:
            with output_path.open("w", newline=EMPTY_STRING, encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        except PermissionError as e:
            msg = f"Permission denied writing CSV file: {e}"
            raise FileIOError(msg) from e
        except OSError as e:
            msg = f"OS error writing CSV file: {e}"
            raise FileIOError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during CSV export: {e}"
            raise ExportError(msg) from e

    @staticmethod
    def _export_json(results: list[ResultDict], output_path: Path) -> None:
        """Export results to JSON format."""
        try:
            output_path.write_text(
                json.dumps(
                    results,
                    ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
                    indent=DEFAULT_JSON_INDENT,
                ),
                encoding=DEFAULT_JSON_ENCODING,
            )
        except PermissionError as e:
            msg = f"Permission denied writing JSON file: {e}"
            raise FileIOError(msg) from e
        except OSError as e:
            msg = f"OS error writing JSON file: {e}"
            raise FileIOError(msg) from e
        except (TypeError, ValueError) as e:
            msg = f"JSON serialization error: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during JSON export: {e}"
            raise ExportError(msg) from e

    def _generate_html(self, results: list[ResultDict]) -> str:
        """Generate HTML report from results."""
        grouped: dict[str, list[ResultDict]] = {}
        for item in results:
            cat = item.get("category", "uncategorized")
            grouped.setdefault(cat, []).append(item)

        display_fields = ["name", "url", "elapsed"]

        try:
            with (
                importlib.resources.files("naminter.cli.templates")
                .joinpath("report.html")
                .open("r", encoding="utf-8") as f
            ):
                template_source = f.read()
        except FileNotFoundError as e:
            msg = f"HTML template not found: {e}"
            raise ConfigurationError(msg) from e
        except PermissionError as e:
            msg = f"Permission denied reading HTML template: {e}"
            raise FileIOError(msg) from e
        except OSError as e:
            msg = f"OS error reading HTML template: {e}"
            raise FileIOError(msg) from e
        except Exception as e:
            msg = f"Unexpected error loading HTML template: {e}"
            raise ConfigurationError(msg) from e

        try:
            template = jinja2.Template(template_source, autoescape=True)
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

    def _export_html(self, results: list[ResultDict], output_path: Path) -> None:
        """Export results to HTML format."""
        try:
            html = self._generate_html(results)
            output_path.write_text(html, encoding="utf-8")
        except PermissionError as e:
            msg = f"Permission denied writing HTML file: {e}"
            raise FileIOError(msg) from e
        except OSError as e:
            msg = f"OS error writing HTML file: {e}"
            raise FileIOError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during HTML export: {e}"
            raise ExportError(msg) from e

    def _export_pdf(self, results: list[ResultDict], output_path: Path) -> None:
        """Export results to PDF format."""
        if not results:
            msg = "No results to export to PDF"
            raise ExportError(msg)

        try:
            html = self._generate_html(results)
            HTML(string=html).write_pdf(str(output_path))
        except PermissionError as e:
            msg = f"Permission denied writing PDF file: {e}"
            raise FileIOError(msg) from e
        except OSError as e:
            msg = f"OS error writing PDF file: {e}"
            raise FileIOError(msg) from e
        except (ValueError, TypeError) as e:
            msg = f"PDF generation error: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"Unexpected error during PDF export: {e}"
            raise ExportError(msg) from e

    @staticmethod
    def _resolve_path(format_name: FormatName, custom: str | Path | None) -> Path:
        if custom:
            return Path(custom)

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}.{format_name}"
        return Path.cwd() / filename
