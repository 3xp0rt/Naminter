import csv
import importlib.resources
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal, Protocol

import jinja2
from weasyprint import HTML

from naminter.core.exceptions import ConfigurationError, ExportError, FileAccessError
from naminter.core.models import SelfEnumerationResult, SiteResult

FormatName = Literal["csv", "json", "html", "pdf"]
ResultDict = dict[str, Any]


class ExportMethod(Protocol):
    def __call__(self, results: list[ResultDict], output_path: Path) -> None: ...


class Exporter:
    """
    Unified exporter for CSV, JSON, HTML, and PDF formats.
    """

    SUPPORTED_FORMATS: ClassVar[list[FormatName]] = ["csv", "json", "html", "pdf"]

    def __init__(
        self, usernames: list[str] | None = None, version: str | None = None
    ) -> None:
        self.usernames = usernames or []
        self.version = version or "unknown"
        self.export_methods: dict[FormatName, ExportMethod] = {
            "csv": self._export_csv,
            "json": self._export_json,
            "html": self._export_html,
            "pdf": self._export_pdf,
        }

    def export(
        self,
        results: list[SiteResult | SelfEnumerationResult],
        formats: dict[FormatName, str | Path | None],
    ) -> None:
        """
        Export results in the given formats.
        """
        if not results:
            return

        dict_results = [
            result.to_dict(exclude_response_text=True) for result in results
        ]

        for format_name, path in formats.items():
            if format_name not in self.SUPPORTED_FORMATS:
                msg = f"Unsupported export format: {format_name}"
                raise ExportError(msg)

            try:
                out_path = self._resolve_path(format_name, path)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                self.export_methods[format_name](dict_results, out_path)
            except FileAccessError as e:
                msg = f"File access error during {format_name} export: {e}"
                raise ExportError(
                    msg
                ) from e
            except Exception as e:
                msg = f"Failed to export {format_name}: {e}"
                raise ExportError(msg) from e

    @staticmethod
    def _export_csv(results: list[ResultDict], output_path: Path) -> None:
        if not results:
            return

        fieldnames = list(results[0].keys())

        try:
            with output_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        except PermissionError as e:
            msg = f"Permission denied writing CSV file: {e}"
            raise FileAccessError(msg) from e
        except OSError as e:
            msg = f"OS error writing CSV file: {e}"
            raise FileAccessError(msg) from e
        except Exception as e:
            msg = f"CSV export error: {e}"
            raise ExportError(msg) from e

    @staticmethod
    def _export_json(results: list[ResultDict], output_path: Path) -> None:
        try:
            output_path.write_text(
                json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except PermissionError as e:
            msg = f"Permission denied writing JSON file: {e}"
            raise FileAccessError(msg) from e
        except OSError as e:
            msg = f"OS error writing JSON file: {e}"
            raise FileAccessError(msg) from e
        except (TypeError, ValueError) as e:
            msg = f"JSON serialization error: {e}"
            raise ExportError(msg) from e
        except Exception as e:
            msg = f"JSON export error: {e}"
            raise ExportError(msg) from e

    def _generate_html(self, results: list[ResultDict]) -> str:
        grouped: dict[str, list[ResultDict]] = {}
        for item in results:
            cat = item.get("category", "uncategorized")
            grouped.setdefault(cat, []).append(item)

        default_fields = ["name", "result_url", "elapsed"]
        display_fields = [f for f in default_fields if any(f in r for r in results)]

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
            raise FileAccessError(
                msg
            ) from e
        except Exception as e:
            msg = f"Could not load HTML template: {e}"
            raise ConfigurationError(msg) from e

        template = jinja2.Template(template_source, autoescape=True)

        return template.render(
            grouped_results=grouped,
            display_fields=display_fields,
            usernames=self.usernames,
            version=self.version,
            current_time=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S %Z"),
            total_count=len(results),
            category_count=len(grouped),
        )

    def _export_html(self, results: list[ResultDict], output_path: Path) -> None:
        try:
            html = self._generate_html(results)
            output_path.write_text(html, encoding="utf-8")
        except PermissionError as e:
            msg = f"Permission denied writing HTML file: {e}"
            raise FileAccessError(msg) from e
        except OSError as e:
            msg = f"OS error writing HTML file: {e}"
            raise FileAccessError(msg) from e
        except Exception as e:
            msg = f"HTML export error: {e}"
            raise ExportError(msg) from e

    def _export_pdf(self, results: list[ResultDict], output_path: Path) -> None:
        if not results:
            msg = "No results to export to PDF"
            raise ExportError(msg)

        try:
            html = self._generate_html(results)
            HTML(string=html).write_pdf(str(output_path))
        except PermissionError as e:
            msg = f"Permission denied writing PDF file: {e}"
            raise FileAccessError(msg) from e
        except OSError as e:
            msg = f"OS error writing PDF file: {e}"
            raise FileAccessError(msg) from e
        except Exception as e:
            msg = f"PDF export error: {e}"
            raise ExportError(msg) from e

    @staticmethod
    def _resolve_path(format_name: FormatName, custom: str | Path | None) -> Path:
        if custom:
            return Path(custom)

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"results_{timestamp}.{format_name}"
        return Path.cwd() / filename
