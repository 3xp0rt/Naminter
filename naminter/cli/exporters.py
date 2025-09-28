import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Literal
import importlib.resources
import jinja2
from weasyprint import HTML

from ..core.models import SiteResult, SelfEnumerationResult
from ..core.exceptions import ConfigurationError, ExportError, FileAccessError

FormatName = Literal['csv', 'json', 'html', 'pdf']
ResultDict = Dict[str, Any]

class ExportMethod(Protocol):
    def __call__(self, results: List[ResultDict], output_path: Path) -> None: ...

class Exporter:
    """
    Unified exporter for CSV, JSON, HTML, and PDF formats.
    """
    SUPPORTED_FORMATS: List[FormatName] = ['csv', 'json', 'html', 'pdf']

    def __init__(self, usernames: Optional[List[str]] = None, version: Optional[str] = None) -> None:
        self.usernames = usernames or []
        self.version = version or 'unknown'
        self.export_methods: Dict[FormatName, ExportMethod] = {
            'csv': self._export_csv,
            'json': self._export_json,
            'html': self._export_html,
            'pdf': self._export_pdf,
        }

    def export(self,
               results: List[SiteResult | SelfEnumerationResult],
               formats: Dict[FormatName, Optional[str | Path]]) -> None:
        """
        Export results in the given formats.
        """
        if not results:
            return

        dict_results = [
            result.to_dict(exclude_response_text=True)
            for result in results
        ]

        for format_name, path in formats.items():
            if format_name not in self.SUPPORTED_FORMATS:
                raise ExportError(f"Unsupported export format: {format_name}")
            
            try:
                out_path = self._resolve_path(format_name, path)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                self.export_methods[format_name](dict_results, out_path)
            except FileAccessError as e:
                raise ExportError(f"File access error during {format_name} export: {e}") from e
            except Exception as e:
                raise ExportError(f"Failed to export {format_name}: {e}") from e

    def _export_csv(self, results: List[ResultDict], output_path: Path) -> None:
        if not results:
            return

        fieldnames = list(results[0].keys())

        try:
            with output_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        except PermissionError as e:
            raise FileAccessError(f"Permission denied writing CSV file: {e}") from e
        except OSError as e:
            raise FileAccessError(f"OS error writing CSV file: {e}") from e
        except Exception as e:
            raise ExportError(f"CSV export error: {e}") from e

    def _export_json(self, results: List[ResultDict], output_path: Path) -> None:
        try:
            output_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        except PermissionError as e:
            raise FileAccessError(f"Permission denied writing JSON file: {e}") from e
        except OSError as e:
            raise FileAccessError(f"OS error writing JSON file: {e}") from e
        except (TypeError, ValueError) as e:
            raise ExportError(f"JSON serialization error: {e}") from e
        except Exception as e:
            raise ExportError(f"JSON export error: {e}") from e

    def _generate_html(self, results: List[ResultDict]) -> str:
        grouped: Dict[str, List[ResultDict]] = {}
        for item in results:
            cat = item.get('category', 'uncategorized')
            grouped.setdefault(cat, []).append(item)

        default_fields = ['name', 'result_url', 'elapsed']
        display_fields = [f for f in default_fields if any(f in r for r in results)]

        try:
            with importlib.resources.files('naminter.cli.templates').joinpath('report.html').open('r', encoding='utf-8') as f:
                template_source = f.read()
        except FileNotFoundError as e:
            raise ConfigurationError(f'HTML template not found: {e}') from e
        except PermissionError as e:
            raise FileAccessError(f'Permission denied reading HTML template: {e}') from e
        except Exception as e:
            raise ConfigurationError(f'Could not load HTML template: {e}') from e

        template = jinja2.Template(template_source, autoescape=True)

        return template.render(
            grouped_results=grouped,
            display_fields=display_fields,
            usernames=self.usernames,
            version=self.version,
            current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_count=len(results),
            category_count=len(grouped)
        )

    def _export_html(self, results: List[ResultDict], output_path: Path) -> None:
        try:
            html = self._generate_html(results)
            output_path.write_text(html, encoding='utf-8')
        except PermissionError as e:
            raise FileAccessError(f"Permission denied writing HTML file: {e}") from e
        except OSError as e:
            raise FileAccessError(f"OS error writing HTML file: {e}") from e
        except Exception as e:
            raise ExportError(f"HTML export error: {e}") from e

    def _export_pdf(self, results: List[ResultDict], output_path: Path) -> None:
        if not results:
            raise ExportError('No results to export to PDF')

        try:
            html = self._generate_html(results)
            HTML(string=html).write_pdf(str(output_path))
        except PermissionError as e:
            raise FileAccessError(f"Permission denied writing PDF file: {e}") from e
        except OSError as e:
            raise FileAccessError(f"OS error writing PDF file: {e}") from e
        except Exception as e:
            raise ExportError(f"PDF export error: {e}") from e

    def _resolve_path(self, format_name: FormatName, custom: Optional[str | Path]) -> Path:
        if custom:
            return Path(custom)
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"results_{timestamp}.{format_name}"
        return Path.cwd() / filename
