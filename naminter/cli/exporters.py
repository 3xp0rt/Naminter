import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Literal
import importlib.resources
import jinja2
from weasyprint import HTML

from ..core.models import SiteResult
from ..core.exceptions import ConfigurationError

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
               results: List[SiteResult | ResultDict],
               formats: Dict[FormatName, Optional[str | Path]]) -> None:
        """
        Export results in the given formats.
        """
        if not results:
            return

        dict_results = [
            (r.to_dict(exclude_response_text=True) if isinstance(r, SiteResult) else r)
            for r in results if isinstance(r, (SiteResult, dict))
        ]

        for fmt, path in formats.items():
            if fmt not in self.SUPPORTED_FORMATS:
                raise ValueError(f"Skipping unsupported format '{fmt}'")
            out_path = self._resolve_path(fmt, path)
            out_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                self.export_methods[fmt](dict_results, out_path)
            except Exception as exc:
                raise RuntimeError(f"Failed to export {fmt}: {exc}") from exc

    def _export_csv(self, results: List[ResultDict], output_path: Path) -> None:
        if not results:
            return
        fieldnames = list(results[0].keys())
        try:
            with output_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        except Exception as exc:
            raise RuntimeError(f"CSV export error: {exc}") from exc

    def _export_json(self, results: List[ResultDict], output_path: Path) -> None:
        try:
            output_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as exc:
            raise RuntimeError(f"JSON export error: {exc}") from exc

    def _generate_html(self, results: List[ResultDict]) -> str:
        grouped: Dict[str, List[ResultDict]] = {}
        for item in results:
            cat = item.get('category', 'uncategorized')
            grouped.setdefault(cat, []).append(item)

        default_fields = ['site_name', 'result_url', 'elapsed']
        display_fields = [f for f in default_fields if any(f in r for r in results)]

        try:
            with importlib.resources.files('naminter.cli.templates').joinpath('report.html').open('r', encoding='utf-8') as f:
                template_source = f.read()
        except Exception as e:
            raise ConfigurationError(f'Could not load HTML template: {e}')

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
        except Exception as exc:
            raise RuntimeError(f"HTML export error: {exc}") from exc

    def _export_pdf(self, results: List[ResultDict], output_path: Path) -> None:
        if not results:
            raise ValueError('No results to export to PDF')
        try:
            html = self._generate_html(results)
            HTML(string=html).write_pdf(str(output_path))
        except Exception as exc:
            raise RuntimeError(f"PDF export error: {exc}") from exc

    def _resolve_path(self, fmt: FormatName, custom: Optional[str | Path]) -> Path:
        if custom:
            return Path(custom)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"results_{timestamp}.{fmt}"
        return Path.cwd() / filename
