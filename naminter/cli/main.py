import asyncio
import json
import logging
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import typing

import rich_click as click
from curl_cffi import requests
from rich import box
from rich.panel import Panel
from rich.table import Table

from curl_cffi import BrowserTypeLiteral
from ..cli.config import NaminterConfig
from ..cli.console import (
    console,
    display_error,
    display_warning,
    display_version,
    ResultFormatter,
)
from ..cli.exporters import Exporter
from ..cli.progress import ProgressManager, ResultsTracker
from ..core.models import ResultStatus, SiteResult, SelfCheckResult
from ..core.main import Naminter
from ..core.constants import MAX_CONCURRENT_TASKS, HTTP_REQUEST_TIMEOUT_SECONDS, HTTP_ALLOW_REDIRECTS, HTTP_SSL_VERIFY, WMN_REMOTE_URL, WMN_SCHEMA_URL
from ..core.exceptions import DataError, ConfigurationError
from .. import __description__, __version__


class NaminterCLI:
    """Handles username availability checks."""
    
    def __init__(self, config: NaminterConfig) -> None:
        self.config: NaminterConfig = config
        self._found_results: List[SiteResult] = []
        self._formatter: ResultFormatter = ResultFormatter(show_details=config.show_details)
        self._response_dir: Optional[Path] = self._setup_response_dir()

    def _setup_response_dir(self) -> Optional[Path]:
        """Setup response directory if response saving is enabled."""
        if not self.config.save_response:
            return None
        
        try:
            response_dir = Path(self.config.response_path) if self.config.response_path else Path.cwd() / "responses"
            response_dir.mkdir(parents=True, exist_ok=True)
            return response_dir
        except Exception as e:
            display_error(f"Cannot create/access response directory: {e}")
            return None

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for cross-platform compatibility."""
        if not filename or not str(filename).strip():
            return "unnamed"
            
        invalid_chars = '<>:"|?*\\/\0'
        sanitized = ''.join('_' if c in invalid_chars or ord(c) < 32 else c for c in str(filename))    
        sanitized = sanitized.strip(' .')[:200] if sanitized.strip(' .') else 'unnamed'
        return sanitized

    def _load_wmn_lists(self, local_list_paths: Optional[List[Path]] = None, remote_list_urls: Optional[List[str]] = None, skip_validation: bool = False) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Load and merge WMN lists from local and remote sources."""
        wmn_data = {"sites": [], "categories": [], "authors": [], "license": []}
        wmn_schema = None
        
        def _fetch_json(url: str, timeout: int = 30) -> Dict[str, Any]:
            """Helper to fetch and parse JSON from URL."""
            if not url or not isinstance(url, str) or not url.strip():
                raise ValueError(f"Invalid URL: {url}")
            
            try:
                response = requests.get(url, timeout=timeout)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                raise DataError(f"Failed to fetch from {url}: {e}") from e
            except json.JSONDecodeError as e:
                raise DataError(f"Failed to parse JSON from {url}: {e}") from e

        def _merge_data(data: Dict[str, Any]) -> None:
            """Helper to merge data into wmn_data."""
            if isinstance(data, dict):
                for key in ["sites", "categories", "authors", "license"]:
                    if key in data and isinstance(data[key], list):
                        wmn_data[key].extend(data[key])
        
        if not skip_validation:
            try:
                if self.config.local_schema_path:
                    wmn_schema = json.loads(Path(self.config.local_schema_path).read_text())
                elif self.config.remote_schema_url:
                    wmn_schema = _fetch_json(self.config.remote_schema_url)
            except Exception:
                pass
        
        sources = []
        if remote_list_urls:
            sources.extend([(url, True) for url in remote_list_urls])
        if local_list_paths:
            sources.extend([(path, False) for path in local_list_paths])
        
        if not sources:
            sources = [(WMN_REMOTE_URL, True)]
        
        for source, is_remote in sources:
            try:
                if is_remote:
                    data = _fetch_json(source)
                else:
                    data = json.loads(Path(source).read_text())
                _merge_data(data)
            except Exception as e:
                if not sources or source == WMN_REMOTE_URL:
                    raise DataError(f"Failed to load WMN data from {source}: {e}") from e
        
        if not wmn_data["sites"]:
            raise DataError("No sites loaded from any source")
        
        unique_sites = {site["name"]: site for site in wmn_data["sites"] 
                       if isinstance(site, dict) and site.get("name")}
        wmn_data["sites"] = list(unique_sites.values())
        wmn_data["categories"] = sorted(set(wmn_data["categories"]))
        wmn_data["authors"] = sorted(set(wmn_data["authors"]))
        wmn_data["license"] = list(dict.fromkeys(wmn_data["license"]))
        
        return wmn_data, wmn_schema

    async def run(self) -> None:
        """Main execution method with progress tracking."""
        wmn_data, wmn_schema = self._load_wmn_lists(
            local_list_paths=self.config.local_list_paths,
            remote_list_urls=self.config.remote_list_urls,
            skip_validation=self.config.skip_validation
        )
        
        async with Naminter(
            wmn_data=wmn_data,
            wmn_schema=wmn_schema,
            max_tasks=self.config.max_tasks,
            timeout=self.config.timeout,
            proxy=self.config.proxy,
            verify_ssl=self.config.verify_ssl,
            allow_redirects=self.config.allow_redirects,
            impersonate=self.config.impersonate,
            ja3=self.config.ja3,
            akamai=self.config.akamai,
            extra_fp=self.config.extra_fp,
        ) as naminter:
            if self.config.self_check:
                results = await self._run_self_check(naminter)
            else:
                results = await self._run_check(naminter)
            
            filtered_results = [r for r in results if self._should_include_result(r)]
            
            if self.config.export_formats:
                export_manager = Exporter(self.config.usernames or [], __version__)
                export_manager.export(filtered_results, self.config.export_formats)

    async def _run_check(self, naminter: Naminter) -> List[SiteResult]:
        """Run the username check functionality."""
        if not self.config.usernames:
            raise ValueError("At least one username is required")
    
        if self.config.site_names:
            available_sites = naminter.list_sites()
            actual_site_count = len([s for s in self.config.site_names if s in available_sites])
        else:
            actual_site_count = len(naminter._wmn_data.get("sites", []))
        
        total_sites = actual_site_count * len(self.config.usernames)
        tracker = ResultsTracker(total_sites)
        all_results = []
        
        with ProgressManager(console, disabled=self.config.no_progressbar) as progress_mgr:
            progress_mgr.start(total_sites, "Checking usernames...")
            
            results = await naminter.check_usernames(
                usernames=self.config.usernames,
                site_names=self.config.site_names,
                fuzzy_mode=self.config.fuzzy_mode,
                as_generator=True
            )  
            async for result in results:
                tracker.add_result(result)

                if self._should_include_result(result):
                    response_file_path = await self._process_result(result)                    
                    formatted_output = self._formatter.format_result(result, response_file_path)
                    console.print(formatted_output)
                
                all_results.append(result)
                progress_mgr.update(description=tracker.get_progress_text())

        return all_results

    async def _run_self_check(self, naminter: Naminter) -> List[SelfCheckResult]:
        """Run the self-check functionality."""
        sites_data = naminter._wmn_data.get("sites", [])
        
        if self.config.site_names:
            available_sites = [site.get("name") for site in sites_data if site.get("name")]
            filtered_sites = [site for site in sites_data if site.get("name") in self.config.site_names]
            site_count = len(filtered_sites)
        else:
            site_count = len(sites_data)
        
        total_tests = 0
        for site in sites_data:
            if isinstance(site, dict):
                known_accounts = site.get("known", [])
                if isinstance(known_accounts, list) and known_accounts:
                    total_tests += len(known_accounts)

        tracker = ResultsTracker(total_tests)
        all_results = []

        with ProgressManager(console, disabled=self.config.no_progressbar) as progress_mgr:
            progress_mgr.start(site_count, "Running self-check...")
            
            results = await naminter.self_check(
                site_names=self.config.site_names,
                fuzzy_mode=self.config.fuzzy_mode,
                as_generator=True
            )
            async for result in results:
                for site_result in result.results:
                    tracker.add_result(site_result)
                
                if self._should_include_result(result):
                    response_files = []
                    for site_result in result.results:
                        response_file_path = await self._process_result(site_result)
                        if response_file_path:
                            response_files.append(response_file_path)
                    
                    formatted_output = self._formatter.format_self_check(result, response_files)
                    console.print(formatted_output)
                    
                all_results.append(result)
                progress_mgr.update(description=tracker.get_progress_text())

        return all_results

    def _should_include_result(self, result: Union[SiteResult, SelfCheckResult]) -> bool:
        """Determine if a result should be included in output based on filter settings."""
        if isinstance(result, SelfCheckResult):
            status = result.overall_status
        else:
            status = result.result_status
        
        if self.config.filter_all:
            return True
        elif self.config.filter_errors and status == ResultStatus.ERROR:
            return True
        elif self.config.filter_not_found and status == ResultStatus.NOT_FOUND:
            return True
        elif self.config.filter_unknown and status == ResultStatus.UNKNOWN:
            return True
        elif self.config.filter_ambiguous and status == ResultStatus.AMBIGUOUS:
            return True
        elif not any([self.config.filter_errors, self.config.filter_not_found, self.config.filter_unknown, self.config.filter_ambiguous]):
            return status == ResultStatus.FOUND
        
        return False

    async def _process_result(self, result: SiteResult) -> Optional[Path]:
        """Process a single result: handle browser opening, response saving, and console output."""
        response_file = None

        if result.result_url:
            self._found_results.append(result)
            if self.config.browse:
                try:
                    await asyncio.to_thread(webbrowser.open, result.result_url)
                except Exception as e:
                    display_error(f"Error opening browser for {result.result_url}: {e}")
        
        if self.config.save_response and result.response_text and self._response_dir:
            try:
                safe_site_name = self._sanitize_filename(result.site_name)
                safe_username = self._sanitize_filename(result.username)
                status_str = result.result_status.value
                created_at_str = result.created_at.strftime('%Y%m%d_%H%M%S')
                
                base_filename = f"{status_str}_{result.response_code}_{safe_site_name}_{safe_username}_{created_at_str}.html"
                response_file = self._response_dir / base_filename
                
                await asyncio.to_thread(response_file.write_text, result.response_text, encoding="utf-8")
                
                if self.config.open_response:
                    try:
                        file_uri = response_file.resolve().as_uri()
                        await asyncio.to_thread(webbrowser.open, file_uri)
                    except Exception as e:
                        display_error(f"Error opening response file {response_file}: {e}")
            except Exception as e:
                display_error(f"Failed to save response to file: {e}")
        
        return response_file


@click.group(invoke_without_command=True, context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--version', is_flag=True, help='Show version information and exit')
@click.option('--no-color', is_flag=True, help='Disable colored console output')
@click.option('--no-progressbar', is_flag=True, help='Disable progress bar during execution')
@click.option('--username', '-u', multiple=True, help='Username(s) to search for across social media platforms')
@click.option('--site', '-s', multiple=True, help='Specific site name(s) to check (e.g., "GitHub", "Twitter")')
@click.option('--local-list', type=click.Path(exists=True, path_type=Path), multiple=True, help='Path(s) to local JSON file(s) containing WhatsMyName site data')
@click.option('--remote-list', multiple=True, help='URL(s) to fetch remote WhatsMyName site data')
@click.option('--local-schema', type=click.Path(exists=True, path_type=Path), help='Path to local WhatsMyName JSON schema file for validation')
@click.option('--remote-schema', default=WMN_SCHEMA_URL, help='URL to fetch custom WhatsMyName JSON schema for validation')
@click.option('--skip-validation', is_flag=True, help='Skip JSON schema validation of WhatsMyName data')
@click.option('--self-check', is_flag=True, help='Run self-check mode to validate site detection accuracy')
@click.option('--include-categories', multiple=True, help='Include only sites from specified categories (e.g., "social", "coding")')
@click.option('--exclude-categories', multiple=True, help='Exclude sites from specified categories (e.g., "adult", "gaming")')
@click.option('--proxy', help='Proxy server to use for requests (e.g., http://proxy:port, socks5://proxy:port)')
@click.option('--timeout', type=int, default=HTTP_REQUEST_TIMEOUT_SECONDS, help='Maximum time in seconds to wait for each HTTP request')
@click.option('--allow-redirects', is_flag=True, default=HTTP_ALLOW_REDIRECTS, help='Whether to follow HTTP redirects automatically')
@click.option('--verify-ssl', is_flag=True, default=HTTP_SSL_VERIFY, help='Whether to verify SSL/TLS certificates for HTTPS requests')
@click.option('--impersonate', type=click.Choice(typing.get_args(BrowserTypeLiteral) + ("none",)), default="chrome", help='Browser to impersonate in HTTP requests (use "none" to disable impersonation)')
@click.option('--no-impersonate', is_flag=True, help='Disable browser impersonation (equivalent to --impersonate none)')
@click.option('--ja3', help='JA3 fingerprint string for TLS fingerprinting')
@click.option('--akamai', help='Akamai fingerprint string for Akamai bot detection bypass')
@click.option('--extra-fp', help='Extra fingerprinting options as JSON string (e.g., \'{"tls_grease": true, "tls_cert_compression": "brotli"}\')')
@click.option('--max-tasks', type=int, default=MAX_CONCURRENT_TASKS, help='Maximum number of concurrent tasks')
@click.option('--fuzzy', 'fuzzy_mode', is_flag=True, help='Enable fuzzy validation mode')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), help='Set logging level')
@click.option('--log-file', help='Path to log file for debug output')
@click.option('--show-details', is_flag=True, help='Show detailed information in console output')
@click.option('--browse', is_flag=True, help='Open found profiles in web browser')
@click.option('--save-response', is_flag=True, help='Save HTTP response content for each result to files')
@click.option('--response-path', help='Custom directory path for saving response files')
@click.option('--open-response', is_flag=True, help='Open saved response files in web browser')
@click.option('--csv', 'csv_export', is_flag=True, help='Export results to CSV file')
@click.option('--csv-path', help='Custom path for CSV export')
@click.option('--pdf', 'pdf_export', is_flag=True, help='Export results to PDF file')
@click.option('--pdf-path', help='Custom path for PDF export')
@click.option('--html', 'html_export', is_flag=True, help='Export results to HTML file')
@click.option('--html-path', help='Custom path for HTML export')
@click.option('--json', 'json_export', is_flag=True, help='Export results to JSON file')
@click.option('--json-path', help='Custom path for JSON export')
@click.option('--filter-all', is_flag=True, help='Include all results in console output and exports')
@click.option('--filter-errors', is_flag=True, help='Show only error results in console output and exports')
@click.option('--filter-not-found', is_flag=True, help='Show only not found results in console output and exports')
@click.option('--filter-unknown', is_flag=True, help='Show only unknown results in console output and exports')
@click.option('--filter-ambiguous', is_flag=True, help='Show only ambiguous results in console output and exports')
@click.pass_context
def main(ctx: click.Context, version: bool, **kwargs) -> None:
    """The most powerful and fast username availability checker that searches across hundreds of websites using WhatsMyName dataset."""
    
    if version:
        display_version()
        ctx.exit()
    
    if ctx.invoked_subcommand is not None:
        return
    
    # If no subcommand is invoked, run the main functionality
    if not kwargs.get('username') and not kwargs.get('self_check'):
        click.echo(ctx.get_help())
        ctx.exit(1)
    
    if kwargs.get('no_color'):
        console.no_color = True

    try:
        # Handle --no-impersonate flag
        impersonate_value = kwargs.get('impersonate')
        if kwargs.get('no_impersonate'):
            impersonate_value = "none"
        
        # Parse extra fingerprinting options if provided
        extra_fp = None
        if kwargs.get('extra_fp'):
            try:
                extra_fp = json.loads(kwargs.get('extra_fp'))
            except json.JSONDecodeError as e:
                display_error(f"Invalid JSON in --extra-fp option: {e}")
                ctx.exit(1)

        config = NaminterConfig(
            usernames=kwargs.get('username'),
            site_names=kwargs.get('site'),
            local_list_paths=kwargs.get('local_list'),
            remote_list_urls=kwargs.get('remote_list'),
            local_schema_path=kwargs.get('local_schema'),
            remote_schema_url=kwargs.get('remote_schema'),
            skip_validation=kwargs.get('skip_validation'),
            include_categories=kwargs.get('include_categories'),
            exclude_categories=kwargs.get('exclude_categories'),
            max_tasks=kwargs.get('max_tasks'),
            timeout=kwargs.get('timeout'),
            proxy=kwargs.get('proxy'),
            allow_redirects=kwargs.get('allow_redirects'),
            verify_ssl=kwargs.get('verify_ssl'),
            impersonate=impersonate_value,
            ja3=kwargs.get('ja3'),
            akamai=kwargs.get('akamai'),
            extra_fp=extra_fp,
            fuzzy_mode=kwargs.get('fuzzy_mode'),
            self_check=kwargs.get('self_check'),
            log_level=kwargs.get('log_level'),
            log_file=kwargs.get('log_file'),
            show_details=kwargs.get('show_details'),
            browse=kwargs.get('browse'),
            save_response=kwargs.get('save_response'),
            response_path=kwargs.get('response_path'),
            open_response=kwargs.get('open_response'),
            csv_export=kwargs.get('csv_export'),
            csv_path=kwargs.get('csv_path'),
            pdf_export=kwargs.get('pdf_export'),
            pdf_path=kwargs.get('pdf_path'),
            html_export=kwargs.get('html_export'),
            html_path=kwargs.get('html_path'),
            json_export=kwargs.get('json_export'),
            json_path=kwargs.get('json_path'),
            filter_all=kwargs.get('filter_all'),
            filter_errors=kwargs.get('filter_errors'),
            filter_not_found=kwargs.get('filter_not_found'),
            filter_unknown=kwargs.get('filter_unknown'),
            filter_ambiguous=kwargs.get('filter_ambiguous'),
            no_progressbar=kwargs.get('no_progressbar'),
        )

        if config.log_level and config.log_file:
            log_path = Path(config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            logging.basicConfig(
                level=config.log_level,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                filename=str(log_path),
                filemode="a"
            )
        
        naminter_cli = NaminterCLI(config)
        asyncio.run(naminter_cli.run())
    except KeyboardInterrupt:
        display_warning("Operation interrupted")
        ctx.exit(1)
    except asyncio.TimeoutError:
        display_error("Operation timed out")
        ctx.exit(1)
    except ConfigurationError as e:
        display_error(f"Configuration error: {e}")
        ctx.exit(1)
    except DataError as e:
        display_error(f"Data error: {e}")
        ctx.exit(1)
    except Exception as e:
        display_error(f"Fatal error: {e}")
        ctx.exit(1)


def entry_point() -> None:
    """Entry point for the application."""
    main()


if __name__ == "__main__":
    entry_point()