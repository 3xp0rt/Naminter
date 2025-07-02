import asyncio
import json
import logging
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import typer
from curl_cffi import requests

from ..cli.config import BrowserImpersonation, NaminterConfig
from ..cli.console import (
    console,
    THEME,
    display_error,
    display_version,
    display_warning,
    ResultFormatter,
)
from ..cli.exporters import Exporter
from ..cli.progress import ProgressManager, ResultsTracker
from ..core.models import ResultStatus, SiteResult, SelfCheckResult
from ..core.main import Naminter
from ..core.constants import MAX_CONCURRENT_TASKS, HTTP_REQUEST_TIMEOUT_SECONDS, HTTP_ALLOW_REDIRECTS, HTTP_SSL_VERIFY, WMN_REMOTE_URL, WMN_SCHEMA_URL
from ..core.exceptions import DataError, ConfigurationError

__version__ = "1.0.5"
__author__ = "3xp0rt"
__description__ = "WhatsMyName Enumeration Tool"

app = typer.Typer(
    help=__description__,
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

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
        try:
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
                impersonate=self.config.impersonate,
                verify_ssl=self.config.verify_ssl,
                allow_redirects=self.config.allow_redirects,
                proxy=self.config.proxy,
            ) as naminter:
                if self.config.self_check:
                    results = await self._run_self_check(naminter)
                else:
                    results = await self._run_check(naminter)
                
                filtered_results = [r for r in results if self._should_include_result(r)]
                
                if self.config.export_formats:
                    export_manager = Exporter(self.config.usernames or [], __version__)
                    export_manager.export(filtered_results, self.config.export_formats)
        except KeyboardInterrupt:
            display_warning("Operation interrupted")
            raise typer.Exit(1)
        except asyncio.TimeoutError:
            display_error("Operation timed out")
            raise typer.Exit(1)
        except Exception as e:
            display_error(f"Unexpected error: {e}")
            raise typer.Exit(1)

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
        elif not any([self.config.filter_errors, self.config.filter_not_found, self.config.filter_unknown]):
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

@app.callback(invoke_without_command=True)
def main(
    usernames: Optional[List[str]] = typer.Option(None, "--username", "-u", help="Username(s) to search for across social media platforms", show_default=False),
    site_names: Optional[List[str]] = typer.Option(None, "--site", "-s", help="Specific site name(s) to check (e.g., 'GitHub', 'Twitter')", show_default=False),
    version: bool = typer.Option(False, "--version", help="Display version information and exit"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored console output"),
    no_progressbar: bool = typer.Option(False, "--no-progressbar", help="Disable progress bar during execution"),
    ctx: typer.Context = None,

    # Input lists
    local_list: Optional[List[Path]] = typer.Option(
        None, "--local-list", help="Path(s) to local JSON file(s) containing WhatsMyName site data", show_default=False
    ),
    remote_list_url: Optional[List[str]] = typer.Option(
        None, "--remote-list", help="URL(s) to fetch remote WhatsMyName site data", show_default=False
    ),
    local_schema: Optional[Path] = typer.Option(
        None, "--local-schema", help="Path to local WhatsMyName JSON schema file for validation", show_default=False
    ),
    remote_schema_url: Optional[str] = typer.Option(
        WMN_SCHEMA_URL, "--remote-schema", help="URL to fetch custom WhatsMyName JSON schema for validation"
    ),

    skip_validation: bool = typer.Option(False, "--skip-validation", help="Skip JSON schema validation of WhatsMyName data"),

    # Self-check
    self_check: bool = typer.Option(False, "--self-check", help="Run self-check mode to validate site detection accuracy"),

    # Category filters
    include_categories: Optional[List[str]] = typer.Option(
        None, "--include-categories", show_default=False, help="Include only sites from specified categories (e.g., 'social', 'coding')"
    ),
    exclude_categories: Optional[List[str]] = typer.Option(
        None, "--exclude-categories", show_default=False, help="Exclude sites from specified categories (e.g., 'adult', 'gaming')"
    ),

    # Network
    proxy: Optional[str] = typer.Option(
        None, "--proxy", show_default=False, help="Proxy server to use for requests (e.g., http://proxy:port, socks5://proxy:port)"
    ),
    timeout: int = typer.Option(HTTP_REQUEST_TIMEOUT_SECONDS, "--timeout", help="Maximum time in seconds to wait for each HTTP request"),
    allow_redirects: bool = typer.Option(HTTP_ALLOW_REDIRECTS, "--allow-redirects", help="Whether to follow HTTP redirects automatically"),
    verify_ssl: bool = typer.Option(HTTP_SSL_VERIFY, "--verify-ssl", help="Whether to verify SSL/TLS certificates for HTTPS requests"),
    impersonate: BrowserImpersonation = typer.Option(
        BrowserImpersonation.CHROME, "--impersonate", "-i", help="Browser to impersonate in HTTP requests"
    ),
    
    # Concurrency & Debug
    max_tasks: int = typer.Option(MAX_CONCURRENT_TASKS, "--max-tasks", help="Maximum number of concurrent tasks"),
    fuzzy_mode: bool = typer.Option(False, "--fuzzy", help="Enable fuzzy validation mode"),
    log_level: Optional[str] = typer.Option(None, "--log-level", help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", show_default=False),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Path to log file for debug output", show_default=False),
    show_details: bool = typer.Option(False, "--show-details", help="Show detailed information in console output"),
    browse: bool = typer.Option(False, "--browse", help="Open found profiles in web browser"),

    # Response handling
    save_response: bool = typer.Option(False, "--save-response", help="Save HTTP response content for each result to files"),
    response_path: Optional[str] = typer.Option(None, "--response-path", help="Custom directory path for saving response files", show_default=False),
    open_response: bool = typer.Option(False, "--open-response", help="Open saved response files in web browser"),

    # Export
    csv_export: bool = typer.Option(False, "--csv", help="Export results to CSV file"),
    csv_path: Optional[str] = typer.Option(None, "--csv-path", help="Custom path for CSV export", show_default=False),
    pdf_export: bool = typer.Option(False, "--pdf", help="Export results to PDF file"),
    pdf_path: Optional[str] = typer.Option(None, "--pdf-path", help="Custom path for PDF export", show_default=False),
    html_export: bool = typer.Option(False, "--html", help="Export results to HTML file"),
    html_path: Optional[str] = typer.Option(None, "--html-path", help="Custom path for HTML export", show_default=False),
    json_export: bool = typer.Option(False, "--json", help="Export results to JSON file"),
    json_path: Optional[str] = typer.Option(None, "--json-path", help="Custom path for JSON export", show_default=False),

    # Result filters
    filter_all: bool = typer.Option(False, "--filter-all", help="Include all results in console output and exports"),
    filter_errors: bool = typer.Option(False, "--filter-errors", help="Show only error results in console output and exports"),
    filter_not_found: bool = typer.Option(False, "--filter-not-found", help="Show only not found results in console output and exports"),
    filter_unknown: bool = typer.Option(False, "--filter-unknown", help="Show only unknown results in console output and exports"),
) -> None:
    """Main CLI entry point."""
    
    if ctx and ctx.invoked_subcommand:
        return

    if no_color:
        console.no_color = True

    if version:
        display_version(__version__, __author__, __description__)
        raise typer.Exit()
    
    try:
        config = NaminterConfig(
            usernames=usernames,
            site_names=site_names,
            local_list_paths=local_list,
            remote_list_urls=remote_list_url,
            local_schema_path=local_schema,
            remote_schema_url=remote_schema_url,
            skip_validation=skip_validation,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
            max_tasks=max_tasks,
            timeout=timeout,
            proxy=proxy,
            allow_redirects=allow_redirects,
            verify_ssl=verify_ssl,
            impersonate=impersonate,
            fuzzy_mode=fuzzy_mode,
            self_check=self_check,
            log_level=log_level,
            log_file=log_file,
            show_details=show_details,
            browse=browse,
            save_response=save_response,
            response_path=response_path,
            open_response=open_response,
            csv_export=csv_export,
            csv_path=csv_path,
            pdf_export=pdf_export,
            pdf_path=pdf_path,
            html_export=html_export,
            html_path=html_path,
            json_export=json_export,
            json_path=json_path,
            filter_all=filter_all,
            filter_errors=filter_errors,
            filter_not_found=filter_not_found,
            filter_unknown=filter_unknown,
            no_progressbar=no_progressbar,
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
        raise typer.Exit(1)
    except asyncio.TimeoutError:
        display_error("Operation timed out")
        raise typer.Exit(1)
    except ConfigurationError as e:
        display_error(f"Configuration error: {e}")
        raise typer.Exit(1)
    except DataError as e:
        display_error(f"Data error: {e}")
        raise typer.Exit(1)
    except Exception as e:
        display_error(f"Fatal error: {e}")
        raise typer.Exit(1)

def entry_point() -> None:
    """Entry point for the application."""
    app()

if __name__ == "__main__":
    entry_point()