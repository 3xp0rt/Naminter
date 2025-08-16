import asyncio
import json
import logging
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import typing
import aiofiles

import rich_click as click

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
from ..cli.constants import RESPONSE_FILE_DATE_FORMAT, RESPONSE_FILE_EXTENSION
from ..cli.utils import load_wmn_lists, sanitize_filename
from ..core.models import ResultStatus, SiteResult, SelfEnumerationResult
from ..core.main import Naminter
from ..core.constants import MAX_CONCURRENT_TASKS, HTTP_REQUEST_TIMEOUT_SECONDS, HTTP_ALLOW_REDIRECTS, HTTP_SSL_VERIFY, WMN_SCHEMA_URL, LOGGING_FORMAT

from ..core.exceptions import DataError, ConfigurationError
from .. import __description__, __version__


def _version_callback(ctx: click.Context, param: click.Option, value: bool) -> None:
    """Eager callback to display version and exit."""
    if not value or ctx.resilient_parsing:
        return
    display_version()
    ctx.exit()


class NaminterCLI:
    """Handles username enumeration operations."""
    
    def __init__(self, config: NaminterConfig) -> None:
        self.config: NaminterConfig = config
        self._formatter: ResultFormatter = ResultFormatter(show_details=config.show_details)
        self._response_dir: Optional[Path] = self._setup_response_dir()

    def _setup_response_dir(self) -> Optional[Path]:
        """Setup response directory if response saving is enabled."""
        if not self.config.save_response:
            return None
        
        try:
            response_path = self.config.response_path
            if response_path is None:
                return None
                
            response_path.mkdir(parents=True, exist_ok=True)
            return response_path
        except PermissionError as e:
            display_error(f"Permission denied creating/accessing response directory: {e}")
            return None
        except OSError as e:
            display_error(f"OS error creating/accessing response directory: {e}")
            return None
        except Exception as e:
            display_error(f"Unexpected error setting up response directory: {e}")
            return None

    @staticmethod
    def _setup_logging(config: NaminterConfig) -> None:
        """Setup logging configuration if log level and file are specified."""
        if config.log_level and config.log_file:
            log_path = Path(config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            level_value = getattr(logging, str(config.log_level).upper(), logging.INFO)
            logging.basicConfig(
                level=level_value,
                format=LOGGING_FORMAT,
                filename=str(log_path),
                filemode="a",
            )
    
    async def run(self) -> None:
        """Main execution method with progress tracking."""
        wmn_data, wmn_schema = load_wmn_lists(
            local_list_paths=self.config.local_list_paths,
            remote_list_urls=self.config.remote_list_urls,
            skip_validation=self.config.skip_validation,
            local_schema_path=self.config.local_schema_path,
            remote_schema_url=self.config.remote_schema_url
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
            if self.config.self_enumeration:
                results = await self._run_self_enumeration(naminter)
            else:
                results = await self._run_check(naminter)

            if self.config.export_formats and results:
                export_manager = Exporter(self.config.usernames or [], __version__)
                export_manager.export(results, self.config.export_formats)

    async def _run_check(self, naminter: Naminter) -> List[SiteResult]:
        """Run the username enumeration functionality."""
        summary = await naminter.get_wmn_summary(
            site_names=self.config.sites,
            include_categories=self.config.include_categories,
            exclude_categories=self.config.exclude_categories,
        )
        actual_site_count = int(summary.get("sites_count", 0))
        total_sites = actual_site_count * len(self.config.usernames)
        
        tracker = ResultsTracker(total_sites)
        results: List[SiteResult] = []
        
        with ProgressManager(console, disabled=self.config.no_progressbar) as progress_mgr:
            progress_mgr.start(total_sites, "[bright_cyan]Enumerating usernames...[/bright_cyan]")
            
            result_stream = await naminter.enumerate_usernames(
                usernames=self.config.usernames,
                site_names=self.config.sites,
                include_categories=self.config.include_categories,
                exclude_categories=self.config.exclude_categories,
                fuzzy_mode=self.config.fuzzy_mode,
                as_generator=True
            )  

            async for result in result_stream:
                tracker.add_result(result)

                if self._filter_result(result):
                    response_file_path = await self._process_result(result)
                    formatted_output = self._formatter.format_result(result, response_file_path)
                    console.print(formatted_output)
                    results.append(result)

                progress_mgr.update(advance=1, description=tracker.get_progress_text())

        return results

    async def _run_self_enumeration(self, naminter: Naminter) -> List[SelfEnumerationResult]:
        """Run the self-enumeration functionality."""
        summary = await naminter.get_wmn_summary(
            site_names=self.config.sites,
            include_categories=self.config.include_categories,
            exclude_categories=self.config.exclude_categories,
        )
        total_tests = int(summary.get("known_accounts_total", 0))

        tracker = ResultsTracker(total_tests)
        results: List[SelfEnumerationResult] = []

        with ProgressManager(console, disabled=self.config.no_progressbar) as progress_mgr:
            progress_mgr.start(total_tests, "[bright_cyan]Running self-enumeration...[/bright_cyan]")
            
            result_stream = await naminter.self_enumeration(
                site_names=self.config.sites,
                include_categories=self.config.include_categories,
                exclude_categories=self.config.exclude_categories,
                fuzzy_mode=self.config.fuzzy_mode,
                as_generator=True
            )

            async for result in result_stream:
                for site_result in result.results:
                    tracker.add_result(site_result)
                    progress_mgr.update(advance=1, description=tracker.get_progress_text())

                if self._filter_result(result):
                    response_files: List[Optional[Path]] = []
                    for site_result in result.results:
                        response_file_path = await self._process_result(site_result)
                        if response_file_path:
                            response_files.append(response_file_path)
                        else:
                            response_files.append(None)
                    formatted_output = self._formatter.format_self_enumeration(result, response_files)
                    console.print(formatted_output)
                    results.append(result)

        return results
    
    def _filter_result(self, result: Union[SiteResult, SelfEnumerationResult]) -> bool:
        """Determine if a result should be included in output based on filter settings."""
        status = result.status
        
        if self.config.filter_all:
            return True
        
        filter_map = {
            self.config.filter_found: ResultStatus.FOUND,
            self.config.filter_ambiguous: ResultStatus.AMBIGUOUS,
            self.config.filter_unknown: ResultStatus.UNKNOWN,
            self.config.filter_not_found: ResultStatus.NOT_FOUND,
            self.config.filter_not_valid: ResultStatus.NOT_VALID,
            self.config.filter_errors: ResultStatus.ERROR,
        }
        
        return any(
            filter_enabled and status == expected_status 
            for filter_enabled, expected_status in filter_map.items()
        ) or not any(filter_map.keys())

    async def _process_result(self, result: SiteResult) -> Optional[Path]:
        """Process a single result: handle browser opening, response saving, and console output."""
        response_file = None

        if result.result_url and self.config.browse:
            await self._open_browser(result.result_url)

        if self.config.save_response and result.response_text and self._response_dir:
            try:
                safe_site_name = sanitize_filename(result.name)
                safe_username = sanitize_filename(result.username)
                status_str = result.status.value
                created_at_str = result.created_at.strftime(RESPONSE_FILE_DATE_FORMAT)

                base_filename = f"{status_str}_{result.response_code}_{safe_site_name}_{safe_username}_{created_at_str}{RESPONSE_FILE_EXTENSION}"
                response_file = self._response_dir / base_filename

                await self._write_file(response_file, result.response_text)

                if self.config.open_response:
                    file_uri = response_file.resolve().as_uri()
                    await self._open_browser(file_uri)
            except PermissionError as e:
                display_error(f"Permission denied saving response to file: {e}")
            except OSError as e:
                display_error(f"OS error saving response to file: {e}")
            except Exception as e:
                display_error(f"Failed to save response to file: {e}")

        return response_file

    async def _open_browser(self, url: str) -> None:
        """Open a URL in the browser with error handling."""
        try:
            await asyncio.to_thread(webbrowser.open, url)
        except Exception as e:
            display_error(f"Error opening browser for {url}: {e}")

    async def _write_file(self, file_path: Path, content: str) -> None:
        """Write content to a file with error handling."""
        try:
            async with aiofiles.open(file_path, "w", encoding="utf-8") as file:
                await file.write(content)
        except PermissionError as e:
            display_error(f"Permission denied writing to {file_path}: {e}")
        except OSError as e:
            display_error(f"OS error writing to {file_path}: {e}")
        except Exception as e:
            display_error(f"Failed to write to {file_path}: {e}")


@click.group(invoke_without_command=True, no_args_is_help=True, context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--version', is_flag=True, is_eager=True, expose_value=False, callback=_version_callback, help='Show version information and exit')
@click.option('--no-color', is_flag=True, help='Disable colored console output')
@click.option('--no-progressbar', is_flag=True, help='Disable progress bar during execution')
@click.option('--username', '-u', multiple=True, help='Username(s) to search for across social media platforms')
@click.option('--site', '-s', multiple=True, help='Specific site name(s) to enumerate (e.g., "GitHub", "Twitter")')
@click.option('--local-list', type=click.Path(exists=True, path_type=Path), multiple=True, help='Path(s) to local JSON file(s) containing WhatsMyName site data')
@click.option('--remote-list', multiple=True, help='URL(s) to fetch remote WhatsMyName site data')
@click.option('--local-schema', type=click.Path(exists=True, path_type=Path), help='Path to local WhatsMyName JSON schema file for validation')
@click.option('--remote-schema', default=WMN_SCHEMA_URL, help='URL to fetch custom WhatsMyName JSON schema for validation')
@click.option('--skip-validation', is_flag=True, help='Skip JSON schema validation of WhatsMyName data')
@click.option('--self-enumeration', is_flag=True, help='Run self-enumeration mode to validate site detection accuracy')
@click.option('--include-categories', multiple=True, help='Include only sites from specified categories (e.g., "social", "coding")')
@click.option('--exclude-categories', multiple=True, help='Exclude sites from specified categories (e.g., "adult", "gaming")')
@click.option('--proxy', help='Proxy server to use for requests (e.g., http://proxy:port, socks5://proxy:port)')
@click.option('--timeout', type=int, default=HTTP_REQUEST_TIMEOUT_SECONDS, help='Maximum time in seconds to wait for each HTTP request')
@click.option('--allow-redirects', is_flag=True, default=HTTP_ALLOW_REDIRECTS, help='Whether to follow HTTP redirects automatically')
@click.option('--verify-ssl', is_flag=True, default=HTTP_SSL_VERIFY, help='Whether to verify SSL/TLS certificates for HTTPS requests')
@click.option('--impersonate', type=click.Choice(["none", *typing.get_args(BrowserTypeLiteral)]), default="chrome", help='Browser to impersonate in HTTP requests (use "none" to disable)')
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
@click.option('--filter-found', is_flag=True, help='Show only found results in console output and exports')
@click.option('--filter-ambiguous', is_flag=True, help='Show only ambiguous results in console output and exports')
@click.option('--filter-unknown', is_flag=True, help='Show only unknown results in console output and exports')
@click.option('--filter-not-found', is_flag=True, help='Show only not found results in console output and exports')
@click.option('--filter-not-valid', is_flag=True, help='Show only not valid results in console output and exports')
@click.option('--filter-errors', is_flag=True, help='Show only error results in console output and exports')
@click.pass_context
def main(ctx: click.Context, **kwargs: Any) -> None:
    """Asynchronous OSINT username enumeration tool that searches hundreds of websites using the WhatsMyName dataset."""

    if ctx.invoked_subcommand is not None:
        return
    
    if kwargs.get('no_color'):
        console.no_color = True

    try:
        config = NaminterConfig(
            usernames=kwargs.get('username'),
            sites=kwargs.get('site'),
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
            impersonate=kwargs.get('impersonate'),
            ja3=kwargs.get('ja3'),
            akamai=kwargs.get('akamai'),
            extra_fp=kwargs.get('extra_fp'),
            fuzzy_mode=kwargs.get('fuzzy_mode'),
            self_enumeration=kwargs.get('self_enumeration'),
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
            filter_found=kwargs.get('filter_found'),
            filter_ambiguous=kwargs.get('filter_ambiguous'),
            filter_unknown=kwargs.get('filter_unknown'),
            filter_not_found=kwargs.get('filter_not_found'),
            filter_not_valid=kwargs.get('filter_not_valid'),
            filter_errors=kwargs.get('filter_errors'),
            no_progressbar=kwargs.get('no_progressbar'),
        )

        NaminterCLI._setup_logging(config)
        
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