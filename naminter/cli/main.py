import asyncio
import logging
import typing
from pathlib import Path
from typing import Any, Final

import rich_click as click
from curl_cffi import BrowserTypeLiteral

from naminter.cli.config import NaminterConfig
from naminter.cli.console import (
    ResultFormatter,
    console,
    display_error,
    display_validation_errors,
    display_version,
    display_warning,
)
from naminter.cli.constants import (
    EXIT_CODE_ERROR,
    PROGRESS_ADVANCE_INCREMENT,
)
from naminter.cli.exporters import Exporter
from naminter.cli.progress import ProgressManager, ResultsTracker
from naminter.cli.utils import (
    fetch_json,
    generate_response_filename,
    open_browser,
    read_json,
    write_file,
)
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    DEFAULT_FILE_ENCODING,
    HTTP_ALLOW_REDIRECTS,
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HTTP_SSL_VERIFY,
    LOGGING_FORMAT,
    MAX_CONCURRENT_TASKS,
    WMN_SCHEMA_URL,
)
from naminter.core.exceptions import HttpError, WMNDataError, WMNValidationError
from naminter.core.main import Naminter
from naminter.core.models import WMNMode, WMNResult, WMNStatus, WMNValidationResult
from naminter.core.network import CurlCFFISession

from .exceptions import BrowserError, ConfigurationError, ExportError, FileIOError


def _version_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Eager callback to display version and exit."""
    if not value or ctx.resilient_parsing:
        return
    display_version()
    ctx.exit()


class NaminterCLI:
    """Handles username enumeration operations."""

    def __init__(self, config: NaminterConfig) -> None:
        self.config: NaminterConfig = config
        self._formatter: ResultFormatter = ResultFormatter(
            show_details=config.show_details
        )
        self._response_dir: Path | None = self._setup_response_dir()
        self._status_filters: Final[dict[WMNStatus, bool]] = {
            WMNStatus.FOUND: config.filter_found,
            WMNStatus.AMBIGUOUS: config.filter_ambiguous,
            WMNStatus.UNKNOWN: config.filter_unknown,
            WMNStatus.NOT_FOUND: config.filter_not_found,
            WMNStatus.NOT_VALID: config.filter_not_valid,
            WMNStatus.ERROR: config.filter_errors,
        }

    def _setup_response_dir(self) -> Path | None:
        """Setup response directory if response saving is enabled."""
        if not self.config.save_response:
            return None

        try:
            dir_path = self.config.response_dir
            if dir_path is not None:
                dir_path.mkdir(parents=True, exist_ok=True)
                return dir_path
            return None
        except PermissionError as e:
            display_error(
                f"Permission denied creating/accessing response directory: {e}"
            )
            return None
        except OSError as e:
            display_error(f"OS error creating/accessing response directory: {e}")
            return None
        except Exception as e:
            display_error(f"Unexpected error setting up response directory: {e}")
            return None

    @staticmethod
    def setup_logging(config: NaminterConfig) -> None:
        """Configure project logging."""
        if not config.log_file:
            return

        log_path = Path(config.log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as e:
            msg = f"Failed to create log directory {log_path.parent}: {e}"
            raise FileIOError(msg) from e

        level_value = getattr(
            logging, str(config.log_level or "INFO").upper(), logging.INFO
        )

        logger = logging.getLogger("naminter")
        logger.setLevel(level_value)
        logger.propagate = False

        has_file_handler = any(
            isinstance(handler, logging.FileHandler) for handler in logger.handlers
        )
        if not has_file_handler:
            try:
                file_handler = logging.FileHandler(
                    str(log_path),
                    mode="a",
                    encoding=DEFAULT_FILE_ENCODING,
                )
                formatter = logging.Formatter(LOGGING_FORMAT)
                file_handler.setFormatter(formatter)
                file_handler.setLevel(level_value)
                logger.addHandler(file_handler)
            except (PermissionError, OSError) as e:
                msg = f"Failed to create log file {log_path}: {e}"
                raise FileIOError(msg) from e

    async def run(self) -> None:
        """Main execution method with progress tracking."""
        http_client = CurlCFFISession(
            proxies=self.config.proxy,
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            allow_redirects=self.config.allow_redirects,
            impersonate=self.config.impersonate,
            ja3=self.config.ja3,
            akamai=self.config.akamai,
            extra_fp=self.config.extra_fp,
        )

        wmn_data: dict[str, Any] | None = None
        if self.config.local_list_path:
            wmn_data = await read_json(self.config.local_list_path)
        elif self.config.remote_list_url:
            wmn_data = await fetch_json(http_client, self.config.remote_list_url)

        wmn_schema: dict[str, Any] | None = None
        if not self.config.skip_validation:
            if self.config.local_schema_path:
                wmn_schema = await read_json(self.config.local_schema_path)
            elif self.config.remote_schema_url:
                wmn_schema = await fetch_json(
                    http_client, self.config.remote_schema_url
                )

        async with Naminter(
            http_client=http_client,
            wmn_data=wmn_data,
            wmn_schema=wmn_schema,
            max_tasks=self.config.max_tasks,
        ) as naminter:
            if self.config.validate_sites:
                results = await self._run_validation(naminter)
            else:
                results = await self._run_check(naminter)

            if self.config.export_formats and results:
                exporter = Exporter(self.config.usernames or [])
                exporter.export(results, self.config.export_formats)

    async def _run_check(self, naminter: Naminter) -> list[WMNResult]:
        """Run the username enumeration functionality."""
        summary = await naminter.get_wmn_summary(
            site_names=self.config.sites,
            include_categories=self.config.include_categories,
            exclude_categories=self.config.exclude_categories,
        )
        actual_site_count = summary.sites_count
        total_sites = actual_site_count * len(self.config.usernames)

        tracker = ResultsTracker(total_sites)
        results: list[WMNResult] = []

        with ProgressManager(
            console, disabled=self.config.no_progressbar
        ) as progress_mgr:
            progress_mgr.start(
                total_sites, "[bright_cyan]Enumerating usernames...[/bright_cyan]"
            )

            result_stream = await naminter.enumerate_usernames(
                usernames=self.config.usernames,
                site_names=self.config.sites,
                include_categories=self.config.include_categories,
                exclude_categories=self.config.exclude_categories,
                mode=self.config.mode,
                as_generator=True,
            )

            async for result in result_stream:
                tracker.add_result(result)

                if self._filter_result(result):
                    try:
                        file_path = await self._process_result(result)
                        formatted_output = self._formatter.format_result(
                            result, file_path
                        )
                        console.print(formatted_output)
                        results.append(result)
                    except Exception as e:
                        display_error(f"Error processing result for {result.name}: {e}")

                progress_mgr.update(
                    advance=PROGRESS_ADVANCE_INCREMENT,
                    description=tracker.get_progress_text(),
                )

        return results

    async def _run_validation(self, naminter: Naminter) -> list[WMNValidationResult]:
        """Run the site validation functionality."""
        summary = await naminter.get_wmn_summary(
            site_names=self.config.sites,
            include_categories=self.config.include_categories,
            exclude_categories=self.config.exclude_categories,
        )
        total_tests = summary.known_count

        tracker = ResultsTracker(total_tests)
        results: list[WMNValidationResult] = []

        with ProgressManager(
            console, disabled=self.config.no_progressbar
        ) as progress_mgr:
            progress_mgr.start(
                total_tests,
                "[bright_cyan]Validating sites...[/bright_cyan]",
            )

            result_stream = await naminter.validate_sites(
                site_names=self.config.sites,
                include_categories=self.config.include_categories,
                exclude_categories=self.config.exclude_categories,
                mode=self.config.mode,
                as_generator=True,
            )

            async for result in result_stream:
                for site_result in result.results:
                    tracker.add_result(site_result)
                    progress_mgr.update(
                        advance=PROGRESS_ADVANCE_INCREMENT,
                        description=tracker.get_progress_text(),
                    )

                if self._filter_result(result):
                    try:
                        response_files: list[Path | None] = []
                        for site_result in result.results:
                            response_file_path = await self._process_result(site_result)
                            if response_file_path:
                                response_files.append(response_file_path)
                            else:
                                response_files.append(None)
                        formatted_output = self._formatter.format_validation(
                            result, response_files
                        )
                        console.print(formatted_output)
                        results.append(result)
                    except Exception as e:
                        display_error(
                            f"Error processing validation result for {result.name}: {e}"
                        )

        return results

    def _filter_result(self, result: WMNResult | WMNValidationResult) -> bool:
        """Determine if a result should be included based on filter settings."""
        if self.config.filter_all:
            return True

        return self._status_filters.get(result.status, False)

    async def _process_result(self, result: WMNResult) -> Path | None:
        """Handle browser opening, response saving, and console output for a result."""
        if result.url and self.config.browse:
            try:
                await open_browser(result.url)
            except BrowserError as e:
                display_error(str(e))

        if not self.config.save_response:
            return None

        if not result.response_text or not self._response_dir:
            return None

        filename = generate_response_filename(result)
        file_path = self._response_dir / filename

        try:
            await write_file(file_path, result.response_text)
        except FileIOError as e:
            display_error(str(e))
            return None

        if self.config.open_response:
            file_uri = file_path.resolve().as_uri()
            try:
                await open_browser(file_uri)
            except BrowserError as e:
                display_error(str(e))

        return file_path


@click.group(
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_version_callback,
    help="Show version information and exit",
)
@click.option("--no-color", is_flag=True, help="Disable colored console output")
@click.option(
    "--no-progressbar", is_flag=True, help="Disable progress bar during execution"
)
@click.option(
    "--username",
    "-u",
    multiple=True,
    help="Username(s) to search for across social media platforms",
)
@click.option(
    "--site",
    "-s",
    multiple=True,
    help='Specific site name(s) to enumerate (e.g., "GitHub", "X")',
)
@click.option(
    "--local-list",
    type=click.Path(exists=True, path_type=Path),
    help="Path to a local JSON file containing WhatsMyName site data",
)
@click.option("--remote-list", help="URL to fetch remote WhatsMyName site data")
@click.option(
    "--local-schema",
    type=click.Path(exists=True, path_type=Path),
    help="Path to local WhatsMyName JSON schema file for validation",
)
@click.option(
    "--remote-schema",
    default=WMN_SCHEMA_URL,
    help=(
        "URL to fetch WhatsMyName JSON schema for validation "
        "(ignored with --skip-validation)"
    ),
)
@click.option(
    "--skip-validation",
    is_flag=True,
    help="Skip JSON schema validation of WhatsMyName data",
)
@click.option(
    "--validate-sites",
    is_flag=True,
    help="Validate site detection methods by checking known usernames",
)
@click.option(
    "--include-categories",
    multiple=True,
    help='Include only sites from specified categories (e.g., "social", "coding")',
)
@click.option(
    "--exclude-categories",
    multiple=True,
    help='Exclude sites from specified categories (e.g., "adult", "gaming")',
)
@click.option(
    "--proxy",
    help="Proxy server to use for requests (e.g., http://proxy:port, socks5://proxy:port)",
)
@click.option(
    "--timeout",
    type=int,
    default=HTTP_REQUEST_TIMEOUT_SECONDS,
    help="Maximum time in seconds to wait for each HTTP request",
)
@click.option(
    "--allow-redirects",
    is_flag=True,
    default=HTTP_ALLOW_REDIRECTS,
    help="Whether to follow HTTP redirects automatically",
)
@click.option(
    "--verify-ssl",
    is_flag=True,
    default=HTTP_SSL_VERIFY,
    help="Whether to verify SSL/TLS certificates for HTTPS requests",
)
@click.option(
    "--impersonate",
    type=click.Choice([BROWSER_IMPERSONATE_NONE, *typing.get_args(BrowserTypeLiteral)]),
    default=BROWSER_IMPERSONATE_AGENT,
    help='Browser to impersonate in HTTP requests (use "none" to disable)',
)
@click.option("--ja3", help="JA3 fingerprint string for TLS fingerprinting")
@click.option(
    "--akamai", help="Akamai fingerprint string for Akamai bot detection bypass"
)
@click.option(
    "--extra-fp",
    help=(
        "Extra fingerprinting options as JSON string (e.g., '"
        '{"tls_grease": true, "tls_cert_compression": "brotli"}'
        ")"
    ),
)
@click.option(
    "--max-tasks",
    type=int,
    default=MAX_CONCURRENT_TASKS,
    help="Maximum number of concurrent tasks",
)
@click.option(
    "--mode",
    type=click.Choice([WMNMode.ANY.value, WMNMode.ALL.value]),
    default=WMNMode.ALL.value,
    help="Validation mode: 'all' for strict (AND), 'any' for fuzzy (OR)",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set logging level",
)
@click.option("--log-file", help="Path to log file for debug output")
@click.option(
    "--show-details", is_flag=True, help="Show detailed information in console output"
)
@click.option("--browse", is_flag=True, help="Open found profiles in web browser")
@click.option(
    "--save-response",
    "save_response_opt",
    type=str,
    flag_value="__AUTO__",
    default=None,
    help="Save HTTP responses; optionally specify directory path",
)
@click.option(
    "--open-response", is_flag=True, help="Open saved response files in web browser"
)
@click.option(
    "--csv",
    "csv_opt",
    type=str,
    flag_value="__AUTO__",
    default=None,
    help="Export results to CSV; optionally specify a custom path",
)
@click.option(
    "--pdf",
    "pdf_opt",
    type=str,
    flag_value="__AUTO__",
    default=None,
    help="Export results to PDF; optionally specify a custom path",
)
@click.option(
    "--html",
    "html_opt",
    type=str,
    flag_value="__AUTO__",
    default=None,
    help="Export results to HTML; optionally specify a custom path",
)
@click.option(
    "--json",
    "json_opt",
    type=str,
    flag_value="__AUTO__",
    default=None,
    help="Export results to JSON; optionally specify a custom path",
)
@click.option(
    "--filter-all",
    is_flag=True,
    help="Include all results in console output and exports",
)
@click.option(
    "--filter-found",
    is_flag=True,
    help="Show only found results in console output and exports",
)
@click.option(
    "--filter-ambiguous",
    is_flag=True,
    help="Show only ambiguous results in console output and exports",
)
@click.option(
    "--filter-unknown",
    is_flag=True,
    help="Show only unknown results in console output and exports",
)
@click.option(
    "--filter-not-found",
    is_flag=True,
    help="Show only not found results in console output and exports",
)
@click.option(
    "--filter-not-valid",
    is_flag=True,
    help="Show only not valid results in console output and exports",
)
@click.option(
    "--filter-errors",
    is_flag=True,
    help="Show only error results in console output and exports",
)
@click.pass_context
def main(ctx: click.Context, **kwargs: Any) -> None:
    """A Python package and command-line interface (CLI) tool.
    For asynchronous OSINT username enumeration using the
    WhatsMyName dataset.
    """

    if ctx.invoked_subcommand is not None:
        return

    if kwargs.get("no_color"):
        console.no_color = True

    try:
        csv_export = kwargs.get("csv_opt") is not None
        csv_path = (
            None
            if kwargs.get("csv_opt") in {None, "__AUTO__"}
            else kwargs.get("csv_opt")
        )

        pdf_export = kwargs.get("pdf_opt") is not None
        pdf_path = (
            None
            if kwargs.get("pdf_opt") in {None, "__AUTO__"}
            else kwargs.get("pdf_opt")
        )

        html_export = kwargs.get("html_opt") is not None
        html_path = (
            None
            if kwargs.get("html_opt") in {None, "__AUTO__"}
            else kwargs.get("html_opt")
        )

        json_export = kwargs.get("json_opt") is not None
        json_path = (
            None
            if kwargs.get("json_opt") in {None, "__AUTO__"}
            else kwargs.get("json_opt")
        )

        save_response = kwargs.get("save_response_opt") is not None
        response_path = (
            None
            if kwargs.get("save_response_opt") in {None, "__AUTO__"}
            else kwargs.get("save_response_opt")
        )

        config = NaminterConfig(
            usernames=list(kwargs.get("username") or []),
            sites=kwargs.get("site"),
            local_list_path=kwargs.get("local_list"),
            remote_list_url=kwargs.get("remote_list"),
            local_schema_path=kwargs.get("local_schema"),
            remote_schema_url=kwargs.get("remote_schema"),
            skip_validation=kwargs.get("skip_validation"),
            include_categories=kwargs.get("include_categories"),
            exclude_categories=kwargs.get("exclude_categories"),
            max_tasks=kwargs.get("max_tasks"),
            timeout=kwargs.get("timeout"),
            proxy=kwargs.get("proxy"),
            allow_redirects=bool(kwargs.get("allow_redirects")),
            verify_ssl=bool(kwargs.get("verify_ssl")),
            impersonate=kwargs.get("impersonate"),
            ja3=kwargs.get("ja3"),
            akamai=kwargs.get("akamai"),
            extra_fp=kwargs.get("extra_fp"),
            mode=WMNMode(kwargs.get("mode", WMNMode.ALL.value)),
            validate_sites=bool(kwargs.get("validate_sites")),
            log_level=kwargs.get("log_level"),
            log_file=kwargs.get("log_file"),
            show_details=bool(kwargs.get("show_details")),
            browse=bool(kwargs.get("browse")),
            save_response=save_response,
            response_path=response_path,
            open_response=bool(kwargs.get("open_response")),
            csv_export=csv_export,
            csv_path=csv_path,
            pdf_export=pdf_export,
            pdf_path=pdf_path,
            html_export=html_export,
            html_path=html_path,
            json_export=json_export,
            json_path=json_path,
            filter_all=bool(kwargs.get("filter_all")),
            filter_found=bool(kwargs.get("filter_found")),
            filter_ambiguous=bool(kwargs.get("filter_ambiguous")),
            filter_unknown=bool(kwargs.get("filter_unknown")),
            filter_not_found=bool(kwargs.get("filter_not_found")),
            filter_not_valid=bool(kwargs.get("filter_not_valid")),
            filter_errors=bool(kwargs.get("filter_errors")),
            no_progressbar=bool(kwargs.get("no_progressbar")),
        )

        NaminterCLI.setup_logging(config)

        naminter_cli = NaminterCLI(config)
        asyncio.run(naminter_cli.run())
    except KeyboardInterrupt:
        display_warning("Operation interrupted")
        ctx.exit(EXIT_CODE_ERROR)
    except ConfigurationError as e:
        display_error(f"Configuration error: {e}")
        ctx.exit(EXIT_CODE_ERROR)
    except HttpError as e:
        display_error(f"Network error: {e}")
        ctx.exit(EXIT_CODE_ERROR)
    except WMNDataError as e:
        display_error(f"Data error: {e}")
        if isinstance(e, WMNValidationError) and e.errors:
            display_validation_errors(e.errors)
        ctx.exit(EXIT_CODE_ERROR)
    except FileIOError as e:
        display_error(f"File I/O error: {e}")
        ctx.exit(EXIT_CODE_ERROR)
    except ExportError as e:
        display_error(f"Export error: {e}")
        ctx.exit(EXIT_CODE_ERROR)
    except Exception as e:
        display_error(f"Unexpected error: {e}")
        ctx.exit(EXIT_CODE_ERROR)


def entry_point() -> None:
    """Entry point for the application."""
    main()


if __name__ == "__main__":
    entry_point()
