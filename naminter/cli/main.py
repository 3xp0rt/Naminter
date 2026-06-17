"""CLI entry point, Click commands, and error handling for Naminter."""

from collections.abc import Callable
from functools import wraps
import logging
from pathlib import Path
from typing import Any, Final, get_args

from curl_cffi import BrowserTypeLiteral
import orjson
from pathvalidate.click import validate_filepath_arg
import rich_click as click
import uvloop

from naminter.cli.config import NaminterConfig
from naminter.cli.console import (
    ResultFormatter,
    console,
    display_diff,
    display_error,
    display_errors,
    display_version,
    display_warning,
)
from naminter.cli.constants import (
    EXIT_CODE_ERROR,
    EXIT_CODE_INTERRUPTED,
)
from naminter.cli.exceptions import (
    BrowserError,
    CLIError,
    FileError,
)
from naminter.cli.exporters import Exporter
from naminter.cli.progress import ProgressBar
from naminter.cli.utils import (
    fetch_json,
    get_response_filename,
    open_url,
    read_file,
    read_json,
    write_file,
)
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    DEFAULT_FILE_ENCODING,
    HTTP_ALLOW_REDIRECTS,
    HTTP_SSL_VERIFY,
    HTTP_TIMEOUT,
    LOGGING_FORMAT,
    MAX_CONCURRENT_TASKS,
    WMN_SCHEMA_URL,
)
from naminter.core.exceptions import NaminterError, WMNValidationError
from naminter.core.formatter import WMNFormatter
from naminter.core.main import Naminter
from naminter.core.models import (
    WMNMode,
    WMNResult,
    WMNStatus,
    WMNTestResult,
)
from naminter.core.network import CurlCFFISession
from naminter.core.validator import WMNValidator


def _version_callback(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,  # noqa: FBT001
) -> None:
    """Eager callback to display version and exit.

    Args:
        ctx: Click context for the current invocation.
        _param: The Click parameter that triggered this callback.
        value: Whether the version flag was set.
    """
    if not value or ctx.resilient_parsing:
        return
    display_version()
    ctx.exit()


class NaminterCLI:
    """Handles username enumeration operations."""

    def __init__(self, config: NaminterConfig) -> None:
        """Initialize the CLI handler with configuration.

        Args:
            config: Validated configuration for the CLI session.
        """
        self._config: NaminterConfig = config
        self._formatter: ResultFormatter = ResultFormatter(
            verbose=config.verbose,
        )
        self._response_dir: Path | None = self._setup_response_dir()
        self._status_filters: Final[dict[WMNStatus, bool]] = (
            self._create_status_filters()
        )

    def _create_status_filters(self) -> dict[WMNStatus, bool]:
        """Create status filter mapping from config.

        Returns:
            dict[WMNStatus, bool]: Mapping of statuses to their filter flags.
        """
        return {
            WMNStatus.EXISTS: self._config.filter_exists,
            WMNStatus.PARTIAL_EXISTS: self._config.filter_partial,
            WMNStatus.PARTIAL_MISSING: self._config.filter_partial,
            WMNStatus.CONFLICTING: self._config.filter_conflicting,
            WMNStatus.UNKNOWN: self._config.filter_unknown,
            WMNStatus.MISSING: self._config.filter_missing,
            WMNStatus.NOT_VALID: self._config.filter_not_valid,
            WMNStatus.ERROR: self._config.filter_errors,
        }

    def _setup_response_dir(self) -> Path | None:
        """Setup response directory if response saving is enabled.

        Returns:
            Path | None: Path to response directory if enabled, None otherwise.
        """
        if not self._config.save_response:
            return None

        dir_path = self._config.response_dir_path
        if dir_path is None:
            return None

        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            display_warning(
                f"Permission denied creating response directory: {e}",
            )
            return None
        except OSError as e:
            display_warning(
                f"OS error creating response directory: {e}",
            )
            return None

        return dir_path

    @staticmethod
    def setup_logging(config: NaminterConfig) -> None:
        """Configure project logging.

        Args:
            config: Configuration containing log file and level settings.

        Raises:
            OSError: If log directory or file creation fails.
        """
        if not config.log_file:
            return

        log_path = Path(config.log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as e:
            msg = f"Failed to create log directory {log_path.parent}: {e}"
            raise OSError(msg) from e

        level_value = getattr(
            logging,
            str(config.log_level or "INFO").upper(),
            logging.INFO,
        )

        logger = logging.getLogger("naminter")
        logger.setLevel(level_value)
        logger.propagate = False

        for handler in logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                handler.close()
                logger.removeHandler(handler)

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
            raise OSError(msg) from e

    async def run(self) -> None:
        """Load data, validate, run enumeration or testing, and export results.

        Raises:
            FileError: If data loading or remote fetching fails.
            NetworkError: If remote resource fetching fails.
            ExportError: If result exporting fails.
            HttpSessionError: If HTTP session initialization fails.
            WMNUninitializedError: If WMN data is not provided.
            WMNDataError: If WMN data loading fails.
            WMNValidationError: If data validation fails.
        """
        async with CurlCFFISession(
            proxies=self._config.proxy,
            verify=self._config.verify_ssl,
            timeout=self._config.timeout,
            allow_redirects=self._config.allow_redirects,
            impersonate=self._config.impersonate,
            ja3=self._config.ja3,
            akamai=self._config.akamai,
            extra_fp=self._config.extra_fp,
        ) as http_client:
            data = None
            if self._config.local_data:
                data = await read_json(self._config.local_data)
            elif self._config.remote_data:
                data = await fetch_json(http_client, self._config.remote_data)
                if not isinstance(data, dict):
                    msg = "Remote data must be a JSON object"
                    raise FileError(msg)

            schema = None
            if not self._config.skip_validation:
                if self._config.local_schema:
                    schema = await read_json(self._config.local_schema)
                elif self._config.remote_schema:
                    schema = await fetch_json(
                        http_client,
                        self._config.remote_schema,
                    )
                    if not isinstance(schema, dict):
                        msg = "Remote schema must be a JSON object"
                        raise FileError(msg)

            async with Naminter(
                http_client=http_client,
                data=data,
                schema=schema,
                max_tasks=self._config.max_tasks,
            ) as naminter:
                if self._config.test:
                    results = await self._run_validation(naminter)
                else:
                    results = await self._run_check(naminter)

                if self._config.export_formats and results:
                    exporter = Exporter(self._config.usernames or [])
                    await exporter.export(
                        results,
                        self._config.export_formats,
                    )

    async def _run_check(self, naminter: Naminter) -> list[WMNResult]:
        """Run the username enumeration functionality.

        Args:
            naminter: Initialized Naminter instance to enumerate with.

        Returns:
            list[WMNResult]: Filtered results from the enumeration.
        """
        summary = naminter.summary(
            site_names=self._config.sites,
            include_categories=self._config.include_categories,
            exclude_categories=self._config.exclude_categories,
        )
        actual_site_count = summary.sites_count
        username_count = len(self._config.usernames) if self._config.usernames else 0
        total_sites = actual_site_count * username_count

        results: list[WMNResult] = []

        if total_sites == 0:
            return results

        progress_bar = ProgressBar(console, disabled=self._config.no_progressbar)
        progress_bar.start(
            total_sites,
            "[bright_cyan]Enumerating usernames...[/bright_cyan]",
        )

        async for result in naminter.enumerate_usernames(
            usernames=self._config.usernames,
            site_names=self._config.sites,
            include_categories=self._config.include_categories,
            exclude_categories=self._config.exclude_categories,
            mode=self._config.mode,
            exclude_text=not self._config.save_response,
        ):
            progress_bar.add_result(result)

            if self._filter_result(result):
                try:
                    file_path = await self._save_response(result)
                    await self._open_in_browser(result, file_path)
                    result_tree = self._formatter.format_result(result, file_path)
                    console.print(result_tree)
                    results.append(result)
                except (FileError, BrowserError) as e:
                    display_error(
                        f"Error processing result for {result.name} "
                        f"(status={result.status.value}): {e}",
                    )

        progress_bar.stop()
        return results

    async def _run_validation(self, naminter: Naminter) -> list[WMNTestResult]:
        """Run the site validation functionality.

        Args:
            naminter: Initialized Naminter instance to validate with.

        Returns:
            list[WMNTestResult]: Filtered results from site validation.
        """
        summary = naminter.summary(
            site_names=self._config.sites,
            include_categories=self._config.include_categories,
            exclude_categories=self._config.exclude_categories,
        )
        total_tests = summary.known_count

        results: list[WMNTestResult] = []

        if total_tests == 0:
            return results

        progress_bar = ProgressBar(console, disabled=self._config.no_progressbar)
        progress_bar.start(
            total_tests,
            "[bright_cyan]Running testing...[/bright_cyan]",
        )

        async for result in naminter.test_enumeration(
            site_names=self._config.sites,
            include_categories=self._config.include_categories,
            exclude_categories=self._config.exclude_categories,
            mode=self._config.mode,
            exclude_text=not self._config.save_response,
        ):
            if result.results:
                for site_result in result.results:
                    progress_bar.add_result(site_result)

            if self._filter_result(result):
                try:
                    response_files: list[Path | None] = []
                    if result.results:
                        for site_result in result.results:
                            file_path = await self._save_response(site_result)
                            await self._open_in_browser(site_result, file_path)
                            response_files.append(file_path)
                    result_tree = self._formatter.format_validation(
                        result,
                        response_files,
                    )
                    console.print(result_tree)
                    results.append(result)
                except (FileError, BrowserError) as e:
                    display_error(
                        f"Error processing validation result for {result.name}: {e}",
                    )

        progress_bar.stop()
        return results

    def _filter_result(self, result: WMNResult | WMNTestResult) -> bool:
        """Determine if a result should be included based on filter settings.

        Args:
            result: The result to evaluate against active filters.

        Returns:
            bool: True if the result passes the active filters.
        """
        if self._config.filter_all:
            return True

        return self._status_filters.get(result.status, False)

    async def _open_in_browser(self, result: WMNResult, file_path: Path | None) -> None:
        """Open result URL and saved response file in browser if configured.

        Args:
            result: The WMN result containing URL information.
            file_path: Path to saved response file, if any.
        """
        if self._config.browse and result.uri_pretty:
            try:
                await open_url(result.uri_pretty)
            except BrowserError as e:
                display_error(f"Browser error opening {result.uri_pretty}: {e}")

        if self._config.open_response and file_path:
            try:
                await open_url(file_path)
            except BrowserError as e:
                display_error(f"Browser error opening response file {file_path}: {e}")

    async def _save_response(self, result: WMNResult) -> Path | None:
        """Save HTTP response to file if configured.

        Args:
            result: The WMN result containing the response text to save.

        Returns:
            Path | None: Path to the saved file, or None if not saved.
        """
        if not self._config.save_response:
            return None

        if not result.text or not self._response_dir:
            return None

        filename = get_response_filename(result)
        file_path = self._response_dir / filename

        try:
            await write_file(file_path, result.text)
        except FileError as e:
            display_error(f"Failed to save response file {file_path}: {e}")
            return None

        return file_path


def cli_error_handler(
    func: Callable[..., None],
) -> Callable[..., None]:
    """Decorator to centralize CLI error handling.

    Handles KeyboardInterrupt and common CLI exceptions for Click commands.
    The decorated function must accept `ctx` as its first parameter.

    Args:
        func: The Click command function to wrap.

    Returns:
        Callable[..., None]: Wrapped function with error handling.
    """

    @wraps(func)
    def wrapper(
        ctx: click.Context,
        *args: object,
        **kwargs: object,
    ) -> None:
        try:
            func(ctx, *args, **kwargs)
        except KeyboardInterrupt:
            display_warning("Operation interrupted")
            ctx.exit(EXIT_CODE_INTERRUPTED)
        except (CLIError, NaminterError) as e:
            if isinstance(e, WMNValidationError):
                display_error(str(e), end="")
                if e.schema_errors:
                    display_errors(e.schema_errors, "Schema Errors")
                if e.data_errors:
                    display_errors(e.data_errors, "Data Errors")
            else:
                display_error(str(e))
            ctx.exit(EXIT_CODE_ERROR)
        except Exception as e:  # noqa: BLE001
            display_error(f"Unexpected error: {type(e).__name__}: {e}")
            ctx.exit(EXIT_CODE_ERROR)

    return wrapper


@click.group(
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
# Version & Help
@click.option(
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_version_callback,
    help="Show version information and exit",
)
# Display & Output Formatting
@click.option("--no-color", is_flag=True, help="Disable colored console output")
@click.option(
    "--no-progressbar",
    is_flag=True,
    help="Disable progress bar during execution",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase output verbosity (-v errors, -vv details, -vvv headers)",
)
# Input Specification
@click.option(
    "--username",
    "-u",
    multiple=True,
    required=False,
    help=(
        "Username(s) to search for across social media platforms "
        "(required unless --test)"
    ),
)
@click.option(
    "--site",
    "-s",
    multiple=True,
    help='Specific site name(s) to enumerate (e.g., "GitHub", "X")',
)
# Data Sources - Local
@click.option(
    "--local-data",
    type=click.Path(exists=True, path_type=Path),
    help="Path to local WhatsMyName JSON data file",
)
@click.option(
    "--local-schema",
    type=click.Path(exists=True, path_type=Path),
    help="Path to local WhatsMyName JSON schema file for validation",
)
# Data Sources - Remote
@click.option("--remote-data", help="URL to fetch remote WhatsMyName site data")
@click.option(
    "--remote-schema",
    default=WMN_SCHEMA_URL,
    help=(
        "URL to fetch WhatsMyName JSON schema for validation "
        "(ignored with --skip-validation)"
    ),
)
# Validation
@click.option(
    "--skip-validation",
    is_flag=True,
    help="Skip JSON schema validation of WhatsMyName data",
)
@click.option(
    "--test",
    is_flag=True,
    help="Validate site detection methods by checking known usernames",
)
# Category Filtering
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
# Network Configuration
@click.option(
    "--proxy",
    help="Proxy server to use for requests (e.g., http://proxy:port, socks5://proxy:port)",
)
@click.option(
    "--timeout",
    type=click.IntRange(1, 300),
    default=HTTP_TIMEOUT,
    help="Maximum time in seconds to wait for each HTTP request",
)
@click.option(
    "--allow-redirects/--no-allow-redirects",
    default=HTTP_ALLOW_REDIRECTS,
    help="Whether to follow HTTP redirects automatically",
)
@click.option(
    "--verify-ssl/--no-verify-ssl",
    default=HTTP_SSL_VERIFY,
    help="Verify SSL certificates",
)
@click.option(
    "--impersonate",
    type=click.Choice([BROWSER_IMPERSONATE_NONE, *get_args(BrowserTypeLiteral)]),
    default=BROWSER_IMPERSONATE_AGENT,
    help='Browser to impersonate in HTTP requests (use "none" to disable)',
)
# Fingerprinting Options
@click.option("--ja3", help="JA3 fingerprint string for TLS fingerprinting")
@click.option(
    "--akamai",
    help="Akamai fingerprint string for Akamai bot detection bypass",
)
@click.option(
    "--extra-fp",
    help=(
        "Extra fingerprinting options as JSON string (e.g., '"
        '{"tls_grease": true, "tls_cert_compression": "brotli"}'
        ")"
    ),
)
# Concurrency & Debugging
@click.option(
    "--max-tasks",
    type=click.IntRange(1, 1000),
    default=MAX_CONCURRENT_TASKS,
    help="Maximum number of concurrent tasks",
)
@click.option(
    "--mode",
    type=click.Choice([WMNMode.ANY.value, WMNMode.ALL.value]),
    default=WMNMode.ALL.value,
    help="Validation mode: all or any",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set logging level",
)
@click.option("--log-file", help="Path to log file")
# Response Handling
@click.option(
    "--save-response",
    is_flag=True,
    help="Save HTTP responses",
)
@click.option(
    "--response-dir",
    callback=validate_filepath_arg,
    type=click.Path(file_okay=False, dir_okay=True),
    default=None,
    help="Custom directory for responses",
)
@click.option(
    "--open-response",
    is_flag=True,
    help="Open response files in browser",
)
@click.option("--browse", is_flag=True, help="Open found profiles in web browser")
# Export Options
@click.option(
    "--csv",
    is_flag=True,
    help="Export results to CSV",
)
@click.option(
    "--csv-path",
    callback=validate_filepath_arg,
    default=None,
    help="CSV export file path",
)
@click.option(
    "--json",
    is_flag=True,
    help="Export results to JSON",
)
@click.option(
    "--json-path",
    callback=validate_filepath_arg,
    default=None,
    help="JSON export file path",
)
@click.option(
    "--html",
    is_flag=True,
    help="Export results to HTML",
)
@click.option(
    "--html-path",
    callback=validate_filepath_arg,
    default=None,
    help="HTML export file path",
)
@click.option(
    "--pdf",
    is_flag=True,
    help="Export results to PDF",
)
@click.option(
    "--pdf-path",
    callback=validate_filepath_arg,
    default=None,
    help="PDF export file path",
)
# Result Filtering
@click.option(
    "--filter-all",
    is_flag=True,
    help="Include all results in console output and exports",
)
@click.option(
    "--filter-exists",
    is_flag=True,
    help="Show only existing username results in console output and exports",
)
@click.option(
    "--filter-partial",
    is_flag=True,
    help="Show only partial match results in console output and exports",
)
@click.option(
    "--filter-conflicting",
    is_flag=True,
    help="Show only conflicting results in console output and exports",
)
@click.option(
    "--filter-unknown",
    is_flag=True,
    help="Show only unknown results in console output and exports",
)
@click.option(
    "--filter-missing",
    is_flag=True,
    help="Show only missing username results in console output and exports",
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
@cli_error_handler
def main(ctx: click.Context, **kwargs: dict[str, Any]) -> None:
    """A Python package and CLI tool for asynchronous OSINT username enumeration.

    Uses the WhatsMyName dataset.
    """

    if ctx.invoked_subcommand is not None:
        return

    if kwargs.get("no_color"):
        console.no_color = True

    config = NaminterConfig.from_click(**kwargs)
    NaminterCLI.setup_logging(config)
    naminter_cli = NaminterCLI(config)
    uvloop.run(naminter_cli.run())


@main.command(name="validate")
@click.option(
    "--local-schema",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to local WhatsMyName JSON schema file for validation",
)
@click.option(
    "--local-data",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to local WhatsMyName JSON data file",
)
@click.option("--no-color", is_flag=True, help="Disable colored console output")
@click.pass_context
@cli_error_handler
def validator_command(
    ctx: click.Context,
    local_schema: Path,
    local_data: Path,
    *,
    no_color: bool,
) -> None:
    """Validate WhatsMyName JSON data against a JSON schema."""
    if no_color:
        console.no_color = True

    async def run_validator() -> None:
        """Run validation asynchronously."""
        schema = await read_json(local_schema)
        data = await read_json(local_data)

        validator = WMNValidator(schema)
        schema_errors = validator.validate_schema(data)
        data_errors = WMNValidator.validate_data(data)

        if schema_errors:
            display_errors(schema_errors, "Schema Errors")
        if data_errors:
            display_errors(data_errors, "Data Errors")

        if schema_errors or data_errors:
            ctx.exit(EXIT_CODE_ERROR)

        console.print(
            "[green]+ [Validator] Validation passed: No errors found[/green]",
        )

    uvloop.run(run_validator())


@main.command(name="format")
@click.option(
    "--local-schema",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to local WhatsMyName JSON schema file",
)
@click.option(
    "--local-data",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to local WhatsMyName JSON data file",
)
@click.option(
    "--output-data",
    "-o",
    callback=validate_filepath_arg,
    help="Output path for formatted data (defaults to overwriting --local-data)",
)
@click.option(
    "--output-schema",
    callback=validate_filepath_arg,
    help="Output path for formatted schema (defaults to overwriting --local-schema)",
)
@click.option("--no-color", is_flag=True, help="Disable colored console output")
@click.pass_context
@cli_error_handler
def format_command(
    _ctx: click.Context,
    local_schema: Path,
    local_data: Path,
    output_data: Path | None,
    output_schema: Path | None,
    *,
    no_color: bool,
) -> None:
    """Format WhatsMyName JSON data according to schema ordering and sorting."""
    if no_color:
        console.no_color = True

    async def run_formatter() -> None:
        """Run formatting asynchronously."""
        original_schema = await read_file(local_schema)
        original_data = await read_file(local_data)

        try:
            schema = orjson.loads(original_schema)
        except orjson.JSONDecodeError as e:
            msg = f"Invalid JSON in file {local_schema} at position {e.pos}: {e.msg}"
            raise FileError(msg) from e

        try:
            data = orjson.loads(original_data)
        except orjson.JSONDecodeError as e:
            msg = f"Invalid JSON in file {local_data} at position {e.pos}: {e.msg}"
            raise FileError(msg) from e

        formatter = WMNFormatter(schema)
        formatted_data = formatter.format_data(data)
        formatted_schema = formatter.format_schema()

        data_path = output_data or local_data
        schema_path = output_schema or local_schema

        if original_data != formatted_data:
            await write_file(data_path, formatted_data)
            display_diff(original_data, formatted_data, data_path)

        if original_schema != formatted_schema:
            await write_file(schema_path, formatted_schema)
            display_diff(original_schema, formatted_schema, schema_path)

    uvloop.run(run_formatter())


def entry_point() -> None:
    """Entry point for the application."""
    main()


if __name__ == "__main__":
    entry_point()
