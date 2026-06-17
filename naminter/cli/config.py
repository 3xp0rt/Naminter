"""CLI configuration dataclass for Naminter runtime settings."""

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from naminter.cli.console import display_warning
from naminter.cli.exceptions import ConfigurationError
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    HTTP_ALLOW_REDIRECTS,
    HTTP_SSL_VERIFY,
    HTTP_TIMEOUT,
    MAX_CONCURRENT_TASKS,
    WMN_DATA_URL,
    WMN_SCHEMA_URL,
)
from naminter.core.models import WMNMode

if TYPE_CHECKING:
    from curl_cffi import BrowserTypeLiteral, ExtraFingerprints


@dataclass(frozen=True)
class NaminterConfig:
    """Configuration for Naminter CLI tool.

    Holds all configuration parameters for username enumeration operations,
    including network settings, export options, filtering, and validation
    parameters.
    """

    # Input/Output
    usernames: list[str] = field(default_factory=list)
    sites: list[str] | None = None
    local_data: Path | str | None = None
    remote_data: str | None = None
    local_schema: Path | str | None = None
    remote_schema: str = WMN_SCHEMA_URL

    # Validation & Filtering
    skip_validation: bool = False
    include_categories: list[str] = field(default_factory=list)
    exclude_categories: list[str] = field(default_factory=list)
    filter_all: bool = False
    filter_exists: bool = False
    filter_partial: bool = False
    filter_conflicting: bool = False
    filter_unknown: bool = False
    filter_missing: bool = False
    filter_not_valid: bool = False
    filter_errors: bool = False

    # Network/HTTP
    max_tasks: int = MAX_CONCURRENT_TASKS
    timeout: int = HTTP_TIMEOUT
    proxy: str | None = None
    allow_redirects: bool = HTTP_ALLOW_REDIRECTS
    verify_ssl: bool = HTTP_SSL_VERIFY
    impersonate: "BrowserTypeLiteral | str | None" = BROWSER_IMPERSONATE_AGENT
    ja3: str | None = None
    akamai: str | None = None
    extra_fp: "ExtraFingerprints | dict[str, Any] | str | None" = None

    # Behavior/Output
    browse: bool = False
    mode: WMNMode = field(default_factory=lambda: WMNMode.ALL)
    test: bool = False
    no_progressbar: bool = False
    log_level: str | None = None
    log_file: str | None = None
    verbose: int = 0

    # Response saving
    save_response: bool = False
    response_dir: Path | str | None = None
    open_response: bool = False

    # Export formats
    csv_export: bool = False
    csv_path: Path | str | None = None
    pdf_export: bool = False
    pdf_path: Path | str | None = None
    html_export: bool = False
    html_path: Path | str | None = None
    json_export: bool = False
    json_path: Path | str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize configuration after initialization.

        Raises:
            ConfigurationError: If configuration values are invalid or conflicting.
        """
        self._validate_usernames()
        self._validate_mode()
        self._validate_sources()
        self._normalize_filters()
        self._normalize_impersonate()
        self._normalize_fingerprint()

    @classmethod
    def from_click(cls, **kwargs: Any) -> "NaminterConfig":  # noqa: ANN401
        """Create NaminterConfig from Click CLI arguments.

        Transforms Click kwargs (CLI option names) into config field names
        and normalizes types (tuples to lists, mode string to enum).

        Args:
            **kwargs: Raw kwargs from Click CLI (main command options).

        Returns:
            NaminterConfig: Initialized NaminterConfig instance.

        Raises:
            ConfigurationError: If validation fails.
        """
        parsed = kwargs.copy()
        parsed.pop("no_color", None)

        cls._rename_click_keys(parsed)
        cls._normalize_click_types(parsed)

        return cls(**parsed)

    @classmethod
    def _rename_click_keys(cls, parsed: dict[str, Any]) -> None:
        """Rename Click CLI keys that differ from config field names.

        Args:
            parsed: Mutable dictionary of parsed kwargs to transform.
        """
        if "username" in parsed:
            parsed["usernames"] = list(parsed.pop("username") or [])
        if "site" in parsed:
            parsed["sites"] = list(parsed.pop("site")) or None

        for fmt in ("csv", "pdf", "html", "json"):
            if fmt in parsed:
                parsed[f"{fmt}_export"] = parsed.pop(fmt)

    @classmethod
    def _normalize_click_types(cls, parsed: dict[str, Any]) -> None:
        """Normalize Click argument types to config field types.

        Args:
            parsed: Mutable dictionary of parsed kwargs to normalize.
        """
        for list_key in ("include_categories", "exclude_categories"):
            if list_key in parsed and isinstance(parsed[list_key], tuple):
                parsed[list_key] = list(parsed[list_key])

        if "mode" in parsed:
            parsed["mode"] = WMNMode(parsed["mode"])

    def _validate_usernames(self) -> None:
        """Ensure usernames are provided when not running in test mode.

        Raises:
            ConfigurationError: If no usernames are provided and test mode is off.
        """
        if not self.usernames and not self.test:
            msg = (
                "At least one --username/-u is required unless --test is used. "
                "Provide a username or run in validation mode with --test."
            )
            raise ConfigurationError(msg)

    def _validate_mode(self) -> None:
        """Warn when test mode is enabled with usernames provided."""
        if self.test and self.usernames:
            display_warning(
                "Site validation mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead.",
            )

    def _validate_sources(self) -> None:
        """Validate data source configuration (data and schema sources).

        Raises:
            ConfigurationError: If conflicting data sources are provided.
        """
        if self.local_data and self.remote_data:
            msg = (
                "Conflicting data sources: both local_data and remote_data "
                "are provided. Please specify only one."
            )
            raise ConfigurationError(msg)

        if not self.local_data and not self.remote_data:
            object.__setattr__(self, "remote_data", WMN_DATA_URL)  # noqa: PLC2801

        if self.skip_validation:
            return

        if self.local_schema and self.remote_schema != WMN_SCHEMA_URL:
            msg = (
                "Conflicting schema sources: both local_schema and "
                "remote_schema are provided. Please specify only one."
            )
            raise ConfigurationError(msg)

    def _normalize_filters(self) -> None:
        """Normalize filter settings to ensure at least one filter is active."""
        has_any_filter = any([
            self.filter_all,
            self.filter_exists,
            self.filter_partial,
            self.filter_conflicting,
            self.filter_unknown,
            self.filter_missing,
            self.filter_not_valid,
            self.filter_errors,
        ])

        if not has_any_filter:
            object.__setattr__(self, "filter_exists", True)  # noqa: PLC2801

    def _normalize_impersonate(self) -> None:
        """Normalize impersonate setting to handle 'none' string value."""
        if (
            isinstance(self.impersonate, str)
            and self.impersonate.lower() == BROWSER_IMPERSONATE_NONE
        ):
            object.__setattr__(self, "impersonate", None)  # noqa: PLC2801

    def _normalize_fingerprint(self) -> None:
        """Parse and normalize extra_fp from JSON string to dict if needed.

        Raises:
            ConfigurationError: If extra_fp is not valid JSON or not a dict.
        """
        if not isinstance(self.extra_fp, str):
            return

        extra_fp_str = self.extra_fp.strip()
        if not extra_fp_str:
            object.__setattr__(self, "extra_fp", None)  # noqa: PLC2801
            return

        try:
            parsed = orjson.loads(extra_fp_str)
            if not isinstance(parsed, dict):
                msg = (
                    f"Invalid extra_fp format: expected JSON object, "
                    f"got {type(parsed).__name__}"
                )
                raise ConfigurationError(msg)
            object.__setattr__(self, "extra_fp", parsed)  # noqa: PLC2801
        except orjson.JSONDecodeError as e:
            msg = f"Invalid JSON in extra_fp parameter: {e}"
            raise ConfigurationError(msg) from e

    @cached_property
    def response_dir_path(self) -> Path | None:
        """Return response directory Path if save_response is enabled.

        Returns:
            Path | None: Configured directory path, or None if saving is disabled.
        """
        if not self.save_response:
            return None

        if self.response_dir:
            return Path(self.response_dir)

        return Path.cwd()

    @cached_property
    def export_formats(self) -> dict[str, Path | str | None]:
        """Return enabled export formats with their custom paths.

        Returns:
            dict[str, Path | str | None]: Mapping of format names to output paths.
        """
        export_configs = [
            ("csv", self.csv_export, self.csv_path),
            ("pdf", self.pdf_export, self.pdf_path),
            ("html", self.html_export, self.html_path),
            ("json", self.json_export, self.json_path),
        ]

        return {
            format_name: path
            for format_name, is_enabled, path in export_configs
            if is_enabled
        }
