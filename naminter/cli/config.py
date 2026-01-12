from functools import cached_property
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from naminter.cli.console import display_warning
from naminter.cli.constants import OPTION_AUTO_VALUE
from naminter.cli.exceptions import ConfigurationError
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    HTTP_ALLOW_REDIRECTS,
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HTTP_SSL_VERIFY,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
    WMN_SCHEMA_URL,
)
from naminter.core.models import WMNMode

if TYPE_CHECKING:
    from curl_cffi import BrowserTypeLiteral, ExtraFingerprints


class NaminterConfig:
    """Configuration for Naminter CLI tool.

    Holds all configuration parameters for username enumeration operations,
    including network settings, export options, filtering, and validation
    parameters.
    """

    def __init__(self, /, **kwargs: object) -> None:
        """Initialize config from kwargs (CLI or direct parameters).

        Args:
            **kwargs: Configuration parameters. Can be either:
                - Direct field names (usernames, sites, etc.)
                - CLI-specific names (username, site, csv_opt, etc.)

        Note:
            At least one keyword argument must be provided. Positional arguments
            are not allowed (enforced by position-only `/` parameter).
        """
        if not kwargs:
            msg = "NaminterConfig requires at least one keyword argument"
            raise ConfigurationError(msg)

        # Parse CLI-specific kwargs if present
        parsed = self._parse_cli_kwargs(kwargs)

        # Set all fields with defaults
        self.usernames: list[str] = parsed.get("usernames", [])
        self.sites: list[str] | None = parsed.get("sites")
        self.local_list_path: Path | str | None = parsed.get("local_list")
        self.remote_list_url: str | None = parsed.get("remote_list")
        self.local_schema_path: Path | str | None = parsed.get("local_schema")
        self.remote_schema_url: str | None = parsed.get(
            "remote_schema",
            WMN_SCHEMA_URL,
        )
        self.skip_validation: bool = parsed.get("skip_validation", False)
        self.include_categories: list[str] = parsed.get("include_categories", [])
        self.exclude_categories: list[str] = parsed.get("exclude_categories", [])
        self.filter_all: bool = parsed.get("filter_all", False)
        self.filter_exists: bool = parsed.get("filter_exists", False)
        self.filter_partial: bool = parsed.get("filter_partial", False)
        self.filter_conflicting: bool = parsed.get("filter_conflicting", False)
        self.filter_unknown: bool = parsed.get("filter_unknown", False)
        self.filter_missing: bool = parsed.get("filter_missing", False)
        self.filter_not_valid: bool = parsed.get("filter_not_valid", False)
        self.filter_errors: bool = parsed.get("filter_errors", False)
        self.max_tasks: int = parsed.get("max_tasks", MAX_CONCURRENT_TASKS)
        self.timeout: int = parsed.get("timeout", HTTP_REQUEST_TIMEOUT_SECONDS)
        self.proxy: str | None = parsed.get("proxy")
        self.allow_redirects: bool = parsed.get("allow_redirects", HTTP_ALLOW_REDIRECTS)
        self.verify_ssl: bool = parsed.get("verify_ssl", HTTP_SSL_VERIFY)
        self.impersonate: BrowserTypeLiteral | str | None = parsed.get(
            "impersonate",
            BROWSER_IMPERSONATE_AGENT,
        )
        self.ja3: str | None = parsed.get("ja3")
        self.akamai: str | None = parsed.get("akamai")
        self.extra_fp: ExtraFingerprints | dict[str, Any] | str | None = parsed.get(
            "extra_fp",
        )
        self.browse: bool = parsed.get("browse", False)
        self.mode: WMNMode = parsed.get("mode", WMNMode.ALL)
        self.test: bool = parsed.get("test", False)
        self.no_progressbar: bool = parsed.get("no_progressbar", False)
        self.log_level: str | None = parsed.get("log_level")
        self.log_file: str | None = parsed.get("log_file")
        self.show_details: bool = parsed.get("show_details", False)
        self.save_response: bool = parsed.get("save_response", False)
        self.response_path: str | None = parsed.get("response_path")
        self.open_response: bool = parsed.get("open_response", False)
        self.csv_export: bool = parsed.get("csv_export", False)
        self.csv_path: str | None = parsed.get("csv_path")
        self.pdf_export: bool = parsed.get("pdf_export", False)
        self.pdf_path: str | None = parsed.get("pdf_path")
        self.html_export: bool = parsed.get("html_export", False)
        self.html_path: str | None = parsed.get("html_path")
        self.json_export: bool = parsed.get("json_export", False)
        self.json_path: str | None = parsed.get("json_path")

        self.__post_init__()

    @staticmethod
    def _parse_option_path(option_value: str | None) -> str | None:
        """Parse export/response option value, returning None for auto or unset.

        Args:
            option_value: The option value to parse. Can be None, OPTION_AUTO_VALUE,
                or a path string.

        Returns:
            None if the option is unset or set to auto mode, otherwise the path string.
        """
        if option_value in {None, OPTION_AUTO_VALUE}:
            return None
        return option_value

    @staticmethod
    def _parse_cli_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
        """Parse CLI-specific kwargs into config field names.

        Args:
            kwargs: Raw kwargs from CLI or direct parameters.

        Returns:
            Dictionary with parsed configuration values.
        """
        parsed = kwargs.copy()

        # Handle CLI-specific username/site parameters (tuples from click)
        if "username" in parsed:
            parsed["usernames"] = list(parsed.pop("username") or [])
        if "site" in parsed:
            sites = list(parsed.pop("site") or [])
            parsed["sites"] = sites if sites else None

        # Handle include/exclude categories
        if "include_categories" in parsed and isinstance(
            parsed["include_categories"],
            tuple,
        ):
            parsed["include_categories"] = list(parsed["include_categories"])
        if "exclude_categories" in parsed and isinstance(
            parsed["exclude_categories"],
            tuple,
        ):
            parsed["exclude_categories"] = list(parsed["exclude_categories"])

        # Parse export format options (csv_opt -> csv_export + csv_path)
        for fmt in ["csv", "pdf", "html", "json"]:
            opt_key = f"{fmt}_opt"
            if opt_key in parsed:
                opt_value = parsed.pop(opt_key)
                parsed[f"{fmt}_export"] = opt_value is not None
                parsed[f"{fmt}_path"] = NaminterConfig._parse_option_path(opt_value)

        # Parse response saving option
        if "save_response_opt" in parsed:
            opt_value = parsed.pop("save_response_opt")
            parsed["save_response"] = opt_value is not None
            parsed["response_path"] = NaminterConfig._parse_option_path(opt_value)

        # Convert mode string to WMNMode enum if needed
        if "mode" in parsed and isinstance(parsed["mode"], str):
            parsed["mode"] = WMNMode(parsed["mode"])

        # Convert boolean strings to actual booleans
        bool_fields = [
            "skip_validation",
            "allow_redirects",
            "verify_ssl",
            "browse",
            "test",
            "show_details",
            "open_response",
            "no_progressbar",
            "filter_all",
            "filter_exists",
            "filter_partial",
            "filter_conflicting",
            "filter_unknown",
            "filter_missing",
            "filter_not_valid",
            "filter_errors",
        ]
        for field_name in bool_fields:
            if field_name in parsed and not isinstance(parsed[field_name], bool):
                parsed[field_name] = bool(parsed[field_name])

        return parsed

    def __post_init__(self) -> None:
        """Validate and normalize configuration after initialization."""
        self._validate_usernames()
        self._validate_mode()
        self._validate_sources()
        self._normalize_filters()
        self._normalize_impersonate()
        self._normalize_fingerprint()

    def _validate_usernames(self) -> None:
        """Ensure usernames are provided when not running in test mode."""
        if not self.usernames and not self.test:
            msg = (
                "At least one --username/-u is required unless --test is used. "
                "Provide a username or run in validation mode with --test."
            )
            raise ConfigurationError(msg)

    def _validate_mode(self) -> None:
        """Validate and warn about site validation mode configuration."""
        if self.test and self.usernames:
            display_warning(
                "Site validation mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead.",
            )

    def _validate_sources(self) -> None:
        """Validate data source configuration (list and schema sources)."""
        # Validate list sources
        if self.local_list_path and self.remote_list_url:
            msg = (
                "Conflicting list sources: both local_list_path and remote_list_url "
                "are provided. Please specify only one."
            )
            raise ConfigurationError(msg)

        if not self.local_list_path and not self.remote_list_url:
            self.remote_list_url = WMN_REMOTE_URL

        # Validate schema sources
        if self.local_schema_path and self.remote_schema_url != WMN_SCHEMA_URL:
            msg = (
                "Conflicting schema sources: both local_schema_path and "
                "remote_schema_url are provided. Please specify only one."
            )
            raise ConfigurationError(msg)

        if not self.local_schema_path and not self.remote_schema_url:
            self.remote_schema_url = WMN_SCHEMA_URL

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
            self.filter_exists = True

    def _normalize_impersonate(self) -> None:
        """Normalize impersonate setting to handle 'none' string value."""
        if (
            isinstance(self.impersonate, str)
            and self.impersonate.lower() == BROWSER_IMPERSONATE_NONE
        ):
            self.impersonate = None

    def _normalize_fingerprint(self) -> None:
        """Parse and normalize extra_fp from JSON string to dict if needed."""
        if not isinstance(self.extra_fp, str):
            return

        extra_fp_str = self.extra_fp.strip()
        if not extra_fp_str:
            self.extra_fp = None
            return

        try:
            parsed = json.loads(extra_fp_str)
            if not isinstance(parsed, dict):
                msg = (
                    f"Invalid extra_fp format: expected JSON object, "
                    f"got {type(parsed).__name__}"
                )
                raise ConfigurationError(msg)
            self.extra_fp = parsed
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON in extra_fp parameter: {e}"
            raise ConfigurationError(msg) from e

    @cached_property
    def response_dir(self) -> Path | None:
        """Return response directory Path if save_response is enabled."""
        if not self.save_response:
            return None

        if self.response_path:
            return Path(self.response_path)

        return Path.cwd() / "responses"

    @cached_property
    def export_formats(self) -> dict[str, str | None]:
        """Return enabled export formats with their custom paths."""
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
