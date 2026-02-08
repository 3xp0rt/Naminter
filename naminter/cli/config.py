from dataclasses import dataclass, field
from functools import cached_property
import orjson
from pathlib import Path
from typing import TYPE_CHECKING, Any

from naminter.cli.console import display_warning
from naminter.cli.exceptions import ConfigurationError
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    HTTP_ALLOW_REDIRECTS,
    HTTP_TIMEOUT,
    HTTP_SSL_VERIFY,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
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
    usernames: list[str] = field(default_factory=lambda: list[str]())
    sites: list[str] | None = None
    local_list_path: Path | str | None = None
    remote_list_url: str | None = None
    local_schema_path: Path | str | None = None
    remote_schema_url: str = WMN_SCHEMA_URL

    # Validation & Filtering
    skip_validation: bool = False
    include_categories: list[str] = field(default_factory=lambda: list[str]())
    exclude_categories: list[str] = field(default_factory=lambda: list[str]())
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
        """Validate and normalize configuration after initialization."""
        self._validate_usernames()
        self._validate_mode()
        self._validate_sources()
        self._normalize_filters()
        self._normalize_impersonate()
        self._normalize_fingerprint()

    @classmethod
    def from_click(cls, **kwargs: Any) -> "NaminterConfig":
        """Create NaminterConfig from Click CLI arguments.

        This method handles the transformation of Click-specific kwargs
        (with CLI naming conventions) into the internal config field names.

        Args:
            **kwargs: Raw kwargs from Click CLI.

        Returns:
            Initialized NaminterConfig instance.

        Raises:
            ConfigurationError: If no kwargs are provided or validation fails.
        """
        if not kwargs:
            msg = "NaminterConfig requires at least one keyword argument"
            raise ConfigurationError(msg)

        parsed = kwargs.copy()

        cli_only_keys = ["no_color"]
        for key in cli_only_keys:
            parsed.pop(key, None)

        # Input/Output: Handle username/site and data source parameters
        if "username" in parsed:
            usernames: list[str] = list(parsed.pop("username") or [])
            parsed["usernames"] = usernames
        if "site" in parsed:
            sites: list[str] = list(parsed.pop("site") or [])
            parsed["sites"] = sites if sites else None

        if "local_list" in parsed:
            parsed["local_list_path"] = parsed.pop("local_list")
        if "remote_list" in parsed:
            parsed["remote_list_url"] = parsed.pop("remote_list")
        if "local_schema" in parsed:
            parsed["local_schema_path"] = parsed.pop("local_schema")
        if "remote_schema" in parsed:
            parsed["remote_schema_url"] = parsed.pop("remote_schema")

        # Validation & Filtering: Handle categories (convert tuples to lists)
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

        # Behavior/Output: Convert mode string to WMNMode enum if needed
        if "mode" in parsed and isinstance(parsed["mode"], str):
            parsed["mode"] = WMNMode(parsed["mode"])

        # Export Formats: Parse export format options (separate boolean flags and paths)
        for fmt in ["csv", "pdf", "html", "json"]:
            flag_key = fmt
            path_key = f"{fmt}_path"
            if flag_key in parsed:
                parsed[f"{fmt}_export"] = parsed.pop(flag_key)
            if path_key in parsed:
                parsed[f"{fmt}_path"] = parsed.pop(path_key)

        # Convert boolean strings to actual booleans
        bool_fields = [
            "skip_validation",
            "allow_redirects",
            "verify_ssl",
            "browse",
            "test",
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

        return cls(**parsed)

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
            object.__setattr__(self, "remote_list_url", WMN_REMOTE_URL)

        # Skip schema source validation if validation is disabled
        if self.skip_validation:
            return

        # Validate schema sources
        if self.local_schema_path and self.remote_schema_url != WMN_SCHEMA_URL:
            msg = (
                "Conflicting schema sources: both local_schema_path and "
                "remote_schema_url are provided. Please specify only one."
            )
            raise ConfigurationError(msg)

        if not self.local_schema_path and not self.remote_schema_url:
            object.__setattr__(self, "remote_schema_url", WMN_SCHEMA_URL)

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
            object.__setattr__(self, "filter_exists", True)

    def _normalize_impersonate(self) -> None:
        """Normalize impersonate setting to handle 'none' string value."""
        if (
            isinstance(self.impersonate, str)
            and self.impersonate.lower() == BROWSER_IMPERSONATE_NONE
        ):
            object.__setattr__(self, "impersonate", None)

    def _normalize_fingerprint(self) -> None:
        """Parse and normalize extra_fp from JSON string to dict if needed."""
        if not isinstance(self.extra_fp, str):
            return

        extra_fp_str = self.extra_fp.strip()
        if not extra_fp_str:
            object.__setattr__(self, "extra_fp", None)
            return

        try:
            parsed = orjson.loads(extra_fp_str)
            if not isinstance(parsed, dict):
                msg = (
                    f"Invalid extra_fp format: expected JSON object, "
                    f"got {type(parsed).__name__}"
                )
                raise ConfigurationError(msg)
            object.__setattr__(self, "extra_fp", parsed)
        except orjson.JSONDecodeError as e:
            msg = f"Invalid JSON in extra_fp parameter: {e}"
            raise ConfigurationError(msg) from e

    @cached_property
    def response_dir_path(self) -> Path | None:
        """Return response directory Path if save_response is enabled."""
        if not self.save_response:
            return None

        if self.response_dir:
            return Path(self.response_dir)

        return Path.cwd()

    @cached_property
    def export_formats(self) -> dict[str, Path | str | None]:
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
