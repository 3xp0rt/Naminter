import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints

from naminter.cli.console import display_warning
from naminter.cli.exceptions import ConfigurationError
from naminter.core.constants import (
    BROWSER_IMPERSONATE_AGENT,
    BROWSER_IMPERSONATE_NONE,
    HTTP_REQUEST_TIMEOUT_SECONDS,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
    WMN_SCHEMA_URL,
)
from naminter.core.models import WMNMode


@dataclass
class NaminterConfig:
    """Configuration for Naminter CLI tool.

    Holds all configuration parameters for username enumeration operations,
    including network settings, export options, filtering, and validation
    parameters.
    """

    # Required parameters
    usernames: list[str]
    sites: list[str] | None = None
    logger: object | None = None

    # List and schema sources
    local_list_path: Path | str | None = None
    remote_list_url: str | None = None
    local_schema_path: Path | str | None = None
    remote_schema_url: str | None = WMN_SCHEMA_URL

    # Validation and filtering
    skip_validation: bool = False
    include_categories: list[str] = field(default_factory=lambda: [])  # noqa: PIE807
    exclude_categories: list[str] = field(default_factory=lambda: [])  # noqa: PIE807
    filter_all: bool = False
    filter_found: bool = False
    filter_ambiguous: bool = False
    filter_unknown: bool = False
    filter_not_found: bool = False
    filter_not_valid: bool = False
    filter_errors: bool = False

    # Network and concurrency
    max_tasks: int = MAX_CONCURRENT_TASKS
    timeout: int = HTTP_REQUEST_TIMEOUT_SECONDS
    proxy: str | None = None
    allow_redirects: bool = False
    verify_ssl: bool = False
    impersonate: BrowserTypeLiteral | str | None = BROWSER_IMPERSONATE_AGENT
    ja3: str | None = None
    akamai: str | None = None
    extra_fp: ExtraFingerprints | dict[str, Any] | str | None = None
    browse: bool = False
    mode: WMNMode = WMNMode.ALL
    validate_sites: bool = False
    no_progressbar: bool = False

    # Logging
    log_level: str | None = None
    log_file: str | None = None
    show_details: bool = False

    # Response saving
    save_response: bool = False
    response_path: str | None = None
    open_response: bool = False

    # Export options
    csv_export: bool = False
    csv_path: str | None = None
    pdf_export: bool = False
    pdf_path: str | None = None
    html_export: bool = False
    html_path: str | None = None
    json_export: bool = False
    json_path: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize configuration after initialization."""
        if self.validate_sites and self.usernames:
            display_warning(
                "Site validation mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead."
            )

        if self.local_list_path and self.remote_list_url:
            msg = "Both local and remote list sources provided; only one is allowed"
            raise ConfigurationError(msg)

        if not self.local_list_path and not self.remote_list_url:
            self.remote_list_url = WMN_REMOTE_URL

        if self.local_schema_path and self.remote_schema_url:
            msg = "Both local and remote schema sources provided; only one is allowed"
            raise ConfigurationError(msg)

        if not self.local_schema_path and not self.remote_schema_url:
            self.remote_schema_url = WMN_SCHEMA_URL

        filter_fields = [
            self.filter_all,
            self.filter_ambiguous,
            self.filter_unknown,
            self.filter_not_found,
            self.filter_not_valid,
            self.filter_errors,
        ]
        if not any(filter_fields):
            self.filter_found = True

        if (
            isinstance(self.impersonate, str)
            and self.impersonate.lower() == BROWSER_IMPERSONATE_NONE
        ):
            self.impersonate = None

        if isinstance(self.extra_fp, str):
            try:
                self.extra_fp = json.loads(self.extra_fp)
            except json.JSONDecodeError as e:
                msg = f"Invalid JSON in extra_fp: {e}"
                raise ConfigurationError(msg) from e
            except TypeError as e:
                msg = f"Invalid data type in extra_fp: {e}"
                raise ConfigurationError(msg) from e

    @property
    def response_dir(self) -> Path | None:
        """Return response directory Path if save_response is enabled."""
        if not self.save_response:
            return None

        if self.response_path:
            return Path(self.response_path)

        return Path.cwd() / "responses"

    @property
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
