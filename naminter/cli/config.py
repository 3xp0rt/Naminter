import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints

from naminter.cli.console import display_warning
from naminter.core.constants import (
    HTTP_REQUEST_TIMEOUT_SECONDS,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
    WMN_SCHEMA_URL,
)
from naminter.core.exceptions import ConfigurationError


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
    local_list_paths: list[Path | str] | None = None
    remote_list_urls: list[str] | None = None
    local_schema_path: Path | str | None = None
    remote_schema_url: str | None = WMN_SCHEMA_URL

    # Validation and filtering
    skip_validation: bool = False
    include_categories: list[str] = field(default_factory=list)
    exclude_categories: list[str] = field(default_factory=list)
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
    impersonate: BrowserTypeLiteral | None = "chrome"
    ja3: str | None = None
    akamai: str | None = None
    extra_fp: ExtraFingerprints | dict[str, Any] | str | None = None
    browse: bool = False
    fuzzy_mode: bool = False
    self_enumeration: bool = False
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
        if self.self_enumeration and self.usernames:
            display_warning(
                "Self-enumeration mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead."
            )

        try:
            if self.local_list_paths:
                self.local_list_paths = [str(p) for p in self.local_list_paths]
            if self.remote_list_urls:
                self.remote_list_urls = list(self.remote_list_urls)
            if not self.local_list_paths and not self.remote_list_urls:
                self.remote_list_urls = [WMN_REMOTE_URL]
        except Exception as e:
            msg = f"Configuration validation failed: {e}"
            raise ConfigurationError(msg) from e

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

        if isinstance(self.impersonate, str) and self.impersonate.lower() == "none":
            self.impersonate = None

        if self.extra_fp is not None and isinstance(self.extra_fp, str):
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

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            "usernames": self.usernames,
            "sites": self.sites,
            "local_list_paths": self.local_list_paths,
            "remote_list_urls": self.remote_list_urls,
            "local_schema_path": self.local_schema_path,
            "remote_schema_url": self.remote_schema_url,
            "skip_validation": self.skip_validation,
            "include_categories": self.include_categories,
            "exclude_categories": self.exclude_categories,
            "max_tasks": self.max_tasks,
            "timeout": self.timeout,
            "proxy": self.proxy,
            "allow_redirects": self.allow_redirects,
            "verify_ssl": self.verify_ssl,
            "impersonate": self.impersonate,
            "ja3": self.ja3,
            "akamai": self.akamai,
            "extra_fp": self.extra_fp.to_dict()
            if isinstance(self.extra_fp, ExtraFingerprints)
            else self.extra_fp,
            "browse": self.browse,
            "fuzzy_mode": self.fuzzy_mode,
            "self_enumeration": self.self_enumeration,
            "log_level": self.log_level,
            "log_file": self.log_file,
            "show_details": self.show_details,
            "save_response": self.save_response,
            "response_path": self.response_path,
            "open_response": self.open_response,
            "csv_export": self.csv_export,
            "csv_path": self.csv_path,
            "pdf_export": self.pdf_export,
            "pdf_path": self.pdf_path,
            "html_export": self.html_export,
            "html_path": self.html_path,
            "json_export": self.json_export,
            "json_path": self.json_path,
            "filter_all": self.filter_all,
            "filter_found": self.filter_found,
            "filter_ambiguous": self.filter_ambiguous,
            "filter_unknown": self.filter_unknown,
            "filter_not_found": self.filter_not_found,
            "filter_not_valid": self.filter_not_valid,
            "filter_errors": self.filter_errors,
            "no_progressbar": self.no_progressbar,
        }
