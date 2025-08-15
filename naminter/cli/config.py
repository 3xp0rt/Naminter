from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
import json

from ..cli.console import display_warning
from ..core.constants import (
    HTTP_REQUEST_TIMEOUT_SECONDS,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
    WMN_SCHEMA_URL,
)
from ..core.exceptions import ConfigurationError
from curl_cffi import BrowserTypeLiteral, ExtraFingerprints


@dataclass
class NaminterConfig:
    """Configuration for Naminter CLI tool.
    
    Holds all configuration parameters for username enumeration operations, including network settings, export options, filtering, and validation parameters.
    """
    # Required parameters
    usernames: List[str]
    site_names: Optional[List[str]] = None
    logger: Optional[object] = None

    # List and schema sources
    local_list_paths: Optional[List[Union[Path, str]]] = None
    remote_list_urls: Optional[List[str]] = None
    local_schema_path: Optional[Union[Path, str]] = None
    remote_schema_url: Optional[str] = WMN_SCHEMA_URL

    # Validation and filtering
    skip_validation: bool = False
    include_categories: List[str] = field(default_factory=list)
    exclude_categories: List[str] = field(default_factory=list)
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
    proxy: Optional[str] = None
    allow_redirects: bool = False
    verify_ssl: bool = False
    impersonate: Optional[BrowserTypeLiteral] = "chrome"
    ja3: Optional[str] = None
    akamai: Optional[str] = None
    extra_fp: Optional[Union[ExtraFingerprints, Dict[str, Any], str]] = None
    browse: bool = False
    fuzzy_mode: bool = False
    self_enum: bool = False
    no_progressbar: bool = False

    # Logging
    log_level: Optional[str] = None
    log_file: Optional[str] = None
    show_details: bool = False

    # Response saving
    save_response: bool = False
    response_path: Optional[str] = None
    open_response: bool = False

    # Export options
    csv_export: bool = False
    csv_path: Optional[str] = None
    pdf_export: bool = False
    pdf_path: Optional[str] = None
    html_export: bool = False
    html_path: Optional[str] = None
    json_export: bool = False
    json_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate and normalize configuration after initialization."""
        if self.self_enum and self.usernames:
            display_warning(
                "Self-enum mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead."
            )

        if not self.self_enum and not self.usernames:
            raise ValueError("At least one username is required")

        try:
            if self.local_list_paths:
                self.local_list_paths = [str(p) for p in self.local_list_paths]
            if self.remote_list_urls:
                self.remote_list_urls = list(self.remote_list_urls)
            if not self.local_list_paths and not self.remote_list_urls:
                self.remote_list_urls = [WMN_REMOTE_URL]
        except Exception as e:
            raise ValueError(f"Configuration validation failed: {e}") from e

        filter_fields = [
            self.filter_all,
            self.filter_ambiguous,
            self.filter_unknown,
            self.filter_not_found,
            self.filter_not_valid,
            self.filter_errors
        ]
        if not any(filter_fields):
            self.filter_found = True
            
        if isinstance(self.impersonate, str) and self.impersonate.lower() == "none":
            self.impersonate = None

        if self.extra_fp is not None and isinstance(self.extra_fp, str):
            try:
                self.extra_fp = json.loads(self.extra_fp)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON in extra_fp: {e}") from e
            except TypeError as e:
                raise ConfigurationError(f"Invalid data type in extra_fp: {e}") from e


    @property
    def response_dir(self) -> Optional[Path]:
        """Return response directory Path if save_response is enabled."""
        if not self.save_response:
            return None

        if self.response_path:
            return Path(self.response_path)
            
        return Path.cwd() / "responses"

    @property
    def export_formats(self) -> Dict[str, Optional[str]]:
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            "usernames": self.usernames,
            "site_names": self.site_names,
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
            "extra_fp": self.extra_fp.to_dict() if isinstance(self.extra_fp, ExtraFingerprints) else self.extra_fp,
            "browse": self.browse,
            "fuzzy_mode": self.fuzzy_mode,
            "self_enum": self.self_enum,
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
