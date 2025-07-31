from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union, Dict, Any

from ..cli.console import display_error, display_warning
from ..core.constants import (
    HTTP_REQUEST_TIMEOUT_SECONDS,
    MAX_CONCURRENT_TASKS,
    WMN_REMOTE_URL,
    WMN_SCHEMA_URL,
)
from ..core.models import BrowserImpersonation

@dataclass
class NaminterConfig:
    """Configuration for Naminter CLI tool.
    
    Holds all configuration parameters for username checking operations, including network settings, export options, filtering, and validation parameters.
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
    filter_errors: bool = False
    filter_not_found: bool = False
    filter_unknown: bool = False
    filter_ambiguous: bool = False

    # Network and concurrency
    max_tasks: int = MAX_CONCURRENT_TASKS
    timeout: int = HTTP_REQUEST_TIMEOUT_SECONDS
    proxy: Optional[str] = None
    allow_redirects: bool = False
    verify_ssl: bool = False
    impersonate: BrowserImpersonation = BrowserImpersonation.CHROME
    browse: bool = False
    fuzzy_mode: bool = False
    self_check: bool = False
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
        if self.self_check and self.usernames:
            display_warning(
                "Self-check mode enabled: provided usernames will be ignored, "
                "using known usernames from site configurations instead."
            )
        if not self.self_check and not self.usernames:
            raise ValueError("No usernames provided and self-check not enabled.")
        try:
            if self.local_list_paths:
                self.local_list_paths = [str(p) for p in self.local_list_paths]
            if self.remote_list_urls:
                self.remote_list_urls = list(self.remote_list_urls)
            if not self.local_list_paths and not self.remote_list_urls:
                self.remote_list_urls = [WMN_REMOTE_URL]
        except Exception as e:
            raise ValueError(f"Configuration validation failed: {e}") from e
        self.impersonate = self.get_impersonation()

    def get_impersonation(self) -> Optional[str]:
        """Return impersonation string or None if impersonation is NONE."""
        return None if self.impersonate == BrowserImpersonation.NONE else self.impersonate.value

    @property
    def response_dir(self) -> Optional[Path]:
        """Return response directory Path if save_response is enabled."""
        if not self.save_response:
            return None
        if self.response_path:
            return Path(self.response_path)
        return Path.cwd()

    @property
    def export_formats(self) -> Dict[str, Optional[str]]:
        """Return enabled export formats with their custom paths."""
        formats: Dict[str, Optional[str]] = {}
        if self.csv_export:
            formats["csv"] = self.csv_path
        if self.pdf_export:
            formats["pdf"] = self.pdf_path
        if self.html_export:
            formats["html"] = self.html_path
        if self.json_export:
            formats["json"] = self.json_path
        return formats

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
            "impersonate": self.impersonate.value if isinstance(self.impersonate, BrowserImpersonation) else self.impersonate,
            "browse": self.browse,
            "fuzzy_mode": self.fuzzy_mode,
            "self_check": self.self_check,
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
            "filter_errors": self.filter_errors,
            "filter_not_found": self.filter_not_found,
            "filter_unknown": self.filter_unknown,
            "filter_ambiguous": self.filter_ambiguous,
            "no_progressbar": self.no_progressbar,
        }
