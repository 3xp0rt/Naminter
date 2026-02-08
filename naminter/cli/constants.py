from typing import Final

from naminter.core.models import WMNStatus

# Constants for file operations
RESPONSE_FILE_DATE_FORMAT: Final[str] = "%Y%m%d_%H%M%S"
RESPONSE_FILE_EXTENSION: Final[str] = ".html"

# Default fallback values
DEFAULT_UNNAMED_VALUE: Final[str] = "unnamed"

# Progress tracking
PROGRESS_ADVANCE_INCREMENT: Final[int] = 1

# Exit codes
EXIT_CODE_ERROR: Final[int] = 1
EXIT_CODE_INTERRUPTED: Final[int] = 130

# Filename constraints
MAX_FILENAME_LENGTH: Final[int] = 200

# Status Display Configuration (for CLI/UI)
# Symbol keys use WMNStatus enum members
STATUS_SYMBOLS: Final[dict[WMNStatus, str]] = {
    WMNStatus.EXISTS: "+",
    WMNStatus.PARTIAL_EXISTS: "~",
    WMNStatus.PARTIAL_MISSING: "~",
    WMNStatus.CONFLICTING: "*",
    WMNStatus.UNKNOWN: "?",
    WMNStatus.MISSING: "-",
    WMNStatus.NOT_VALID: "X",
    WMNStatus.ERROR: "!",
}

# Style keys use WMNStatus enum members
STATUS_STYLES: Final[dict[WMNStatus, str]] = {
    WMNStatus.EXISTS: "bright_green bold",
    WMNStatus.PARTIAL_EXISTS: "bright_yellow",
    WMNStatus.PARTIAL_MISSING: "bright_yellow",
    WMNStatus.CONFLICTING: "bright_yellow bold",
    WMNStatus.UNKNOWN: "bright_yellow",
    WMNStatus.MISSING: "bright_red",
    WMNStatus.NOT_VALID: "bright_red",
    WMNStatus.ERROR: "bright_red bold",
}

# Export field ordering
HTML_FIELDS_ORDER: Final[list[str]] = ["name", "url", "elapsed"]
