from typing import Final

# Constants for file operations
RESPONSE_FILE_DATE_FORMAT: Final[str] = "%Y%m%d_%H%M%S"
RESPONSE_FILE_EXTENSION: Final[str] = ".html"

# Default fallback values
DEFAULT_UNNAMED_VALUE: Final[str] = "unnamed"

# Progress tracking
PROGRESS_ADVANCE_INCREMENT: Final[int] = 1

# Exit codes
EXIT_CODE_ERROR: Final[int] = 1
EXIT_CODE_SUCCESS: Final[int] = 0
EXIT_CODE_INTERRUPTED: Final[int] = 130

# Filename constraints
MAX_FILENAME_LENGTH: Final[int] = 200

# Status Display Configuration (for CLI/UI)
# Symbol keys match WMNStatus enum values
STATUS_SYMBOLS: Final[dict[str, str]] = {
    "exists": "+",
    "partial": "~",
    "conflicting": "*",
    "unknown": "?",
    "missing": "-",
    "not_valid": "X",
    "error": "!",
}

# Style keys match WMNStatus enum values
STATUS_STYLES: Final[dict[str, str]] = {
    "exists": "bright_green bold",
    "partial": "bright_yellow",
    "conflicting": "bright_yellow bold",
    "unknown": "bright_yellow",
    "missing": "bright_red",
    "not_valid": "bright_red",
    "error": "bright_red bold",
}

# Export field ordering
HTML_FIELDS_ORDER: Final[list[str]] = ["name", "url", "elapsed"]

# Option parsing
OPTION_AUTO_VALUE: Final[str] = "__AUTO__"
