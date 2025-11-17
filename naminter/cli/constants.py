# Constants for file operations
RESPONSE_FILE_DATE_FORMAT = "%Y%m%d_%H%M%S"
RESPONSE_FILE_EXTENSION = ".html"

# Default network timeout (overrides core default for CLI)
DEFAULT_NETWORK_TIMEOUT: int = 30

# Progress tracking
PROGRESS_ADVANCE_INCREMENT: int = 1

# Exit codes
EXIT_CODE_ERROR: int = 1
EXIT_CODE_SUCCESS: int = 0

# Filename constraints
MAX_FILENAME_LENGTH: int = 200

# Supported export formats
SUPPORTED_FORMATS: list[str] = ["csv", "json", "html", "pdf"]
