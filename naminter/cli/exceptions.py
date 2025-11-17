from naminter.core.exceptions import NaminterError


# Configuration errors
class ConfigurationError(NaminterError):
    """Raised when there's an error in the configuration parameters.

    This includes invalid configuration values, missing required settings,
    configuration file parsing errors, or invalid URLs.
    """


# File/IO errors
class FileIOError(NaminterError):
    """Raised when file operations fail.

    This includes reading/writing local lists, responses, exports,
    and other file system operations.
    """


# Browser errors
class BrowserError(NaminterError):
    """Raised when browser operations fail in the CLI layer."""


# Export errors
class ExportError(NaminterError):
    """Raised when export operations fail in the CLI layer."""


__all__ = [
    "BrowserError",
    "ConfigurationError",
    "ExportError",
    "FileIOError",
    "NaminterError",
]
