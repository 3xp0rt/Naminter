"""Exception hierarchy for Naminter CLI-layer errors."""


class CLIError(Exception):
    """Base class for all CLI-layer errors."""


class FileError(CLIError):
    """File-related errors (paths, permissions, encoding, JSON content, etc.)."""


class NetworkError(CLIError):
    """Network-related errors (URLs, HTTP failures, invalid remote JSON, etc.)."""


class BrowserError(CLIError):
    """Browser-related errors (invalid URL, browser launch problems, etc.)."""


class ExportError(CLIError):
    """Errors raised during export operations in the CLI layer."""


class ConfigurationError(CLIError):
    """Configuration validation errors.

    Invalid CLI arguments, conflicting options, etc.
    """


class ValidationError(CLIError):
    """Input format validation errors.

    Invalid username format, site name format, etc.
    """


__all__ = [
    "BrowserError",
    "CLIError",
    "ConfigurationError",
    "ExportError",
    "FileError",
    "NetworkError",
    "ValidationError",
]
