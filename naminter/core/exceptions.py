from typing import Optional


class NaminterError(Exception):
    """Base exception class for Naminter errors.
    
    Args:
        message: Error message describing what went wrong.
        cause: Optional underlying exception that caused this error.
    """
    
    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause


class ConfigurationError(NaminterError):
    """Raised when there's an error in the configuration parameters.
    
    This includes invalid configuration values, missing required settings,
    or configuration file parsing errors.
    """
    pass


class NetworkError(NaminterError):
    """Raised when network-related errors occur.
    
    This includes connection failures, DNS resolution errors,
    and other network-level issues.
    """
    pass


class DataError(NaminterError):
    """Raised when there are issues with data processing or validation.
    
    This includes malformed data, parsing errors, and data integrity issues.
    """
    pass


class SessionError(NetworkError):
    """Raised when HTTP session creation or management fails.
    
    This includes session initialization errors, authentication failures,
    and session state management issues.
    """
    pass


class SchemaError(DataError):
    """Raised when WMN schema validation fails.
    
    This occurs when the WhatsMyName list format doesn't match
    the expected schema structure, or when the schema itself is invalid.
    """
    pass


class TimeoutError(NetworkError):
    """Raised when network requests timeout.
    
    This includes both connection timeouts and read timeouts
    during HTTP requests.
    """
    pass


class FileAccessError(DataError):
    """Raised when file operations fail.
    
    This includes reading/writing local lists, responses, exports,
    and other file system operations.
    """
    pass


class ValidationError(DataError):
    """Raised when input validation fails.
    
    This includes invalid usernames, malformed URLs,
    and other input parameter validation errors.
    """
    pass


class ExportError(NaminterError):
    """Raised when export operations fail.
    
    This includes file writing errors, format conversion errors,
    and other export-related issues.
    """
    pass


__all__ = [
    "NaminterError",
    "ConfigurationError",
    "NetworkError",
    "DataError",
    "SessionError",
    "SchemaError",
    "TimeoutError",
    "FileAccessError",
    "ValidationError",
    "ExportError",
]