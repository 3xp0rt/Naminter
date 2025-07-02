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


class SchemaValidationError(DataError):
    """Raised when WMN schema validation fails.
    
    This occurs when the WhatsMyName list format doesn't match
    the expected schema structure.
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


class LoggingError(ConfigurationError):
    """Raised when logging configuration fails.
    
    This includes logger setup errors, handler configuration issues,
    and log file access problems.
    """
    pass


class ValidationError(DataError):
    """Raised when input validation fails.
    
    This includes invalid usernames, malformed URLs,
    and other input parameter validation errors.
    """
    pass


class WMNListError(DataError):
    """Raised when WhatsMyName list loading or processing fails.
    
    This includes download errors, parsing failures,
    and list update issues.
    """
    pass


class ConcurrencyError(NaminterError):
    """Raised when concurrency-related errors occur.
    
    This includes semaphore acquisition failures, task management errors,
    and thread/async coordination issues.
    """
    pass


__all__ = [
    "NaminterError",
    "ConfigurationError",
    "NetworkError",
    "DataError",
    "SessionError",
    "SchemaValidationError",
    "TimeoutError",
    "FileAccessError",
    "LoggingError",
    "ValidationError",
    "WMNListError",
    "ConcurrencyError",
]