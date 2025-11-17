from typing import Any


# Base exception
class NaminterError(Exception):
    """Base exception class for Naminter errors.

    Args:
        message: Error message describing what went wrong.
        cause: Optional underlying exception that caused this error.
    """

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause


# Network/HTTP errors
class HttpError(NaminterError):
    """Raised when network-related errors occur.

    This includes connection failures, DNS resolution errors,
    and other network-level issues.
    """


class HttpSessionError(HttpError):
    """Raised when HTTP session creation or management fails.

    This includes session initialization errors, authentication failures,
    and session state management issues.
    """


class HttpTimeoutError(HttpError):
    """Raised when network requests timeout.

    This includes both connection timeouts and read timeouts
    during HTTP requests.
    """


# Data processing errors
class WMNDataError(NaminterError):
    """Raised when there are issues with WMN data processing or validation.

    This includes malformed data, parsing errors, and data integrity issues.
    """


class WMNSchemaError(WMNDataError):
    """Raised when the WMN JSON Schema itself is invalid or cannot be used."""


class WMNValidationError(WMNDataError):
    """Raised when WMN dataset does not conform to the provided JSON Schema.

    Attributes:
        errors: Structured list of validation errors to display/inspect.
    """

    def __init__(
        self,
        message: str,
        errors: list[Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, cause)
        self.errors: list[Any] = errors or []


__all__ = [
    "HttpError",
    "HttpSessionError",
    "HttpTimeoutError",
    "NaminterError",
    "WMNDataError",
    "WMNSchemaError",
    "WMNValidationError",
]
