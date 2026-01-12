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


class HttpStatusError(HttpError):
    """Raised when an HTTP request returns an error status code.

    Attributes:
        status_code: The HTTP status code that caused the error.
        url: The URL that returned the error status.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        url: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, cause)
        self.status_code: int | None = status_code
        self.url: str | None = url


# Data processing errors
class WMNDataError(NaminterError):
    """Raised when there are issues with WMN data processing or validation.

    This includes malformed data, parsing errors, and data integrity issues.
    """


class WMNUninitializedError(WMNDataError):
    """Raised when WMN data is not initialized or missing.

    This occurs when operations require WMN data but it hasn't been provided
    or loaded yet.
    """


class WMNUnknownSiteError(WMNDataError):
    """Raised when a requested site name doesn't exist in the WMN dataset.

    Attributes:
        site_names: List of unknown site names that were requested.
    """

    def __init__(
        self,
        message: str,
        site_names: list[str] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, cause)
        self.site_names: list[str] = site_names or []


class WMNUnknownCategoriesError(WMNDataError):
    """Raised when requested categories don't exist in the WMN dataset.

    Attributes:
        categories: List of unknown category names that were requested.
    """

    def __init__(
        self,
        message: str,
        categories: list[str] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, cause)
        self.categories: list[str] = categories or []


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


class WMNArgumentError(WMNDataError):
    """Raised when invalid arguments are passed to Naminter core APIs.

    This is used for programmer / caller mistakes such as providing an empty
    username list where at least one username is required.
    """


class WMNEnumerationError(WMNDataError):
    """Raised when site enumeration fails due to configuration errors.

    This includes invalid headers, strip_bad_char configuration errors,
    and other site-specific configuration issues.
    """


class WMNFormatError(WMNDataError):
    """Raised when WMN data formatting fails.

    This includes JSON serialization errors, invalid data structure,
    and other formatting-related issues.
    """


__all__ = [
    "HttpError",
    "HttpSessionError",
    "HttpStatusError",
    "HttpTimeoutError",
    "NaminterError",
    "WMNArgumentError",
    "WMNDataError",
    "WMNEnumerationError",
    "WMNFormatError",
    "WMNSchemaError",
    "WMNUninitializedError",
    "WMNUnknownCategoriesError",
    "WMNUnknownSiteError",
    "WMNValidationError",
]
