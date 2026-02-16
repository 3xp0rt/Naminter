"""Data models for WMN dataset structures, enumeration results, and responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum, auto
from typing import Any, NotRequired, TypedDict

import orjson

from naminter.core.constants import (
    DEFAULT_UNKNOWN_VALUE,
    SITE_KEY_CATEGORY,
    SITE_KEY_NAME,
)


class WMNMode(StrEnum):
    """Enumeration mode for username enumeration.

    ALL uses AND logic, ANY uses OR logic.
    """

    ALL = auto()
    ANY = auto()


class WMNStatus(StrEnum):
    """Status of username search results."""

    EXISTS = auto()
    MISSING = auto()
    PARTIAL_EXISTS = auto()
    PARTIAL_MISSING = auto()
    CONFLICTING = auto()
    UNKNOWN = auto()
    NOT_VALID = auto()
    ERROR = auto()


class WMNSite(TypedDict):
    """Type definition for a single site in the WMN dataset structure.

    Required: name, uri_check, e_code, e_string, m_string, m_code, known, cat.

    Optional with conditions:
        post_body: Must contain ``{account}``. When present, ``headers``
            is required and ``{account}`` is not required in ``uri_check``.
        headers: Required when ``post_body`` is present. Must be dict[str, str].
        uri_check: Must contain ``{account}`` when ``post_body`` is absent.
        strip_bad_char: Characters to strip from username before substitution.
        uri_pretty: Display URL template (not validated).
        valid: Site validity flag (not validated).
        protection: Protection mechanisms (not validated).
    """

    name: str
    uri_check: str
    uri_pretty: NotRequired[str]
    post_body: NotRequired[str]
    headers: NotRequired[dict[str, str]]
    strip_bad_char: NotRequired[str]
    e_code: int
    e_string: str
    m_string: str
    m_code: int
    known: list[str]
    cat: str
    valid: NotRequired[bool]
    protection: NotRequired[list[str]]


WMN_REQUIRED_KEYS: frozenset[str] = frozenset({
    "name",
    "uri_check",
    "e_code",
    "e_string",
    "m_string",
    "m_code",
    "known",
    "cat",
})


class WMNDataset(TypedDict):
    """Type definition for WMN dataset structure.

    All fields are required per JSON schema.
    """

    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[WMNSite]


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNSummary:
    """Summary of the loaded WhatsMyName dataset and filters applied.

    Attributes:
        license: License information from the dataset.
        authors: Authors of the dataset.
        site_names: Names of all sites included.
        sites_count: Total number of sites.
        categories: Categories of the included sites.
        categories_count: Number of unique categories.
        known_count: Total number of known usernames across all sites.
    """

    license: tuple[str, ...]
    authors: tuple[str, ...]
    site_names: tuple[str, ...]
    sites_count: int
    categories: tuple[str, ...]
    categories_count: int
    known_count: int

    def to_dict(self) -> dict[str, Any]:
        """Convert the summary to a plain dictionary.

        Returns:
            dict[str, Any]: Dictionary representation with lists instead of tuples.
        """
        return {
            "license": list(self.license),
            "authors": list(self.authors),
            "site_names": list(self.site_names),
            "sites_count": self.sites_count,
            "categories": list(self.categories),
            "categories_count": self.categories_count,
            "known_count": self.known_count,
        }


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNResult:
    """Result of testing a username on a site.

    Attributes:
        name: Site name from the WMN dataset.
        category: Site category from the WMN dataset.
        username: Username that was tested.
        status: Detection status of the username on the site.
        uri_check: URL used for the check (request URL).
        uri_pretty: Optional "pretty" URL for display/reporting.
        status_code: HTTP status code of the response.
        headers: HTTP response headers.
        text: Response body text.
        elapsed: Time elapsed for the HTTP request.
        error: Error message if the check failed.
        created_at: Timestamp when the result was created.
    """

    name: str
    category: str
    username: str
    status: WMNStatus
    uri_check: str | None = None
    uri_pretty: str | None = None
    status_code: int | None = None
    headers: dict[str, str] | None = None
    text: str | None = None
    elapsed: timedelta | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_error(
        cls,
        *,
        username: str,
        message: str,
        site: WMNSite,
        uri_check: str | None = None,
        uri_pretty: str | None = None,
    ) -> WMNResult:
        """Create error result.

        Args:
            username: Username being checked.
            message: Error message.
            site: Site configuration.
            uri_check: Optional URL used for the check.
            uri_pretty: Optional pretty URL for display.

        Returns:
            WMNResult: Result with ERROR status.
        """
        return cls(
            name=site.get("name", DEFAULT_UNKNOWN_VALUE),
            category=site.get("cat", DEFAULT_UNKNOWN_VALUE),
            username=username,
            uri_check=uri_check,
            uri_pretty=uri_pretty,
            status=WMNStatus.ERROR,
            error=message,
        )

    @classmethod
    def from_not_valid(
        cls,
        *,
        username: str,
        site: WMNSite,
    ) -> WMNResult:
        """Create a NOT_VALID result for sites marked as invalid.

        Args:
            username: Username being checked.
            site: Site configuration.

        Returns:
            WMNResult: Result with NOT_VALID status.
        """
        return cls(
            name=site.get("name", DEFAULT_UNKNOWN_VALUE),
            category=site.get("cat", DEFAULT_UNKNOWN_VALUE),
            username=username,
            status=WMNStatus.NOT_VALID,
        )

    @staticmethod
    def _determine_status(
        *,
        condition_exists: bool,
        condition_missing: bool,
        partial_exists: bool = False,
        partial_missing: bool = False,
    ) -> WMNStatus:
        """Determine result status based on exists/missing conditions.

        Priority order:
        1. CONFLICTING - if both exists and missing conditions are True
        2. EXISTS - if exists condition is True
        3. MISSING - if missing condition is True
        4. PARTIAL_EXISTS - if only code OR text matched for exists
        5. PARTIAL_MISSING - if only code OR text matched for missing
        6. UNKNOWN - if no condition matched

        Args:
            condition_exists: Whether the full "exists" condition matched.
            condition_missing: Whether the full "missing" condition matched.
            partial_exists: Whether a partial "exists" match occurred.
            partial_missing: Whether a partial "missing" match occurred.

        Returns:
            WMNStatus: The determined status based on the priority order above.
        """
        if condition_exists and condition_missing:
            return WMNStatus.CONFLICTING
        if condition_exists:
            return WMNStatus.EXISTS
        if condition_missing:
            return WMNStatus.MISSING
        if partial_exists:
            return WMNStatus.PARTIAL_EXISTS
        if partial_missing:
            return WMNStatus.PARTIAL_MISSING
        return WMNStatus.UNKNOWN

    @classmethod
    def from_response(
        cls,
        *,
        username: str,
        uri_check: str,
        uri_pretty: str | None,
        response: WMNResponse,
        site: WMNSite,
        mode: WMNMode,
        exclude_text: bool = False,
    ) -> WMNResult:
        """Create WMNResult from HTTP response by evaluating detection criteria.

        Args:
            username: Username being checked.
            uri_check: URL that was checked (request URL).
            uri_pretty: Pretty URL for display, or None to use uri_check.
            response: HTTP response object.
            site: Site configuration dictionary with detection criteria.
            mode: Detection mode (ANY or ALL).
            exclude_text: When True, omit response text from the result.

        Returns:
            WMNResult: Result with determined status.
        """
        exists_code_match = response.status_code == site["e_code"]
        exists_text_match = site["e_string"] in response.text
        missing_code_match = response.status_code == site["m_code"]
        missing_text_match = site["m_string"] in response.text

        partial_exists = (exists_code_match and not exists_text_match) or (
            exists_text_match and not exists_code_match
        )
        partial_missing = (missing_code_match and not missing_text_match) or (
            missing_text_match and not missing_code_match
        )

        if mode == WMNMode.ALL:
            condition_exists = exists_code_match and exists_text_match
            condition_missing = missing_code_match and missing_text_match
        else:
            condition_exists = exists_code_match or exists_text_match
            condition_missing = missing_code_match or missing_text_match

        status = cls._determine_status(
            condition_exists=condition_exists,
            condition_missing=condition_missing,
            partial_exists=partial_exists,
            partial_missing=partial_missing,
        )

        return cls(
            name=site["name"],
            category=site["cat"],
            username=username,
            uri_check=uri_check,
            uri_pretty=uri_pretty,
            status=status,
            status_code=response.status_code,
            headers=response.headers,
            elapsed=response.elapsed,
            text=None if exclude_text else response.text,
        )

    def to_dict(
        self,
        *,
        exclude_text: bool = False,
        exclude_none: bool = True,
    ) -> dict[str, Any]:
        """Convert the result to a plain dictionary.

        Args:
            exclude_text: When True, omit the response text field.
            exclude_none: When True, omit fields with None values.

        Returns:
            dict[str, Any]: Dictionary representation of this result.
        """
        result_dict: dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "username": self.username,
            "status": self.status.value,
            "uri_check": self.uri_check,
            "uri_pretty": self.uri_pretty,
            "status_code": self.status_code,
            "headers": self.headers,
            "elapsed": self.elapsed.total_seconds() if self.elapsed else None,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
        }
        if not exclude_text:
            result_dict["text"] = self.text
        if exclude_none:
            result_dict = {
                key: value for key, value in result_dict.items() if value is not None
            }
        return result_dict


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNTestResult:
    """Result of validation testing for a site's detection methods.

    Attributes:
        name: Site name from the WMN dataset.
        category: Site category from the WMN dataset.
        results: List of individual WMNResult objects, or None.
        error: Error message if testing failed.
        created_at: Timestamp when the test result was created.
        status: Aggregate status computed from individual results.
    """

    name: str
    category: str
    results: list[WMNResult] | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: WMNStatus = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", self._get_result_status())

    @classmethod
    def from_site(
        cls,
        site: WMNSite,
        *,
        results: list[WMNResult] | None = None,
        error: str | None = None,
    ) -> WMNTestResult:
        """Create WMNTestResult from a site configuration.

        Args:
            site: Site configuration dictionary.
            results: Optional list of WMNResult objects.
            error: Optional error message.

        Returns:
            WMNTestResult: Result with name and category from site.
        """
        return cls(
            name=site.get(SITE_KEY_NAME, DEFAULT_UNKNOWN_VALUE),
            category=site.get(SITE_KEY_CATEGORY, DEFAULT_UNKNOWN_VALUE),
            results=results,
            error=error,
        )

    def _get_result_status(self) -> WMNStatus:
        """Determine aggregate status from individual results.

        Priority order:
        1. ERROR - if error message exists or any result has ERROR status
        2. UNKNOWN - if no results exist
        3. Single status if all results share the same status
        4. CONFLICTING - if both exist-like (EXISTS/PARTIAL_EXISTS) and
           miss-like (MISSING/PARTIAL_MISSING) statuses are present
        5. PARTIAL_EXISTS or PARTIAL_MISSING if present in mixed statuses
        6. UNKNOWN - for other mixed statuses

        Returns:
            WMNStatus: The aggregate status for this test result.
        """
        if self.error or not self.results:
            return WMNStatus.ERROR if self.error else WMNStatus.UNKNOWN

        statuses = {result.status for result in self.results}

        if WMNStatus.ERROR in statuses:
            return WMNStatus.ERROR

        if len(statuses) == 1:
            return next(iter(statuses))

        exist_signals = {WMNStatus.EXISTS, WMNStatus.PARTIAL_EXISTS}
        miss_signals = {WMNStatus.MISSING, WMNStatus.PARTIAL_MISSING}
        if statuses & exist_signals and statuses & miss_signals:
            return WMNStatus.CONFLICTING

        if WMNStatus.PARTIAL_EXISTS in statuses:
            return WMNStatus.PARTIAL_EXISTS

        return (
            WMNStatus.PARTIAL_MISSING
            if WMNStatus.PARTIAL_MISSING in statuses
            else WMNStatus.UNKNOWN
        )

    def to_dict(
        self,
        *,
        exclude_text: bool = False,
        exclude_none: bool = True,
    ) -> dict[str, Any]:
        """Convert the test result to a plain dictionary.

        Args:
            exclude_text: When True, omit response text from nested results.
            exclude_none: When True, omit fields with None values.

        Returns:
            dict[str, Any]: Dictionary representation of this test result.
        """
        result_dict: dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "results": [
                result.to_dict(
                    exclude_text=exclude_text,
                    exclude_none=exclude_none,
                )
                for result in (self.results or [])
            ],
            "error": self.error,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
        }
        if exclude_none:
            result_dict = {
                key: value for key, value in result_dict.items() if value is not None
            }
        return result_dict


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNResponse:
    """HTTP response abstraction used by session adapters.

    Attributes:
        status_code: HTTP status code of the response.
        text: Response body text.
        elapsed: Time elapsed for the HTTP request.
        headers: HTTP response headers, or None if unavailable.
    """

    status_code: int
    text: str
    elapsed: timedelta
    headers: dict[str, str] | None = None

    def json(self) -> dict[str, Any] | list[Any] | str | int | float | bool | None:
        """Parse the response body as JSON and return the resulting object.

        Returns:
            dict[str, Any] | list[Any] | str | int | float | bool | None:
                The parsed JSON value.

        Raises:
            orjson.JSONDecodeError: If the response text is not valid JSON.
        """
        return orjson.loads(self.text)


@dataclass(frozen=True, slots=True, kw_only=True)
class WMNError:
    """Structured representation of a validation error.

    Attributes:
        path: JSON path where the error occurred.
        data: Preview of the offending data, or None.
        message: Human-readable error description.
    """

    path: str
    data: str | None
    message: str


__all__ = [
    "WMN_REQUIRED_KEYS",
    "WMNDataset",
    "WMNError",
    "WMNMode",
    "WMNResponse",
    "WMNResult",
    "WMNSite",
    "WMNStatus",
    "WMNSummary",
    "WMNTestResult",
]
