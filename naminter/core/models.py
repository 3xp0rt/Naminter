from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum, auto
import orjson
from typing import Any, NotRequired, TypedDict

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

    Required fields per JSON schema: name, uri_check, e_code, e_string,
    m_string, m_code, known, cat. Other fields are optional.
    """

    name: str
    cat: str
    uri_check: str
    uri_pretty: NotRequired[str]
    headers: NotRequired[dict[str, str]]
    post_body: NotRequired[str]
    strip_bad_char: NotRequired[str]
    e_code: int
    e_string: str
    m_code: int
    m_string: str
    known: list[str]
    valid: NotRequired[bool]
    protection: NotRequired[list[str]]


WMN_REQUIRED_KEYS: frozenset[str] = frozenset({
    "name",
    "cat",
    "uri_check",
    "e_code",
    "e_string",
    "m_code",
    "m_string",
    "known",
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
    """Summary of the loaded WhatsMyName dataset and filters applied."""

    license: tuple[str, ...]
    authors: tuple[str, ...]
    site_names: tuple[str, ...]
    sites_count: int
    categories: tuple[str, ...]
    categories_count: int
    known_count: int

    def to_dict(self) -> dict[str, Any]:
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
    """Result of testing a username on a site."""

    name: str
    category: str
    username: str
    status: WMNStatus
    url: str | None = None
    status_code: int | None = None
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
        url: str | None = None,
    ) -> WMNResult:
        """Create error result.

        Args:
            username: Username being checked.
            message: Error message.
            site: Site configuration.
            url: Optional URL.

        Returns:
            WMNResult with ERROR status.
        """
        return cls(
            name=site.get("name", DEFAULT_UNKNOWN_VALUE),
            category=site.get("cat", DEFAULT_UNKNOWN_VALUE),
            username=username,
            url=url,
            status=WMNStatus.ERROR,
            error=message,
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
        url: str,
        response: WMNResponse,
        site: WMNSite,
        mode: WMNMode,
        exclude_text: bool = False,
    ) -> WMNResult:
        """Create WMNResult from HTTP response by evaluating detection criteria.

        Args:
            username: Username being checked.
            url: URL that was checked (computed uri_pretty).
            response: HTTP response object.
            site: Site configuration dictionary with detection criteria.
            mode: Detection mode (ANY or ALL).
            exclude_text: When True, omit response text from the result.

        Returns:
            WMNResult with determined status.
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
            url=url,
            status=status,
            status_code=response.status_code,
            elapsed=response.elapsed,
            text=None if exclude_text else response.text,
        )

    def to_dict(
        self,
        *,
        exclude_text: bool = False,
        exclude_none: bool = True,
    ) -> dict[str, Any]:
        result_dict: dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "username": self.username,
            "status": self.status.value,
            "url": self.url,
            "status_code": self.status_code,
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
    """Result of validation testing for a site's detection methods."""

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
            WMNTestResult with name and category extracted from site.
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
        3. Return the single status if all results have the same status
        4. CONFLICTING - if both EXISTS and MISSING are present
        5. PARTIAL_EXISTS - if PARTIAL_EXISTS is present in mixed statuses
        6. PARTIAL_MISSING - if PARTIAL_MISSING is present in mixed statuses
        7. UNKNOWN - for other mixed statuses
        """
        if self.error:
            return WMNStatus.ERROR

        if not self.results:
            return WMNStatus.UNKNOWN

        statuses = {result.status for result in self.results}

        if WMNStatus.ERROR in statuses:
            return WMNStatus.ERROR

        if len(statuses) == 1:
            return next(iter(statuses))

        if WMNStatus.EXISTS in statuses and WMNStatus.MISSING in statuses:
            return WMNStatus.CONFLICTING

        if WMNStatus.PARTIAL_EXISTS in statuses:
            return WMNStatus.PARTIAL_EXISTS

        if WMNStatus.PARTIAL_MISSING in statuses:
            return WMNStatus.PARTIAL_MISSING

        return WMNStatus.UNKNOWN

    def to_dict(
        self,
        *,
        exclude_text: bool = False,
        exclude_none: bool = True,
    ) -> dict[str, Any]:
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
    """HTTP response abstraction used by session adapters."""

    status_code: int
    text: str
    elapsed: timedelta
    headers: dict[str, str] | None = None

    def json(self) -> dict[str, Any] | list[Any] | str | int | float | bool | None:
        """Parse the response body as JSON and return the resulting object.

        Raises:
            orjson.JSONDecodeError: If the response text is not valid JSON.
        """
        return orjson.loads(self.text)


@dataclass(frozen=True, slots=True, kw_only=True)
class WMNError:
    """Structured representation of a validation error."""

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
