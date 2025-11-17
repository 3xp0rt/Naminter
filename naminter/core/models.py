from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from collections.abc import Sequence


class WMNMode(StrEnum):
    """Enumeration mode for username enumeration.

    ALL uses AND logic, ANY uses OR logic.
    """

    ALL = auto()
    ANY = auto()


class WMNStatus(StrEnum):
    """Status of username search results."""

    FOUND = auto()
    AMBIGUOUS = auto()
    UNKNOWN = auto()
    NOT_FOUND = auto()
    NOT_VALID = auto()
    ERROR = auto()


class WMNDataset(TypedDict):
    """Type definition for WMN dataset structure."""

    sites: list[dict[str, Any]]
    categories: list[str]
    authors: list[str]
    license: str | list[str]


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
    response_code: int | None = None
    response_text: str | None = None
    elapsed: float | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_error(
        cls,
        *,
        name: str,
        category: str,
        username: str,
        message: str,
        url: str | None = None,
    ) -> WMNResult:
        return cls(
            name=name,
            category=category,
            username=username,
            url=url,
            status=WMNStatus.ERROR,
            error=message,
        )

    @classmethod
    def from_response(
        cls,
        *,
        name: str,
        category: str,
        username: str,
        url: str | None,
        response_code: int,
        response_text: str,
        elapsed: float | None,
        mode: WMNMode,
        e_code: int | None,
        e_string: str | None,
        m_code: int | None,
        m_string: str | None,
    ) -> WMNResult:
        if mode == WMNMode.ANY:
            condition_found = (e_code is not None and response_code == e_code) or (
                e_string is not None and e_string in response_text
            )
            condition_not_found = (m_code is not None and response_code == m_code) or (
                m_string is not None and m_string in response_text
            )
        else:
            condition_found = (
                (e_code is None or response_code == e_code)
                and (e_string is None or e_string in response_text)
                and (e_code is not None or e_string is not None)
            )
            condition_not_found = (
                (m_code is None or response_code == m_code)
                and (m_string is None or m_string in response_text)
                and (m_code is not None or m_string is not None)
            )

        if condition_found and condition_not_found:
            status = WMNStatus.AMBIGUOUS
        elif condition_found:
            status = WMNStatus.FOUND
        elif condition_not_found:
            status = WMNStatus.NOT_FOUND
        else:
            status = WMNStatus.UNKNOWN

        return cls(
            name=name,
            category=category,
            username=username,
            url=url,
            status=status,
            response_code=response_code,
            elapsed=elapsed,
            response_text=response_text,
        )

    def to_dict(
        self, *, exclude_response_text: bool = False, include_none: bool = False
    ) -> dict[str, Any]:
        result_dict: dict[str, Any] = {
            "name": self.name,
            "category": self.category,
            "username": self.username,
            "status": self.status.value,
            "url": self.url,
            "response_code": self.response_code,
            "elapsed": self.elapsed,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
        }
        if not exclude_response_text:
            result_dict["response_text"] = self.response_text
        if not include_none:
            result_dict = {
                key: value for key, value in result_dict.items() if value is not None
            }
        return result_dict


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNValidationResult:
    """Result of validation testing for a site's detection methods."""

    name: str
    category: str
    results: Sequence[WMNResult] | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: WMNStatus = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", self._get_result_status())

    def _get_result_status(self) -> WMNStatus:
        status = WMNStatus.UNKNOWN
        if self.error:
            status = WMNStatus.ERROR
        elif not self.results:
            status = WMNStatus.UNKNOWN
        else:
            statuses = {result.status for result in self.results}
            if WMNStatus.ERROR in statuses:
                status = WMNStatus.ERROR
            elif WMNStatus.FOUND in statuses and WMNStatus.NOT_FOUND in statuses:
                status = WMNStatus.AMBIGUOUS
            elif len(statuses) == 1:
                status = next(iter(statuses))
        return status

    def to_dict(self, *, exclude_response_text: bool = False) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "results": [
                result.to_dict(exclude_response_text=exclude_response_text)
                for result in (self.results or [])
            ],
            "error": self.error,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(slots=True, frozen=True, kw_only=True)
class WMNResponse:
    """HTTP response abstraction used by session adapters."""

    status_code: int
    text: str
    elapsed: float

    def json(self) -> Any:
        """Parse the response body as JSON and return the resulting object."""
        return json.loads(self.text)


@dataclass(frozen=True, slots=True, kw_only=True)
class WMNValidationModel:
    """Structured representation of a validation error."""

    path: str
    data: str | None
    message: str
