from dataclasses import dataclass, asdict, field
from enum import StrEnum, auto
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
import json

class ValidationMode(StrEnum):
    FUZZY = auto()
    STRICT = auto()

class ResultStatus(StrEnum):
    """Status of username search results."""
    FOUND = auto()
    AMBIGUOUS = auto()
    UNKNOWN = auto()
    NOT_FOUND = auto()
    NOT_VALID = auto()
    ERROR = auto()

@dataclass(slots=True, frozen=True)
class SiteResult:
    """Result of testing a username on a site."""
    name: str
    category: str
    username: str
    status: ResultStatus
    result_url: Optional[str] = None
    response_code: Optional[int] = None
    response_text: Optional[str] = None
    elapsed: Optional[float] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def get_result_status(
        cls,
        response_code: int,
        response_text: str,
        e_code: Optional[int] = None,
        e_string: Optional[str] = None,
        m_code: Optional[int] = None,
        m_string: Optional[str] = None,
        fuzzy_mode: bool = False,
    ) -> ResultStatus:
        condition_found = False
        condition_not_found = False

        if fuzzy_mode:
            condition_found = (e_code is not None and response_code == e_code) or (e_string and e_string in response_text)
            condition_not_found = (m_code is not None and response_code == m_code) or (m_string and m_string in response_text)
        else:
            condition_found = (
                (e_code is None or response_code == e_code) and
                (e_string is None or e_string in response_text) and
                (e_code is not None or e_string is not None)
            )

            condition_not_found = (
                (m_code is None or response_code == m_code) and
                (m_string is None or m_string in response_text) and
                (m_code is not None or m_string is not None)
            )

        if condition_found and condition_not_found:
            return ResultStatus.AMBIGUOUS
        elif condition_found:
            return ResultStatus.FOUND
        elif condition_not_found:
            return ResultStatus.NOT_FOUND
        else:
            return ResultStatus.UNKNOWN

    def to_dict(self, exclude_response_text: bool = False) -> Dict[str, Any]:
        """Convert SiteResult to dict."""
        result = asdict(self)
        result['status'] = self.status.value
        result['created_at'] = self.created_at.isoformat()
        if exclude_response_text:
            result.pop('response_text', None)
        return result

@dataclass(slots=True, frozen=True)
class SelfEnumerationResult:
    """Result of a self-enumeration for a username."""
    name: str
    category: str
    results: Optional[List[SiteResult]] = None
    status: ResultStatus = field(init=False)
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        """Calculate result status from results."""
        object.__setattr__(self, 'status', self._get_result_status())

    def _get_result_status(self) -> ResultStatus:
        """Determine result status from results."""
        if self.error:
            return ResultStatus.ERROR
            
        if not self.results:
            return ResultStatus.UNKNOWN
            
        statuses: Set[ResultStatus] = {result.status for result in self.results if result}
        
        if not statuses:
            return ResultStatus.UNKNOWN
        
        if ResultStatus.ERROR in statuses:
            return ResultStatus.ERROR
            
        if len(statuses) > 1:
            return ResultStatus.UNKNOWN
            
        return next(iter(statuses))
        
    def to_dict(self, exclude_response_text: bool = False) -> Dict[str, Any]:
        """Convert SelfEnumerationResult to dict."""
        return {
            'name': self.name,
            'category': self.category,
            'results': [result.to_dict(exclude_response_text=exclude_response_text) for result in self.results] if self.results else [],
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'error': self.error,
        }

@dataclass(slots=True, frozen=True)
class Summary:
    """Summary of the loaded WhatsMyName dataset and filters applied."""
    license: List[str]
    authors: List[str]
    site_names: List[str]
    sites_count: int
    categories: List[str]
    categories_count: int
    known_accounts_total: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert Summary to a plain dictionary for serialization/legacy callers."""
        return {
            'license': list(self.license),
            'authors': list(self.authors),
            'site_names': list(self.site_names),
            'sites_count': int(self.sites_count),
            'categories': list(self.categories),
            'categories_count': int(self.categories_count),
            'known_accounts_total': int(self.known_accounts_total),
        }

@dataclass(slots=True, frozen=True)
class Response:
    """HTTP response abstraction used by session adapters."""
    status_code: int
    text: str
    elapsed: float

    def json(self) -> Any:
        """Parse the response body as JSON and return the resulting object.

        Raises:
            ValueError: If the response text is not valid JSON.
        """
        return json.loads(self.text)