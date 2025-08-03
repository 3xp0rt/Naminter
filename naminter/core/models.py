from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional, Dict, Any, List, Union, Set, Literal, TypedDict
from datetime import datetime
from curl_cffi import BrowserTypeLiteral, CurlSslVersion, ExtraFingerprints

class ResultStatus(Enum):
    """Status of username search results."""
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    NOT_VALID = "not_valid"

@dataclass
class SiteResult:
    """Result of testing a username on a site."""
    site_name: str
    category: str
    username: str
    result_status: ResultStatus
    result_url: Optional[str] = None
    response_code: Optional[int] = None
    response_text: Optional[str] = None
    elapsed: Optional[float] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        """Validate numeric fields after initialization."""
        if self.response_code is not None and self.response_code < 0:
            raise ValueError("response_code must be non-negative")
        
        if self.elapsed is not None and self.elapsed < 0:
            raise ValueError("elapsed must be non-negative")

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
        result['result_status'] = self.result_status.value
        result['created_at'] = self.created_at.isoformat()
        if exclude_response_text:
            result.pop('response_text', None)
        return result

@dataclass
class SelfCheckResult:
    """Result of a self-check for a username."""
    site_name: str
    category: str
    results: List[SiteResult]
    overall_status: ResultStatus = field(init=False)
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        """Calculate overall status from results."""
        self.overall_status = self._get_overall_status()

    def _get_overall_status(self) -> ResultStatus:
        """Determine overall status from results."""
        if self.error:
            return ResultStatus.ERROR
            
        if not self.results:
            return ResultStatus.UNKNOWN
            
        statuses: Set[ResultStatus] = {result.result_status for result in self.results if result}
        
        if not statuses:
            return ResultStatus.UNKNOWN
        
        if ResultStatus.ERROR in statuses:
            return ResultStatus.ERROR
            
        if len(statuses) > 1:
            return ResultStatus.UNKNOWN
            
        return next(iter(statuses))
        
    def to_dict(self, exclude_response_text: bool = False) -> Dict[str, Any]:
        """Convert SelfCheckResult to dict."""
        return {
            'site_name': self.site_name,
            'category': self.category,
            'overall_status': self.overall_status.value,
            'results': [result.to_dict(exclude_response_text=exclude_response_text) for result in self.results],
            'created_at': self.created_at.isoformat(),
            'error': self.error,
        }

