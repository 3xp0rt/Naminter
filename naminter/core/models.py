from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional, Dict, Any, List, Union, Set
from datetime import datetime

def serialize_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO format string."""
    if dt is None:
        return None
    if not isinstance(dt, datetime):
        raise ValueError(f"Input must be a datetime object, got {type(dt)}")
    return dt.isoformat()

def deserialize_datetime(dt_str: Union[str, datetime, None]) -> Optional[datetime]:
    """Convert ISO string to datetime."""
    if dt_str is None:
        return None
    
    if isinstance(dt_str, datetime):
        return dt_str
    
    if not isinstance(dt_str, str):
        raise ValueError(f"Datetime input must be string, datetime, or None, got {type(dt_str)}")
    
    dt_str = dt_str.strip()
    if not dt_str:
        return None
    
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError as e:
        raise ValueError(f"Invalid datetime format '{dt_str}': {e}") from e

class ResultStatus(Enum):
    """Status of username search results."""
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOT_VALID = "not_valid"
    
    def __str__(self) -> str:
        """Return status as string."""
        return self.value
    
    @classmethod
    def from_string(cls, value: str) -> "ResultStatus":
        """Create ResultStatus from string."""
        try:
            return cls(value.lower().strip())
        except ValueError as e:
            raise ValueError(f"Invalid result status: '{value}'") from e

class BrowserImpersonation(str, Enum):
    """Browser impersonation options."""
    NONE = "none"
    CHROME = "chrome"
    CHROME_ANDROID = "chrome_android"
    SAFARI = "safari"
    SAFARI_IOS = "safari_ios"
    EDGE = "edge"
    FIREFOX = "firefox"

    def __str__(self) -> str:
        """Return browser impersonation as string."""
        return self.value

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
        """Validate fields after initialization."""
        self._validate_string_field('site_name', self.site_name)
        self._validate_string_field('category', self.category)
        self._validate_string_field('username', self.username)
        if self.result_url is not None:
            self._validate_string_field('result_url', self.result_url)
        
        if not isinstance(self.result_status, ResultStatus):
            raise ValueError("result_status must be a valid ResultStatus")
        
        if self.response_code is not None and (not isinstance(self.response_code, int) or self.response_code < 0):
            raise ValueError("response_code must be a non-negative integer")
        
        if self.elapsed is not None and (not isinstance(self.elapsed, (int, float)) or self.elapsed < 0):
            raise ValueError("elapsed must be a non-negative number")

    @classmethod
    def determine_result_status(
        cls,
        response_code: int,
        response_text: str,
        e_code: Optional[int] = None,
        e_string: Optional[str] = None,
        m_code: Optional[int] = None,
        m_string: Optional[str] = None,
        fuzzy_mode: bool = False,
    ) -> ResultStatus:
        """Determine result status from response data."""
        exists_status_matches = e_code is not None and response_code == e_code
        exists_string_matches = bool(e_string and e_string in response_text)
        not_exists_status_matches = m_code is not None and response_code == m_code
        not_exists_string_matches = bool(m_string and m_string in response_text)

        if fuzzy_mode:
            condition_found = exists_status_matches or exists_string_matches
            condition_not_found = not_exists_status_matches or not_exists_string_matches
        else:
            condition_found = (
                (e_code is not None and e_string and exists_status_matches and exists_string_matches) or
                (e_code is not None and not e_string and exists_status_matches) or
                (e_code is None and e_string and exists_string_matches)
            )
            condition_not_found = (
                (m_code is not None and m_string and not_exists_status_matches and not_exists_string_matches) or
                (m_code is not None and not m_string and not_exists_status_matches) or
                (m_code is None and m_string and not_exists_string_matches)
            )

        return (
            ResultStatus.FOUND if condition_found else
            ResultStatus.NOT_FOUND if condition_not_found else
            ResultStatus.UNKNOWN
        )

    def _validate_string_field(self, field_name: str, value: Any) -> None:
        """Validate a non-empty string field."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

    def to_dict(self, exclude_response_text: bool = False) -> Dict[str, Any]:
        """Convert SiteResult to dict."""
        try:
            result = asdict(self)
            result['result_status'] = self.result_status.value
            result['created_at'] = serialize_datetime(self.created_at)
            
            if exclude_response_text:
                result.pop('response_text', None)
                
            return result
        except Exception as e:
            raise ValueError(f"Failed to serialize SiteResult: {e}") from e

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
        """Validate fields after initialization."""
        self._validate_string_field('site_name', self.site_name)
        self._validate_string_field('category', self.category)
        
        if not isinstance(self.results, list):
            raise ValueError("results must be a list")
        
        for i, result in enumerate(self.results):
            if not isinstance(result, SiteResult):
                raise ValueError(f"results[{i}] must be a SiteResult instance")
        
        self.overall_status = self._determine_overall_status()

        if self.error:
            self.overall_status = ResultStatus.ERROR

    def _validate_string_field(self, field_name: str, value: Any) -> None:
        """Validate a non-empty string field."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

    def _determine_overall_status(self) -> ResultStatus:
        """Determine overall status from results."""
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
        try:
            return {
                'site_name': self.site_name,
                'category': self.category,
                'overall_status': self.overall_status.value,
                'results': [result.to_dict(exclude_response_text=exclude_response_text) for result in self.results],
                'created_at': serialize_datetime(self.created_at),
                'error': self.error,
            }
        except Exception as e:
            raise ValueError(f"Failed to serialize SelfCheckResult: {e}") from e

