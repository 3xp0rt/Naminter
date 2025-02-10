from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime

class CheckStatus(Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOT_VALID = "not_valid"

@dataclass
class SiteResult:
    site_name: str
    site_url: str
    category: str
    check_status: CheckStatus
    status_code: Optional[int] = None
    elapsed: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class TestResult:
    # username: str
    site_url: str
    check_status: CheckStatus
    status_code: Optional[int] = None
    elapsed: Optional[float] = None
    error: Optional[str] = None
   
@dataclass
class SelfTestResult:
    site_name: str
    category: str
    results: List[TestResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'site_name': self.site_name,
            'results': [asdict(result) for result in self.results]
        }