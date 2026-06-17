"""Naminter: Async OSINT username enumeration using the WhatsMyName dataset."""

from naminter._metadata import __description__, __email__, __license__, __url__
from naminter.core.constants import WMN_DATA_URL, WMN_SCHEMA_URL
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
)
from naminter.core.formatter import WMNFormatter
from naminter.core.main import Naminter
from naminter.core.models import (
    WMNMode,
    WMNResponse,
    WMNResult,
    WMNStatus,
    WMNSummary,
    WMNTestResult,
)
from naminter.core.network import BaseSession, CurlCFFISession
from naminter.core.validator import WMNValidator

__version__ = "1.0.7"
__author__ = "3xp0rt"
__all__ = [
    "WMN_DATA_URL",
    "WMN_SCHEMA_URL",
    "BaseSession",
    "CurlCFFISession",
    "HttpError",
    "HttpSessionError",
    "Naminter",
    "WMNFormatter",
    "WMNMode",
    "WMNResponse",
    "WMNResult",
    "WMNStatus",
    "WMNSummary",
    "WMNTestResult",
    "WMNValidator",
]
