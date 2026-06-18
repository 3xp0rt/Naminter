"""Naminter: Async OSINT username enumeration using the WhatsMyName dataset."""

from __future__ import annotations

from email.utils import parseaddr
from importlib.metadata import metadata, version

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

_distribution = "naminter"
_meta = metadata(_distribution)

__version__ = version(_distribution)
__author__, __email__ = parseaddr(_meta.get("Author-email", ""))
__description__ = _meta.get("Summary", "")
__license__ = _meta.get("License", "")
__url__ = ""
for _entry in _meta.get_all("Project-URL") or []:
    _name, _, _url = _entry.partition(", ")
    if _name == "Homepage" and _url:
        __url__ = _url
        break

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
