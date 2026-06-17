"""Constants for HTTP configuration, WMN data keys, and application settings."""

from typing import Final, Literal

# =============================================================================
# HTTP Configuration
# =============================================================================

# HTTP Methods
HttpMethod = Literal["GET", "POST"]
HTTP_METHOD_GET: Final[HttpMethod] = "GET"
HTTP_METHOD_POST: Final[HttpMethod] = "POST"

# HTTP Request Settings
HTTP_TIMEOUT: Final[int] = 30
HTTP_SSL_VERIFY: Final[bool] = False
HTTP_ALLOW_REDIRECTS: Final[bool] = False

# HTTP Status Code Ranges
HTTP_STATUS_CODE_MIN: Final[int] = 100
HTTP_STATUS_CODE_MAX: Final[int] = 599

# Browser Impersonation Settings
BROWSER_IMPERSONATE_AGENT: Final[str] = "chrome"
BROWSER_IMPERSONATE_NONE: Final[str] = "none"

# =============================================================================
# WMN (WhatsMyName) Configuration
# =============================================================================

# WMN data and schema URLs
WMN_DATA_URL: Final[str] = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
WMN_SCHEMA_URL: Final[str] = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json"
)

# WMN Data Structure Keys
WMN_KEY_SITES: Final[Literal["sites"]] = "sites"
WMN_KEY_CATEGORIES: Final[Literal["categories"]] = "categories"
WMN_KEY_AUTHORS: Final[Literal["authors"]] = "authors"
WMN_KEY_LICENSE: Final[Literal["license"]] = "license"

# Site Object Structure Keys
SITE_KEY_NAME: Final[Literal["name"]] = "name"
SITE_KEY_URI_CHECK: Final[Literal["uri_check"]] = "uri_check"
SITE_KEY_URI_PRETTY: Final[Literal["uri_pretty"]] = "uri_pretty"
SITE_KEY_POST_BODY: Final[Literal["post_body"]] = "post_body"
SITE_KEY_HEADERS: Final[Literal["headers"]] = "headers"
SITE_KEY_STRIP_BAD_CHAR: Final[Literal["strip_bad_char"]] = "strip_bad_char"
SITE_KEY_E_CODE: Final[Literal["e_code"]] = "e_code"
SITE_KEY_E_STRING: Final[Literal["e_string"]] = "e_string"
SITE_KEY_M_STRING: Final[Literal["m_string"]] = "m_string"
SITE_KEY_M_CODE: Final[Literal["m_code"]] = "m_code"
SITE_KEY_KNOWN: Final[Literal["known"]] = "known"
SITE_KEY_CATEGORY: Final[Literal["cat"]] = "cat"
SITE_KEY_VALID: Final[Literal["valid"]] = "valid"

# =============================================================================
# JSON Configuration
# =============================================================================

# JSON Schema Keys
SCHEMA_KEY_PROPERTIES: Final[str] = "properties"
SCHEMA_KEY_ITEMS: Final[str] = "items"

# =============================================================================
# Application Settings
# =============================================================================

# Concurrency Settings
MAX_CONCURRENT_TASKS: Final[int] = 50

# Logging Configuration
LOGGING_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# =============================================================================
# String Constants
# =============================================================================

# Account Name Substitution
ACCOUNT_PLACEHOLDER: Final[str] = "{account}"

# Default Values
DEFAULT_UNKNOWN_VALUE: Final[str] = "unknown"
EMPTY_STRING: Final[str] = ""

# File Operations
DEFAULT_FILE_ENCODING: Final[str] = "utf-8"
