from typing import Final, Literal

# Remote Data Source Configuration
WMN_REMOTE_URL: Final[str] = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
WMN_SCHEMA_URL: Final[str] = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json"
)

# HTTP Configuration
HTTP_REQUEST_TIMEOUT_SECONDS: Final[int] = 30
HTTP_SSL_VERIFY: Final[bool] = False
HTTP_ALLOW_REDIRECTS: Final[bool] = False

# Browser Impersonation Settings
BROWSER_IMPERSONATE_AGENT: Final[str] = "chrome"
BROWSER_IMPERSONATE_NONE: Final[str] = "none"

# Concurrency Settings
MAX_CONCURRENT_TASKS: Final[int] = 50

# Logging Configuration
LOGGING_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Account Name Substitution
ACCOUNT_PLACEHOLDER: Final[str] = "{account}"

# WMN Dataset Structure Keys
WMN_KEY_SITES: Final[Literal["sites"]] = "sites"
WMN_KEY_CATEGORIES: Final[Literal["categories"]] = "categories"
WMN_KEY_AUTHORS: Final[Literal["authors"]] = "authors"
WMN_KEY_LICENSE: Final[Literal["license"]] = "license"
WMN_KEY_NAME: Final[Literal["name"]] = "name"

WMN_LIST_FIELDS: Final[tuple[str, ...]] = (
    WMN_KEY_SITES,
    WMN_KEY_CATEGORIES,
    WMN_KEY_AUTHORS,
    WMN_KEY_LICENSE,
)

# Site Object Structure Keys
SITE_KEY_NAME: Final[Literal["name"]] = "name"
SITE_KEY_CATEGORY: Final[Literal["cat"]] = "cat"
SITE_KEY_URI_CHECK: Final[Literal["uri_check"]] = "uri_check"
SITE_KEY_URI_PRETTY: Final[Literal["uri_pretty"]] = "uri_pretty"
SITE_KEY_HEADERS: Final[Literal["headers"]] = "headers"
SITE_KEY_POST_BODY: Final[Literal["post_body"]] = "post_body"
SITE_KEY_STRIP_BAD_CHAR: Final[Literal["strip_bad_char"]] = "strip_bad_char"
SITE_KEY_E_CODE: Final[Literal["e_code"]] = "e_code"
SITE_KEY_E_STRING: Final[Literal["e_string"]] = "e_string"
SITE_KEY_M_STRING: Final[Literal["m_string"]] = "m_string"
SITE_KEY_M_CODE: Final[Literal["m_code"]] = "m_code"
SITE_KEY_KNOWN: Final[Literal["known"]] = "known"

# JSON Configuration
DEFAULT_JSON_INDENT: Final[int] = 2
DEFAULT_JSON_ENSURE_ASCII: Final[bool] = False

# JSON Schema Keys
SCHEMA_KEY_PROPERTIES: Final[str] = "properties"
SCHEMA_KEY_ITEMS: Final[str] = "items"

# File Operations
DEFAULT_FILE_ENCODING: Final[str] = "utf-8"

# Default Values and String Processing
DEFAULT_UNKNOWN_VALUE: Final[str] = "unknown"
EMPTY_STRING: Final[str] = ""

# HTTP Methods
HttpMethod = Literal["GET", "POST"]
HTTP_METHOD_GET: Final[HttpMethod] = "GET"
HTTP_METHOD_POST: Final[HttpMethod] = "POST"

# HTTP Status Code Ranges
HTTP_STATUS_CODE_MIN: Final[int] = 100
HTTP_STATUS_CODE_MAX: Final[int] = 599
