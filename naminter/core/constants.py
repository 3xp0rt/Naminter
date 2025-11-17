from typing import Final

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
WMN_KEY_SITES: Final[str] = "sites"
WMN_KEY_CATEGORIES: Final[str] = "categories"
WMN_KEY_AUTHORS: Final[str] = "authors"
WMN_KEY_LICENSE: Final[str] = "license"
WMN_KEY_NAME: Final[str] = "name"

WMN_LIST_FIELDS: Final[tuple[str, ...]] = (
    WMN_KEY_SITES,
    WMN_KEY_CATEGORIES,
    WMN_KEY_AUTHORS,
    WMN_KEY_LICENSE,
)

# Site Object Structure Keys
SITE_KEY_NAME: Final[str] = "name"
SITE_KEY_CATEGORY: Final[str] = "cat"
SITE_KEY_URI_CHECK: Final[str] = "uri_check"
SITE_KEY_URI_PRETTY: Final[str] = "uri_pretty"
SITE_KEY_HEADERS: Final[str] = "headers"
SITE_KEY_POST_BODY: Final[str] = "post_body"
SITE_KEY_STRIP_BAD_CHAR: Final[str] = "strip_bad_char"
SITE_KEY_E_CODE: Final[str] = "e_code"
SITE_KEY_E_STRING: Final[str] = "e_string"
SITE_KEY_M_STRING: Final[str] = "m_string"
SITE_KEY_M_CODE: Final[str] = "m_code"
SITE_KEY_KNOWN: Final[str] = "known"

# Validation Requirements
REQUIRED_KEYS_ENUMERATE: Final[tuple[str, ...]] = (
    SITE_KEY_NAME,
    SITE_KEY_URI_CHECK,
    SITE_KEY_E_CODE,
    SITE_KEY_E_STRING,
    SITE_KEY_M_STRING,
    SITE_KEY_M_CODE,
    SITE_KEY_CATEGORY,
)

REQUIRED_KEYS_SELF_ENUM: Final[tuple[str, ...]] = (
    SITE_KEY_NAME,
    SITE_KEY_CATEGORY,
    SITE_KEY_KNOWN,
)

# JSON Configuration
DEFAULT_JSON_INDENT: Final[int] = 2
DEFAULT_JSON_ENCODING: Final[str] = "utf-8"
DEFAULT_JSON_ENSURE_ASCII: Final[bool] = False

# File Operations
DEFAULT_FILE_ENCODING: Final[str] = "utf-8"

# Default Values and String Processing
DEFAULT_UNKNOWN_VALUE: Final[str] = "unknown"
EMPTY_STRING: Final[str] = ""
