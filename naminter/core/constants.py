from typing import Final

# Remote data source configuration
WMN_REMOTE_URL: Final[str] = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
WMN_SCHEMA_URL: Final[str] = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json"

# HTTP request configuration
HTTP_REQUEST_TIMEOUT_SECONDS: Final[int] = 30
HTTP_SSL_VERIFY: Final[bool] = False
HTTP_ALLOW_REDIRECTS: Final[bool] = False

# Browser impersonation settings
BROWSER_IMPERSONATE_AGENT: Final[str] = "chrome"

# Concurrency settings
MAX_CONCURRENT_TASKS: Final[int] = 50

# Validation ranges and thresholds
MIN_TASKS: Final[int] = 1
MAX_TASKS_LIMIT: Final[int] = 1000
MIN_TIMEOUT: Final[int] = 0
MAX_TIMEOUT: Final[int] = 300

# Performance warning thresholds
HIGH_CONCURRENCY_THRESHOLD: Final[int] = 100
HIGH_CONCURRENCY_MIN_TIMEOUT: Final[int] = 10
VERY_HIGH_CONCURRENCY_THRESHOLD: Final[int] = 50
VERY_HIGH_CONCURRENCY_MIN_TIMEOUT: Final[int] = 5
EXTREME_CONCURRENCY_THRESHOLD: Final[int] = 500
LOW_TIMEOUT_WARNING_THRESHOLD: Final[int] = 3

# Logging format - includes logger name to distinguish between core and cli
LOGGING_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Placeholder for account name substitution in uri_check or post_body
ACCOUNT_PLACEHOLDER: Final[str] = "{account}"

# Required key sets for validations
REQUIRED_KEYS_ENUMERATE: Final[tuple[str, ...]] = (
    "name",
    "uri_check",
    "e_code",
    "e_string",
    "m_string",
    "m_code",
    "cat",
)

REQUIRED_KEYS_SELF_ENUM: Final[tuple[str, ...]] = (
    "name",
    "cat",
    "known",
)

# WMN dataset keys
WMN_KEY_SITES: Final[str] = "sites"
WMN_KEY_CATEGORIES: Final[str] = "categories"
WMN_KEY_AUTHORS: Final[str] = "authors"
WMN_KEY_LICENSE: Final[str] = "license"
WMN_KEY_NAME: Final[str] = "name"

# Collection of list fields present in WMN payloads
WMN_LIST_FIELDS: Final[tuple[str, ...]] = (
    WMN_KEY_SITES,
    WMN_KEY_CATEGORIES,
    WMN_KEY_AUTHORS,
    WMN_KEY_LICENSE,
)

