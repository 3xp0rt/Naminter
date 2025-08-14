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
