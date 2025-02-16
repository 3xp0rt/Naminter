from typing import Final
from pathlib import Path

# Remote data source configuration
SITES_LIST_REMOTE_URL: Final[str] = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

# HTTP request configuration
HTTP_REQUEST_TIMEOUT_SECONDS: Final[int] = 30
HTTP_SSL_VERIFY: Final[bool] = False
HTTP_ALLOW_REDIRECTS: Final[bool] = False

# Browser impersonation settings
BROWSER_IMPERSONATE_AGENT: Final[str] = "chrome"

# Semaphore settings
MAX_TASKS: Final[int] = 50

# Logging format
LOGGING_FORMAT: Final[str] = "%(asctime)s - %(levelname)s - %(message)s"