import logging
from typing import Any

from .constants import (
    EXTREME_CONCURRENCY_THRESHOLD,
    HIGH_CONCURRENCY_MIN_TIMEOUT,
    HIGH_CONCURRENCY_THRESHOLD,
    LOW_TIMEOUT_WARNING_THRESHOLD,
    MAX_TASKS_LIMIT,
    MAX_TIMEOUT,
    MIN_TASKS,
    MIN_TIMEOUT,
    VERY_HIGH_CONCURRENCY_MIN_TIMEOUT,
    VERY_HIGH_CONCURRENCY_THRESHOLD,
    WMN_LIST_FIELDS,
)
from .exceptions import (
    ConfigurationError,
    ValidationError,
)

logger = logging.getLogger(__name__)


def deduplicate_strings(values: list[str] | None) -> list[str]:
    """Return a list of unique, non-empty strings preserving original order."""
    if not values:
        return []

    seen: set[str] = set()
    unique_values: list[str] = []

    for item in values:
        if isinstance(item, str):
            normalized = item.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_values.append(normalized)

    return unique_values


def validate_numeric_values(max_tasks: int, timeout: int) -> list[str]:
    """Validate numeric configuration values and return warnings."""
    warnings: list[str] = []

    if not (MIN_TASKS <= max_tasks <= MAX_TASKS_LIMIT):
        msg = (
            "Invalid max_tasks: "
            f"{max_tasks} must be between {MIN_TASKS} and {MAX_TASKS_LIMIT}"
        )
        raise ConfigurationError(
            msg
        )

    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        msg = (
            "Invalid timeout: "
            f"{timeout} must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds"
        )
        raise ConfigurationError(
            msg
        )

    if (
        max_tasks > HIGH_CONCURRENCY_THRESHOLD
        and timeout < HIGH_CONCURRENCY_MIN_TIMEOUT
    ):
        warnings.append(
            "High concurrency ("
            f"{max_tasks}) with low timeout ({timeout}s) may cause failures; "
            "consider increasing timeout or reducing max_tasks."
        )
    elif (
        max_tasks > VERY_HIGH_CONCURRENCY_THRESHOLD
        and timeout < VERY_HIGH_CONCURRENCY_MIN_TIMEOUT
    ):
        warnings.append(
            "Very high concurrency ("
            f"{max_tasks}) with very low timeout ({timeout}s) may cause connection "
            "issues; recommend timeout >= "
            f"{HIGH_CONCURRENCY_MIN_TIMEOUT}s for max_tasks > "
            f"{VERY_HIGH_CONCURRENCY_THRESHOLD}."
        )

    if max_tasks > EXTREME_CONCURRENCY_THRESHOLD:
        warnings.append(
            "Extremely high concurrency ("
            f"{max_tasks}) may overwhelm servers or cause rate limiting; "
            "lowering value is recommended."
        )

    if timeout < LOW_TIMEOUT_WARNING_THRESHOLD:
        warnings.append(
            "Very low timeout ("
            f"{timeout}s) may cause legitimate requests to fail; increase "
            "timeout for better accuracy."
        )

    return warnings


def configure_proxy(proxy: str | dict[str, str] | None) -> dict[str, str] | None:
    """Validate and configure proxy settings."""
    if proxy is None:
        return None

    if isinstance(proxy, str):
        if not proxy.strip():
            msg = "Invalid proxy: proxy string cannot be empty"
            raise ConfigurationError(msg)

        if not (
            proxy.startswith(("http://", "https://", "socks5://"))
        ):
            msg = "Invalid proxy: must be http://, https://, or socks5:// URL"
            raise ConfigurationError(
                msg
            )

        logger.debug("Proxy configuration validated")
        return {"http": proxy, "https": proxy}

    elif isinstance(proxy, dict):
        for protocol, proxy_url in proxy.items():
            if protocol not in {"http", "https"}:
                msg = f"Invalid proxy protocol: {protocol}"
                raise ConfigurationError(msg)

            if not isinstance(proxy_url, str) or not proxy_url.strip():
                msg = f"Invalid proxy URL for {protocol}: must be non-empty string"
                raise ConfigurationError(
                    msg
                )

        logger.debug("Proxy dictionary configuration validated")
        return proxy


def validate_usernames(usernames: list[str]) -> list[str]:
    """Validate and deduplicate usernames, preserving order."""

    unique_usernames: list[str] = deduplicate_strings(usernames)

    if not unique_usernames:
        msg = "No valid usernames provided"
        raise ValidationError(msg)

    return unique_usernames


def merge_lists(data: dict[str, Any], accumulator: dict[str, Any]) -> None:
    """Merge list fields from data into the accumulator dictionary."""
    if isinstance(data, dict):
        for key in WMN_LIST_FIELDS:
            if key in data and isinstance(data[key], list):
                accumulator[key].extend(data[key])
