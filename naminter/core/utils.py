import logging
import json
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Set, Tuple

from .exceptions import (
    ConfigurationError,
    DataError,
    SchemaError,
    ValidationError,
)

from .constants import (
    WMN_REMOTE_URL,
    MIN_TASKS,
    MAX_TASKS_LIMIT,
    MIN_TIMEOUT,
    MAX_TIMEOUT,
    HIGH_CONCURRENCY_THRESHOLD,
    HIGH_CONCURRENCY_MIN_TIMEOUT,
    VERY_HIGH_CONCURRENCY_THRESHOLD,
    VERY_HIGH_CONCURRENCY_MIN_TIMEOUT,
    EXTREME_CONCURRENCY_THRESHOLD,
    LOW_TIMEOUT_WARNING_THRESHOLD,
    WMN_LIST_FIELDS,
)
from .network import BaseSession

logger = logging.getLogger(__name__)


def deduplicate_strings(values: Optional[List[str]]) -> List[str]:
    """Return a list of unique, non-empty strings preserving original order."""
    if not values:
        return []

    seen: Set[str] = set()
    unique_values: List[str] = []

    for item in values:
        if isinstance(item, str):
            normalized = item.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_values.append(normalized)

    return unique_values

def validate_numeric_values(max_tasks: int, timeout: int) -> List[str]:
    """Validate numeric configuration values and return warnings.
    """
    warnings: List[str] = []

    if not (MIN_TASKS <= max_tasks <= MAX_TASKS_LIMIT):
        raise ConfigurationError(f"Invalid max_tasks: {max_tasks} must be between {MIN_TASKS} and {MAX_TASKS_LIMIT}")
    
    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        raise ConfigurationError(f"Invalid timeout: {timeout} must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")

    if max_tasks > HIGH_CONCURRENCY_THRESHOLD and timeout < HIGH_CONCURRENCY_MIN_TIMEOUT:
        warnings.append(
            f"High concurrency ({max_tasks}) with low timeout ({timeout}s) may cause failures; consider increasing timeout or reducing max_tasks."
        )
    elif max_tasks > VERY_HIGH_CONCURRENCY_THRESHOLD and timeout < VERY_HIGH_CONCURRENCY_MIN_TIMEOUT:
        warnings.append(
            f"Very high concurrency ({max_tasks}) with very low timeout ({timeout}s) may cause connection issues; recommend timeout >= {HIGH_CONCURRENCY_MIN_TIMEOUT}s for max_tasks > {VERY_HIGH_CONCURRENCY_THRESHOLD}."
        )

    if max_tasks > EXTREME_CONCURRENCY_THRESHOLD:
        warnings.append(
            f"Extremely high concurrency ({max_tasks}) may overwhelm servers or cause rate limiting; lowering value is recommended."
        )

    if timeout < LOW_TIMEOUT_WARNING_THRESHOLD:
        warnings.append(
            f"Very low timeout ({timeout}s) may cause legitimate requests to fail; increase timeout for better accuracy."
        )

    return warnings

def configure_proxy(proxy: Optional[Union[str, Dict[str, str]]]) -> Optional[Dict[str, str]]:
    """Validate and configure proxy settings."""
    if proxy is None:
        return None

    if isinstance(proxy, str):
        if not proxy.strip():
            raise ConfigurationError("Invalid proxy: proxy string cannot be empty")
        
        if not (proxy.startswith('http://') or proxy.startswith('https://') or proxy.startswith('socks5://')):
            raise ConfigurationError("Invalid proxy: must be http://, https://, or socks5:// URL")
        
        logger.debug("Proxy configuration validated")
        return {"http": proxy, "https": proxy}
    
    elif isinstance(proxy, dict):
        for protocol, proxy_url in proxy.items():
            if protocol not in ['http', 'https']:
                raise ConfigurationError(f"Invalid proxy protocol: {protocol}")
            
            if not isinstance(proxy_url, str) or not proxy_url.strip():
                raise ConfigurationError(f"Invalid proxy URL for {protocol}: must be non-empty string")
        
        logger.debug("Proxy dictionary configuration validated")
        return proxy

def validate_usernames(usernames: List[str]) -> List[str]:
    """Validate and deduplicate usernames, preserving order."""

    unique_usernames: List[str] = deduplicate_strings(usernames)

    if not unique_usernames:
        raise ValidationError("No valid usernames provided")

    return unique_usernames

def merge_lists(data: Dict[str, Any], accumulator: Dict[str, Any]) -> None:
    """Merge list fields from data into the accumulator dictionary."""
    if isinstance(data, dict):
        for key in WMN_LIST_FIELDS:
            if key in data and isinstance(data[key], list):
                accumulator[key].extend(data[key])
