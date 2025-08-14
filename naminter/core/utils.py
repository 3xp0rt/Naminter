import logging
from typing import Any, Dict, List, Optional, Union, Set

import jsonschema

from .exceptions import (
    ConfigurationError,
    DataError,
    SchemaValidationError,
    ValidationError,
)
from .constants import (
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
)

logger = logging.getLogger(__name__)


def validate_wmn_data(data: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> None:
    """Validate WMN data against schema."""
    if not data:
        logger.error("No WMN data provided during initialization.")
        raise DataError("No WMN data provided during initialization.")

    if schema:
        try:
            jsonschema.validate(instance=data, schema=schema)
            logger.info("WMN data validation successful")
        except jsonschema.ValidationError as e:
            logger.error(f"WMN data does not match schema: {e.message}")
            raise SchemaValidationError(f"WMN data does not match schema: {e.message}") from e
        except jsonschema.SchemaError as e:
            logger.error(f"Invalid WMN schema: {e.message}")
            raise SchemaValidationError(f"Invalid WMN schema: {e.message}") from e
    else:
        logger.warning("No schema provided - skipping WMN data validation")


def validate_numeric_values(max_tasks: int, timeout: int) -> None:
    """Validate numeric configuration values for max_tasks and timeout."""
    logger.debug(f"Validating numeric values: max_tasks={max_tasks}, timeout={timeout}")
    
    if not (MIN_TASKS <= max_tasks <= MAX_TASKS_LIMIT):
        logger.error(f"max_tasks out of range: {max_tasks} not in [{MIN_TASKS}-{MAX_TASKS_LIMIT}]")
        raise ConfigurationError(f"Invalid max_tasks: {max_tasks} must be between {MIN_TASKS} and {MAX_TASKS_LIMIT}")
    
    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        logger.error(f"timeout out of range: {timeout} not in [{MIN_TIMEOUT}-{MAX_TIMEOUT}]")
        raise ConfigurationError(f"Invalid timeout: {timeout} must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")

    if max_tasks > HIGH_CONCURRENCY_THRESHOLD and timeout < HIGH_CONCURRENCY_MIN_TIMEOUT:
        logger.warning(
            f"High concurrency ({max_tasks} tasks) with low timeout ({timeout}s) may cause failures - consider increasing timeout or reducing max_tasks"
        )
    elif max_tasks > VERY_HIGH_CONCURRENCY_THRESHOLD and timeout < VERY_HIGH_CONCURRENCY_MIN_TIMEOUT:
        logger.warning(
            f"Very high concurrency ({max_tasks} tasks) with very low timeout ({timeout}s) may cause connection issues - recommend timeout >= {HIGH_CONCURRENCY_MIN_TIMEOUT}s for max_tasks > {VERY_HIGH_CONCURRENCY_THRESHOLD}"
        )

    if max_tasks > EXTREME_CONCURRENCY_THRESHOLD:
        logger.warning(
            f"Extremely high concurrency ({max_tasks} tasks) may overwhelm servers or cause rate limiting - lower value recommended"
        )

    if timeout < LOW_TIMEOUT_WARNING_THRESHOLD:
        logger.warning(
            f"Very low timeout ({timeout}s) may cause legitimate requests to fail - increase timeout for better accuracy"
        )


def configure_proxy(proxy: Optional[Union[str, Dict[str, str]]]) -> Optional[Dict[str, str]]:
    """Validate and configure proxy settings."""
    if proxy is None:
        return None

    if isinstance(proxy, str):
        if not proxy.strip():
            logger.error("Proxy validation failed: empty string.")
            raise ConfigurationError("Invalid proxy: proxy string cannot be empty")
        
        if not (proxy.startswith('http://') or proxy.startswith('https://') or proxy.startswith('socks5://')):
            logger.error(f"Proxy validation failed: invalid protocol in '{proxy}'")
            raise ConfigurationError("Invalid proxy: must be http://, https://, or socks5:// URL")
        
        logger.info("Proxy configuration validated successfully")
        return {"http": proxy, "https": proxy}
    
    elif isinstance(proxy, dict):
        for protocol, proxy_url in proxy.items():
            if protocol not in ['http', 'https']:
                logger.error(f"Proxy validation failed: invalid protocol '{protocol}' in dict.")
                raise ConfigurationError(f"Invalid proxy protocol: {protocol}")
            
            if not isinstance(proxy_url, str) or not proxy_url.strip():
                logger.error(f"Proxy validation failed: empty or invalid URL for protocol '{protocol}'.")
                raise ConfigurationError(f"Invalid proxy URL for {protocol}: must be non-empty string")
        
        logger.info("Proxy dictionary configuration validated successfully")
        return proxy
    
    else:
        logger.error(f"Proxy validation failed: not a string or dict. Value: {proxy!r}")
        raise ConfigurationError("Invalid proxy: must be string or dict")


def validate_usernames(usernames: List[str]) -> List[str]:
    """Validate and deduplicate usernames, preserving order."""
    logger.debug(f"Validating and deduplicating usernames: {usernames!r}")
    
    seen: Set[str] = set()
    unique_usernames: List[str] = []
    
    for u in usernames:
        if isinstance(u, str):
            name = u.strip()
            if name and name not in seen:
                seen.add(name)
                unique_usernames.append(name)
    
    if not unique_usernames:
        logger.error("No valid usernames provided after validation.")
        raise ValidationError("No valid usernames provided")
    
    logger.info(f"Validated {len(unique_usernames)} unique usernames")
    return unique_usernames
