import asyncio
import jsonschema
import logging
import time
from typing import Any, AsyncGenerator, Coroutine, Dict, List, Optional, Union

import jsonschema
from curl_cffi.requests import AsyncSession, RequestsError

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints
from ..core.models import ResultStatus, SiteResult, SelfCheckResult
from ..core.exceptions import (
    ConfigurationError,
    NetworkError,
    DataError,
    SessionError,
    SchemaValidationError,
    ValidationError,
    ConcurrencyError,
)
from ..core.utils import (
    validate_wmn_data,
    validate_numeric_values,
    configure_proxy,
    validate_usernames,
    filter_sites,
)
from ..core.constants import (
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HTTP_SSL_VERIFY,
    HTTP_ALLOW_REDIRECTS,
    BROWSER_IMPERSONATE_AGENT,
    MAX_CONCURRENT_TASKS,
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
    ACCOUNT_PLACEHOLDER,
)

class Naminter:
    """Main class for Naminter username enumeration."""

    def __init__(
        self,
        wmn_data: Dict[str, Any],
        wmn_schema: Optional[Dict[str, Any]] = None,
        max_tasks: int = MAX_CONCURRENT_TASKS,
        timeout: int = HTTP_REQUEST_TIMEOUT_SECONDS,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
        verify_ssl: bool = HTTP_SSL_VERIFY,
        allow_redirects: bool = HTTP_ALLOW_REDIRECTS,
        impersonate: Optional[BrowserTypeLiteral] = BROWSER_IMPERSONATE_AGENT,
        ja3: Optional[str] = None,
        akamai: Optional[str] = None,
        extra_fp: Optional[Union[ExtraFingerprints, Dict[str, Any]]] = None,
    ) -> None:
        """Initialize Naminter with configuration parameters."""
        self._logger = logging.getLogger(__name__)
        self._logger.addHandler(logging.NullHandler())

        self._logger.info(
            "Initializing Naminter with configuration: max_tasks=%d, timeout=%ds, browser=%s, ssl_verify=%s, allow_redirects=%s, proxy=%s, ja3=%s, akamai=%s", 
            max_tasks, timeout, impersonate, verify_ssl, allow_redirects, bool(proxy), ja3, akamai
        )

        self.max_tasks = max_tasks if max_tasks is not None else MAX_CONCURRENT_TASKS
        self.timeout = timeout if timeout is not None else HTTP_REQUEST_TIMEOUT_SECONDS
        self.impersonate = impersonate if impersonate is not None else BROWSER_IMPERSONATE_AGENT
        self.verify_ssl = verify_ssl if verify_ssl is not None else HTTP_SSL_VERIFY
        self.allow_redirects = allow_redirects if allow_redirects is not None else HTTP_ALLOW_REDIRECTS
        self.proxy = configure_proxy(proxy)
        self.ja3 = ja3
        self.akamai = akamai
        self.extra_fp = extra_fp
        
        validate_numeric_values(self.max_tasks, self.timeout)
        validate_wmn_data(wmn_data, wmn_schema)

        self._wmn_data = wmn_data
        self._wmn_schema = wmn_schema
        self._semaphore = asyncio.Semaphore(self.max_tasks)
        self._session: Optional[AsyncSession] = None
        
        sites_count = len(self._wmn_data.get("sites", [])) if self._wmn_data else 0
        self._logger.info(
            "Naminter initialized successfully: loaded %d sites, max_tasks=%d, timeout=%ds, browser=%s, ssl_verify=%s, proxy=%s, ja3=%s, akamai=%s",
            sites_count, self.max_tasks, self.timeout,
            self.impersonate, self.verify_ssl, bool(self.proxy), self.ja3, self.akamai
        )

    async def __aenter__(self) -> "Naminter":
        # Convert ExtraFingerprints to dict if needed
        extra_fp_value = self.extra_fp.to_dict() if isinstance(self.extra_fp, ExtraFingerprints) else self.extra_fp
        
        self._session = AsyncSession(
            proxies=self.proxy,
            verify=self.verify_ssl,
            timeout=self.timeout,
            allow_redirects=self.allow_redirects,
            impersonate=self.impersonate,
            ja3=self.ja3,
            akamai=self.akamai,
            extra_fp=extra_fp_value,
        )
        return self
    
    async def __aexit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """Async context manager exit."""
        if self._session:
            try:
                await self._session.close()
                self._logger.info("HTTP session closed successfully.")
            except Exception as e:
                self._logger.warning("Error closing session during cleanup: %s", e, exc_info=True)
            finally:
                self._session = None

    async def get_wmn_info(self) -> Dict[str, Any]:
        """Get WMN metadata information."""
        try:
            info = {
                "license": self._wmn_data.get("license", []),
                "authors": self._wmn_data.get("authors", []),
                "categories": list(set(site.get("cat", "") for site in self._wmn_data.get("sites", []))),
                "sites_count": len(self._wmn_data.get("sites", []))
            }
            self._logger.info("Retrieved WMN metadata: %d sites across %d categories", 
                             info["sites_count"], len(info["categories"]))
            return info
        except Exception as e:
            self._logger.error("Error retrieving WMN metadata: %s", e, exc_info=True)
            return {"error": f"Failed to retrieve metadata: {e}"}

    def list_sites(self) -> List[str]:
        """List all site names."""
        sites = [site.get("name", "") for site in self._wmn_data.get("sites", [])]
        self._logger.info("Retrieved %d site names from WMN data", len(sites))
        return sites
    
    def list_categories(self) -> List[str]:
        """List all unique categories."""
        category_list = sorted({site.get("cat") for site in self._wmn_data.get("sites", []) if site.get("cat")})
        self._logger.info("Retrieved %d unique categories from WMN data", len(category_list))
        return category_list
    
    async def check_site(
        self,
        site: Dict[str, Any],
        username: str,
        fuzzy_mode: bool = False,
    ) -> SiteResult:
        """Check a single site for the given username."""
        site_name = site.get("name")
        category = site.get("cat")
        uri_check_template = site.get("uri_check")
        post_body_template = site.get("post_body")
        e_code, e_string = site.get("e_code"), site.get("e_string")
        m_code, m_string = site.get("m_code"), site.get("m_string")
        
        if not site_name:
            self._logger.error("Site configuration missing required 'name' field: %r", site)
            return SiteResult(
                site_name="",
                category=category,
                username=username,
                result_status=ResultStatus.ERROR,
                error="Site missing required field: name",
            )
        
        if not category:
            self._logger.error("Site '%s' missing required 'cat' field", site_name)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_status=ResultStatus.ERROR,
                error="Site missing required field: cat",
            )
    
        if not uri_check_template:
            self._logger.error("Site '%s' missing required 'uri_check' field", site_name)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_status=ResultStatus.ERROR,
                error="Site missing required field: uri_check",
            )
            
        has_placeholder = ACCOUNT_PLACEHOLDER in uri_check_template or (post_body_template and ACCOUNT_PLACEHOLDER in post_body_template)
        if not has_placeholder:
            return SiteResult(site_name, category, username, ResultStatus.ERROR, error=f"Site '{site_name}' missing {ACCOUNT_PLACEHOLDER} placeholder")

        matchers = {
            'e_code':  e_code,
            'e_string': e_string,
            'm_code':  m_code,
            'm_string': m_string,
        }

        if fuzzy_mode:
            if all(val is None for val in matchers.values()):
                self._logger.error(
                    "Site '%s' must define at least one matcher (e_code, e_string, m_code, or m_string) for fuzzy mode",
                    site_name
                )
                return SiteResult(
                    site_name=site_name,
                    category=category,
                    username=username,
                    result_status=ResultStatus.ERROR,
                    error="Site must define at least one matcher for fuzzy mode",
                )
        else:
            missing = [name for name, val in matchers.items() if val is None]
            if missing:
                self._logger.error(
                    "Site '%s' missing required matchers for strict mode: %s",
                    site_name, missing
                )
                return SiteResult(
                    site_name=site_name,
                    category=category,
                    username=username,
                    result_status=ResultStatus.ERROR,
                    error=f"Site missing required matchers: {missing}",
                )
        
        clean_username = username.translate(str.maketrans("", "", site.get("strip_bad_char", "")))
        if not clean_username:
            return SiteResult(site_name, category, username, ResultStatus.ERROR, error=f"Username '{username}' became empty after character stripping")

        uri_check = uri_check_template.replace(ACCOUNT_PLACEHOLDER, clean_username)
        uri_pretty = site.get("uri_pretty", uri_check_template).replace(ACCOUNT_PLACEHOLDER, clean_username)

        self._logger.info("Checking site '%s' (category: %s) for username '%s' in %s mode", 
                         site_name, category, username, "fuzzy" if fuzzy_mode else "strict")

        try:
            async with self._semaphore:
                start_time = time.monotonic()
                headers = site.get("headers", {})
                post_body = site.get("post_body")

                if post_body:
                    post_body = post_body.replace(ACCOUNT_PLACEHOLDER, clean_username)
                    self._logger.debug("Making POST request to %s with body: %.100s", uri_check, post_body)
                    response = await self._session.post(uri_check, headers=headers, data=post_body)
                else:
                    self._logger.debug("Making GET request to %s", uri_check)
                    response = await self._session.get(uri_check, headers=headers)

                elapsed = time.monotonic() - start_time
                self._logger.info("Request to '%s' completed in %.2fs with status %d", site_name, elapsed, response.status_code)
        except asyncio.CancelledError:
            self._logger.warning("Request to '%s' was cancelled", site_name)
            raise
        except RequestsError as e:
            self._logger.warning("Network error while checking '%s': %s", site_name, e, exc_info=True)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_url=uri_pretty,
                result_status=ResultStatus.ERROR,
                error=f"Network error: {e}",
            )
        except Exception as e:
            self._logger.error("Unexpected error while checking '%s': %s", site_name, e, exc_info=True)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_url=uri_pretty,
                result_status=ResultStatus.ERROR,
                error=f"Unexpected error: {e}",
            )

        response_text = response.text
        response_code = response.status_code

        result_status = SiteResult.get_result_status(
            response_code=response_code,
            response_text=response_text,
            e_code=e_code,
            e_string=e_string,
            m_code=m_code,
            m_string=m_string,
            fuzzy_mode=fuzzy_mode,
        )

        self._logger.debug(
            "Site '%s' result: %s (HTTP %d) in %.2fs (%s mode)",
            site_name,
            result_status.name,
            response_code,
            elapsed,
            "fuzzy" if fuzzy_mode else "strict",
        )

        return SiteResult(
            site_name=site_name,
            category=category,
            username=username,
            result_url=uri_pretty,
            result_status=result_status,
            response_code=response_code,
            elapsed=elapsed,
            response_text=response_text,
        )

    async def check_usernames(
        self,
        usernames: List[str],
        site_names: Optional[List[str]] = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> Union[List[SiteResult], AsyncGenerator[SiteResult, None]]:
        """Check one or multiple usernames across all loaded sites."""
        usernames = validate_usernames(usernames)
        self._logger.info("Starting username enumeration for %d username(s): %s", len(usernames), usernames)
        
        sites = await filter_sites(site_names, self._wmn_data.get("sites", []))
        self._logger.info("Will check against %d sites in %s mode", len(sites), "fuzzy" if fuzzy_mode else "strict")

        tasks: List[Coroutine[Any, Any, SiteResult]] = [
            self.check_site(site, username, fuzzy_mode)
            for site in sites for username in usernames
        ]

        async def generate_results() -> AsyncGenerator[SiteResult, None]:
            for task in asyncio.as_completed(tasks):
                yield await task

        if as_generator:
            return generate_results()
        
        results = await asyncio.gather(*tasks)
        return results

    async def self_check(
        self,
        site_names: Optional[List[str]] = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> Union[List[SelfCheckResult], AsyncGenerator[SelfCheckResult, None]]:
        """Run self-checks using known accounts for each site."""
        sites = await filter_sites(site_names, self._wmn_data.get("sites", []))

        self._logger.info("Starting self-check validation for %d sites in %s mode", len(sites), "fuzzy" if fuzzy_mode else "strict")

        async def _check_known(site: Dict[str, Any]) -> SelfCheckResult:
            """Helper function to check a site with all its known users."""
            site_name = site.get("name")
            category = site.get("cat")
            known = site.get("known")

            if not site_name:
                self._logger.error("Site configuration missing required 'name' field for self-check: %r", site)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site missing required field: name"
                )

            if not category:
                self._logger.error("Site '%s' missing required 'cat' field for self-check", site_name)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site '{site_name}' missing required field: cat"
                )
            
            if known is None:
                self._logger.error("Site '%s' missing required 'known' field for self-check", site_name)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site '{site_name}' missing required field: known"
                )
            
            self._logger.info("Self-checking site '%s' (category: %s) with %d known accounts", site_name, category, len(known))

            try:
                tasks = [self.check_site(site, username, fuzzy_mode) for username in known]
                site_results = await asyncio.gather(*tasks)

                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=site_results
                )
            except Exception as e:
                self._logger.error("Unexpected error during self-check for site '%s': %s", site_name, e, exc_info=True)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Unexpected error during self-check: {e}"
                )
        
        tasks: List[Coroutine[Any, Any, SelfCheckResult]] = [
            _check_known(site) for site in sites if isinstance(site, dict)
        ]

        async def generate_results() -> AsyncGenerator[SelfCheckResult, None]:
            for task in asyncio.as_completed(tasks):
                yield await task

        if as_generator:
            return generate_results()
        
        results = await asyncio.gather(*tasks)
        return results