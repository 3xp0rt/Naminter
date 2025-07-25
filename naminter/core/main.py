import asyncio
import jsonschema
import logging
import time
from typing import Any, AsyncGenerator, Coroutine, Dict, List, Optional, Union

import jsonschema
from curl_cffi.requests import AsyncSession, RequestsError

from ..core.models import BrowserImpersonation, ResultStatus, SiteResult, SelfCheckResult
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
    validate_schema,
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
        impersonate: Optional[BrowserImpersonation] = BROWSER_IMPERSONATE_AGENT,
        verify_ssl: bool = HTTP_SSL_VERIFY,
        allow_redirects: bool = HTTP_ALLOW_REDIRECTS,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
    ) -> None:
        """Initialize Naminter with configuration parameters."""
        self._logger = logging.getLogger(__name__)
        self._logger.addHandler(logging.NullHandler())

        self._logger.info(
            "Naminter initializing: max_tasks=%d, timeout=%ds, browser=%s, ssl_verify=%s, allow_redirects=%s, proxy=%s", 
            max_tasks, timeout, impersonate, verify_ssl, allow_redirects, bool(proxy)
        )

        self.max_tasks = max_tasks if max_tasks is not None else MAX_CONCURRENT_TASKS
        self.timeout = timeout if timeout is not None else HTTP_REQUEST_TIMEOUT_SECONDS
        self.impersonate = impersonate if impersonate is not None else BROWSER_IMPERSONATE_AGENT
        self.verify_ssl = verify_ssl if verify_ssl is not None else HTTP_SSL_VERIFY
        self.allow_redirects = allow_redirects if allow_redirects is not None else HTTP_ALLOW_REDIRECTS
        self.proxy = configure_proxy(proxy)
        
        validate_numeric_values(self.max_tasks, self.timeout)
        validate_schema(wmn_data, wmn_schema)

        self._wmn_data = wmn_data
        self._wmn_schema = wmn_schema
        self._semaphore = asyncio.Semaphore(self.max_tasks)
        self._session: Optional[AsyncSession] = None
        
        sites_count = len(self._wmn_data.get("sites", [])) if self._wmn_data else 0
        self._logger.info(
            "Naminter ready. Sites: %d, Max tasks: %d, Timeout: %ds, Browser: %s, SSL verify: %s, Proxy: %s",
            sites_count, self.max_tasks, self.timeout,
            self.impersonate, self.verify_ssl, bool(self.proxy)
        )

    async def __aenter__(self) -> "Naminter":
        self._session = AsyncSession(
            impersonate=self.impersonate,
            verify=self.verify_ssl,
            timeout=self.timeout,
            allow_redirects=self.allow_redirects,
            proxies=self.proxy,
        )
        return self
    
    async def __aexit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """Async context manager exit."""
        self._logger.debug("Exiting async context manager for Naminter.")
        if self._session:
            try:
                await self._session.close()
                self._logger.info("Session closed successfully during context exit.")
            except Exception as e:
                self._logger.warning("Error closing session during cleanup: %s", e, exc_info=True)
            finally:
                self._session = None
        else:
            self._logger.debug("No session to close on context exit.")

    async def _create_session(self) -> AsyncSession:
        """Create and configure an asynchronous HTTP session."""
        try:
            self._logger.debug("Creating AsyncSession (impersonate=%s, verify_ssl=%s, timeout=%d, allow_redirects=%s, proxies=%s)", 
                              self.impersonate, self.verify_ssl, self.timeout, self.allow_redirects, self.proxy)
            session = AsyncSession(
                impersonate=self.impersonate,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                proxies=self.proxy,
            )
            self._logger.info("AsyncSession created successfully.")
            return session
        except Exception as e:
            self._logger.critical("Failed to create session: %s", e, exc_info=True)
            raise SessionError(f"Failed to create session: {e}") from e

    async def get_wmn_info(self) -> Dict[str, Any]:
        """Get WMN metadata information."""
        self._logger.debug("Retrieving WMN metadata information.")
        try:
            info = {
                "license": self._wmn_data.get("license", []),
                "authors": self._wmn_data.get("authors", []),
                "categories": list(set(site.get("cat", "") for site in self._wmn_data.get("sites", []))),
                "sites_count": len(self._wmn_data.get("sites", []))
            }
            self._logger.info("WMN metadata retrieved: %d sites, %d categories.", 
                             info["sites_count"], len(info["categories"]))
            return info
        except Exception as e:
            self._logger.error("Error retrieving WMN metadata: %s", e, exc_info=True)
            return {"error": f"Failed to retrieve metadata: {e}"}

    def list_sites(self) -> List[str]:
        """List all site names."""
        self._logger.debug("Listing all site names.")        
        sites = [site.get("name", "") for site in self._wmn_data.get("sites", [])]
        self._logger.info("Found %d sites.", len(sites))
        return sites
    
    def list_categories(self) -> List[str]:
        """List all unique categories."""
        self._logger.debug("Listing all unique categories.")        
        category_list = sorted({site.get("cat") for site in self._wmn_data.get("sites", []) if site.get("cat")})
        self._logger.info("Found %d unique categories.", len(category_list))
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
            self._logger.error("Site missing required field: name. Site: %r", site)
            return SiteResult(
                site_name="",
                category=category,
                username=username,
                result_status=ResultStatus.ERROR,
                error="Site missing required field: name",
            )
        
        if not category:
            self._logger.error("Site '%s' missing required field: cat", site_name)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_status=ResultStatus.ERROR,
                error="Site missing required field: cat",
            )
    
        if not uri_check_template:
            self._logger.error("Site '%s' missing required field: uri_check", site_name)
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
                    "Site '%s' must define at least one of e_code, e_string, m_code, or m_string in fuzzy mode",
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
                    "Site '%s' missing required matchers in strict mode: %s",
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

        self._logger.info("Checking site '%s' for username '%s' (fuzzy_mode=%s)", site_name, username, fuzzy_mode)

        try:
            async with self._semaphore:
                start_time = time.monotonic()
                headers = site.get("headers", {})
                post_body = site.get("post_body")

                if post_body:
                    post_body = post_body.replace(ACCOUNT_PLACEHOLDER, clean_username)
                    self._logger.debug("POST %s, body: %.100s, headers: %r", uri_check, post_body, headers)
                    response = await self._session.post(uri_check, headers=headers, data=post_body)
                else:
                    self._logger.debug("GET %s, headers: %r", uri_check, headers)
                    response = await self._session.get(uri_check, headers=headers)

                elapsed = time.monotonic() - start_time
                self._logger.info("Request to '%s' completed in %.2fs (status %d)", site_name, elapsed, response.status_code)
        except asyncio.CancelledError:
            self._logger.warning("Request to '%s' was cancelled.", site_name)
            raise
        except RequestsError as e:
            self._logger.warning("Network error checking '%s': %s", site_name, e, exc_info=True)
            return SiteResult(
                site_name=site_name,
                category=category,
                username=username,
                result_url=uri_pretty,
                result_status=ResultStatus.ERROR,
                error=f"Network error: {e}",
            )
        except Exception as e:
            self._logger.error("Unexpected error checking '%s': %s", site_name, e, exc_info=True)
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
            "[%s] Result: %s, Code: %s, Time: %.2fs, Mode: %s",
            site_name,
            result_status.name,
            response_code,
            elapsed,
            "fuzzy" if fuzzy_mode else "full",
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
        self._logger.info("Checking %d username(s): %s", len(usernames), usernames)
        
        sites = await filter_sites(site_names, self._wmn_data.get("sites", []))
        self._logger.info("Checking against %d sites in %s mode.", len(sites), "fuzzy" if fuzzy_mode else "full")

        tasks: List[Coroutine[Any, Any, SiteResult]] = [
            self.check_site(site, username, fuzzy_mode)
            for site in sites for username in usernames
        ]
        self._logger.debug("Created %d check tasks.", len(tasks))

        async def generate_results() -> AsyncGenerator[SiteResult, None]:
            for task in asyncio.as_completed(tasks):
                yield await task

        if as_generator:
            self._logger.info("Returning username check results as async generator.")
            return generate_results()
        
        results = await asyncio.gather(*tasks)
        self._logger.info("Username check complete. Generated %d results.", len(results))
        return results

    async def self_check(
        self,
        site_names: Optional[List[str]] = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> Union[List[SelfCheckResult], AsyncGenerator[SelfCheckResult, None]]:
        """Run self-checks using known accounts for each site."""
        sites = await filter_sites(site_names, self._wmn_data.get("sites", []))

        self._logger.info("Starting self-check for %d sites (fuzzy_mode=%s)", len(sites), fuzzy_mode)

        async def _check_known(site: Dict[str, Any]) -> SelfCheckResult:
            """Helper function to check a site with all its known users."""
            site_name = site.get("name")
            category = site.get("cat")
            known = site.get("known")

            if not site_name:
                self._logger.error("Site missing required field: name. Site: %r", site)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site missing required field: name"
                )

            if not category:
                self._logger.error("Site '%s' missing required field: cat", site_name)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site '{site_name}' missing required field: cat"
                )
            
            if known is None:
                self._logger.error("Site '%s' missing required field: known.", site_name)
                return SelfCheckResult(
                    site_name=site_name,
                    category=category,
                    results=[],
                    error=f"Site '{site_name}' missing required field: known"
                )
            
            self._logger.info("Self-checking site '%s' (category: %s) with %d known accounts.", site_name, category, len(known))

            try:
                tasks = [self.check_site(site, username, fuzzy_mode) for username in known]
                self._logger.debug("Created %d self-check tasks for site '%s'", len(tasks), site_name)
                site_results = await asyncio.gather(*tasks)

                self._logger.info("Self-check completed for site '%s': %d test results.", site_name, len(site_results))
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
        self._logger.debug("Created %d self-check tasks for all sites.", len(tasks))

        async def generate_results() -> AsyncGenerator[SelfCheckResult, None]:
            for task in asyncio.as_completed(tasks):
                yield await task

        if as_generator:
            self._logger.info("Returning self-check results as async generator.")
            return generate_results()
        
        results = await asyncio.gather(*tasks)
        self._logger.info("Self-check complete. Results generated for %d sites.", len(results))
        return results