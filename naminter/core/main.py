import asyncio
import logging
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Union, Set

from curl_cffi.requests import AsyncSession, RequestsError

from curl_cffi import BrowserTypeLiteral, ExtraFingerprints
from ..core.models import ResultStatus, SiteResult, SelfEnumerationResult, ValidationMode
from ..core.exceptions import (
    DataError,
    ValidationError,
)
from ..core.utils import (
    validate_wmn_data,
    validate_numeric_values,
    configure_proxy,
    validate_usernames,
)
from ..core.constants import (
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HTTP_SSL_VERIFY,
    HTTP_ALLOW_REDIRECTS,
    BROWSER_IMPERSONATE_AGENT,
    MAX_CONCURRENT_TASKS,
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
        impersonate: BrowserTypeLiteral = BROWSER_IMPERSONATE_AGENT,
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

        self.max_tasks = max_tasks
        self.timeout = timeout
        self.impersonate = impersonate
        self.verify_ssl = verify_ssl
        self.allow_redirects = allow_redirects
        self.proxy = configure_proxy(proxy)
        self.ja3 = ja3
        self.akamai = akamai
        self.extra_fp = extra_fp.to_dict() if isinstance(extra_fp, ExtraFingerprints) else extra_fp
        
        validate_numeric_values(self.max_tasks, self.timeout)
        validate_wmn_data(wmn_data, wmn_schema)

        self._wmn_data = wmn_data
        self._wmn_schema = wmn_schema
        self._semaphore = asyncio.Semaphore(self.max_tasks)
        self._session_lock = asyncio.Lock()
        self._session: Optional[AsyncSession] = None
        
        self._logger.info(
            "Naminter initialized successfully: max_tasks=%d, timeout=%ds, browser=%s, ssl_verify=%s, proxy=%s, ja3=%s, akamai=%s",
            self.max_tasks, self.timeout,
            self.impersonate, self.verify_ssl, bool(self.proxy), self.ja3, self.akamai
        )

    def _create_async_session(self) -> AsyncSession:
        """Create and configure the underlying HTTP session."""
        return AsyncSession(
            proxies=self.proxy,
            verify=self.verify_ssl,
            timeout=self.timeout,
            allow_redirects=self.allow_redirects,
            impersonate=self.impersonate,
            ja3=self.ja3,
            akamai=self.akamai,
            extra_fp=self.extra_fp,
        )

    async def _open_session(self) -> None:
        """Open the HTTP session for manual (non-context) usage."""
        if self._session is None:
            self._session = self._create_async_session()
            self._logger.info("HTTP session opened successfully.")

    async def _ensure_session(self) -> None:
        """Ensure the HTTP session is initialized (safe for concurrent calls)."""
        if self._session is not None:
            return
            
        async with self._session_lock:
            if self._session is None:
                self._session = self._create_async_session()
                self._logger.info("HTTP session opened successfully.")

    async def _close_session(self) -> None:
        """Close the HTTP session if it is open."""
        if self._session:
            try:
                await self._session.close()
                self._logger.info("HTTP session closed successfully.")
            except Exception as e:
                self._logger.warning("Error closing session during cleanup: %s", e, exc_info=True)
            finally:
                self._session = None

    async def __aenter__(self) -> "Naminter":
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """Async context manager exit."""
        await self._close_session()

    async def get_wmn_summary(
        self,
        site_names: Optional[List[str]] = None,
        include_categories: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Get enriched WMN metadata information for diagnostics and UI.

        Filters can be applied to compute statistics on a subset of sites.
        """
        try:
            sites: List[Dict[str, Any]] = self._filter_sites(
                site_names,
                include_categories=include_categories,
                exclude_categories=exclude_categories,
            )

            category_list: List[str] = [site.get("cat") for site in sites if site.get("cat")]
            site_name_list: List[str] = [site.get("name") for site in sites if site.get("name")]
            
            total_known_accounts: int = 0
            
            for site in sites:
                known_list = site.get("known")
                if isinstance(known_list, list) and len(known_list) > 0:
                    total_known_accounts += len(known_list)

            info: Dict[str, Any] = {
                "license": list(dict.fromkeys(self._wmn_data.get("license", []))),
                "authors": list(dict.fromkeys(self._wmn_data.get("authors", []))),
                "site_names": list(dict.fromkeys(site_name_list)),
                "sites_count": len(sites),
                "categories": list(dict.fromkeys(category_list)),
                "categories_count": len(set(category_list)),
                "known_accounts_total": total_known_accounts,
            }

            self._logger.info(
                "WMN info: %d sites, %d categories (filters - names: %s, include: %s, exclude: %s)",
                info["sites_count"],
                info["categories_count"],
                bool(site_names),
                bool(include_categories),
                bool(exclude_categories),
            )
            return info
        except Exception as e:
            self._logger.error("Error retrieving WMN metadata: %s", e, exc_info=True)
            return {"error": f"Failed to retrieve metadata: {e}"}

    
    def _filter_sites(
        self,
        site_names: Optional[List[str]],
        include_categories: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Filter sites by names and categories for the current WMN dataset."""
        sites: List[Dict[str, Any]] = self._wmn_data.get("sites", [])

        if site_names:
            requested_site_names: Set[str] = set(site_names)
            available_names: Set[str] = {site.get("name") for site in sites}
            missing_names = requested_site_names - available_names
            if missing_names:
                raise DataError(f"Unknown site names: {missing_names}")
        else:
            requested_site_names = set()

        filtered_sites: List[Dict[str, Any]] = sites

        if requested_site_names:
            filtered_sites = [
                site for site in filtered_sites if site.get("name") in requested_site_names
            ]

        if include_categories:
            include_set: Set[str] = set(include_categories)
            filtered_sites = [
                site for site in filtered_sites if site.get("cat") in include_set
            ]

        if exclude_categories:
            exclude_set: Set[str] = set(exclude_categories)
            filtered_sites = [
                site for site in filtered_sites if site.get("cat") not in exclude_set
            ]

        self._logger.info(
            "Filtered to %d sites from %d total (names: %s, include: %s, exclude: %s)",
            len(filtered_sites),
            len(sites),
            bool(site_names),
            bool(include_categories),
            bool(exclude_categories),
        )
        return filtered_sites
    
    async def enumerate_site(
        self,
        site: Dict[str, Any],
        username: str,
        fuzzy_mode: bool = False,
    ) -> SiteResult:
        """Enumerate a single site for the given username."""
        await self._ensure_session()

        name = site.get("name")
        category = site.get("cat")
        uri_check_template = site.get("uri_check")
        post_body_template = site.get("post_body")
        e_code, e_string = site.get("e_code"), site.get("e_string")
        m_code, m_string = site.get("m_code"), site.get("m_string")
        
        if not name:
            self._logger.error("Site configuration missing required 'name' field: %r", site)
            return SiteResult(
                name="",
                category=category,
                username=username,
                status=ResultStatus.ERROR,
                error="Site missing required field: name",
            )
        
        if not category:
            self._logger.error("Site '%s' missing required 'cat' field", name)
            return SiteResult(
                name=name,
                category="",
                username=username,
                status=ResultStatus.ERROR,
                error="Site missing required field: cat",
            )
    
        if not uri_check_template:
            self._logger.error("Site '%s' missing required 'uri_check' field", name)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                status=ResultStatus.ERROR,
                error="Site missing required field: uri_check",
            )
            
        has_placeholder = ACCOUNT_PLACEHOLDER in uri_check_template or (post_body_template and ACCOUNT_PLACEHOLDER in post_body_template)
        if not has_placeholder:
            return SiteResult(name, category, username, ResultStatus.ERROR, error=f"Site '{name}' missing {ACCOUNT_PLACEHOLDER} placeholder")

        matchers = {
            'e_code':  e_code,
            'e_string': e_string,
            'm_code':  m_code,
            'm_string': m_string,
        }

        if fuzzy_mode:
            if all(val is None for val in matchers.values()):
                self._logger.error(
                    "Site '%s' must define at least one matcher (e_code, e_string, m_code, or m_string) for %s mode",
                    name,
                    ValidationMode.FUZZY,
                )
                return SiteResult(
                    name=name,
                    category=category,
                    username=username,
                    status=ResultStatus.ERROR,
                    error=f"Site must define at least one matcher for {ValidationMode.FUZZY} mode",
                )
        else:
            missing = [name for name, val in matchers.items() if val is None]
            if missing:
                self._logger.error(
                    "Site '%s' missing required matchers for %s mode: %s",
                    name, ValidationMode.STRICT, missing
                )
                return SiteResult(
                    name=name,
                    category=category,
                    username=username,
                    status=ResultStatus.ERROR,
                    error=f"Site missing required matchers for {ValidationMode.STRICT} mode: {missing}",
                )

        strip_bad_char = site.get("strip_bad_char", "")
        clean_username = username.translate(str.maketrans("", "", strip_bad_char))
        if not clean_username:
            return SiteResult(name, category, username, ResultStatus.ERROR, error=f"Username '{username}' became empty after character stripping")

        uri_check = uri_check_template.replace(ACCOUNT_PLACEHOLDER, clean_username)
        uri_pretty = site.get("uri_pretty", uri_check_template).replace(ACCOUNT_PLACEHOLDER, clean_username)

        self._logger.info("Enumerating site '%s' (category: %s) for username '%s' in %s mode", 
                         name, category, username, ValidationMode.FUZZY if fuzzy_mode else ValidationMode.STRICT)

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
                self._logger.info("Request to '%s' completed in %.2fs with status %d", name, elapsed, response.status_code)
        except asyncio.CancelledError:
            self._logger.warning("Request to '%s' was cancelled", name)
            raise
        except RequestsError as e:
            self._logger.warning("Network error while enumerating '%s': %s", name, e, exc_info=True)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
                error=f"Network error: {e}",
            )
        except Exception as e:
            self._logger.error("Unexpected error while enumerating '%s': %s", name, e, exc_info=True)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
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
            name,
            result_status.name,
            response_code,
            elapsed,
            ValidationMode.FUZZY if fuzzy_mode else ValidationMode.STRICT,
        )

        return SiteResult(
            name=name,
            category=category,
            username=username,
            result_url=uri_pretty,
            status=result_status,
            response_code=response_code,
            elapsed=elapsed,
            response_text=response_text,
        )

    async def enumerate_usernames(
        self,
        usernames: List[str],
        site_names: Optional[List[str]] = None,
        include_categories: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> Union[List[SiteResult], AsyncGenerator[SiteResult, None]]:
        """Enumerate one or multiple usernames across all loaded sites."""
        await self._ensure_session()

        usernames = validate_usernames(usernames)
        self._logger.info("Starting username enumeration for %d username(s): %s", len(usernames), usernames)
        
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )
        self._logger.info("Will enumerate against %d sites in %s mode", len(sites), ValidationMode.FUZZY if fuzzy_mode else ValidationMode.STRICT)

        coroutines = [
            self.enumerate_site(site, username, fuzzy_mode)
            for site in sites for username in usernames
        ]

        async def iterate_results() -> AsyncGenerator[SiteResult, None]:
            for completed_task in asyncio.as_completed(coroutines):
                yield await completed_task

        if as_generator:
            return iterate_results()
        
        results = await asyncio.gather(*coroutines)
        return results

    async def self_enumeration(
        self,
        site_names: Optional[List[str]] = None,
        include_categories: Optional[List[str]] = None,
        exclude_categories: Optional[List[str]] = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False
    ) -> Union[List[SelfEnumerationResult], AsyncGenerator[SelfEnumerationResult, None]]:
        """Run self-enumeration using known accounts for each site."""
        await self._ensure_session()

        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        self._logger.info("Starting self-enumeration validation for %d sites in %s mode", len(sites), ValidationMode.FUZZY if fuzzy_mode else ValidationMode.STRICT)

        async def _enumerate_known(site: Dict[str, Any]) -> SelfEnumerationResult:
            """Helper function to enumerate a site with all its known users."""
            name = site.get("name")
            category = site.get("cat")
            known = site.get("known")

            if not name:
                self._logger.error("Site configuration missing required 'name' field for self-enumeration: %r", site)
                return SelfEnumerationResult(
                    name="",
                    category=category or "",
                    results=[],
                    error=f"Site missing required field: name"
                )

            if not category:
                self._logger.error("Site '%s' missing required 'cat' field for self-enumeration", name)
                return SelfEnumerationResult(
                    name=name,
                    category="",
                    results=[],
                    error=f"Site missing required field: cat"
                )
            
            if known is None:
                self._logger.error("Site '%s' missing required 'known' field for self-enumeration", name)
                return SelfEnumerationResult(
                    name=name,
                    category=category,
                    results=[],
                    error=f"Site '{name}' missing required field: known"
                )
            
            self._logger.info("Self-enumerating site '%s' (category: %s) with %d known accounts", name, category, len(known))

            try:
                coroutines = [self.enumerate_site(site, username, fuzzy_mode) for username in known]
                results = await asyncio.gather(*coroutines)

                return SelfEnumerationResult(
                    name=name,
                    category=category,
                    results=results
                )
            except Exception as e:
                self._logger.error("Unexpected error during self-enumeration for site '%s': %s", name, e, exc_info=True)
                return SelfEnumerationResult(
                    name=name,
                    category=category,
                    results=[],
                    error=f"Unexpected error during self-enumeration: {e}"
                )
        
        coroutines = [
            _enumerate_known(site) for site in sites if isinstance(site, dict)
        ]

        async def iterate_results() -> AsyncGenerator[SelfEnumerationResult, None]:
            for completed_task in asyncio.as_completed(coroutines):
                yield await completed_task

        if as_generator:
            return iterate_results()
        
        results = await asyncio.gather(*coroutines)
        return results