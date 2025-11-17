import asyncio
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
from functools import wraps
from typing import Any, Literal, TypeVar, overload

from naminter.core.constants import (
    ACCOUNT_PLACEHOLDER,
    DEFAULT_UNKNOWN_VALUE,
    EMPTY_STRING,
    MAX_CONCURRENT_TASKS,
    REQUIRED_KEYS_ENUMERATE,
    REQUIRED_KEYS_SELF_ENUM,
    SITE_KEY_CATEGORY,
    SITE_KEY_E_CODE,
    SITE_KEY_E_STRING,
    SITE_KEY_HEADERS,
    SITE_KEY_KNOWN,
    SITE_KEY_M_CODE,
    SITE_KEY_M_STRING,
    SITE_KEY_NAME,
    SITE_KEY_POST_BODY,
    SITE_KEY_STRIP_BAD_CHAR,
    SITE_KEY_URI_CHECK,
    SITE_KEY_URI_PRETTY,
    WMN_KEY_AUTHORS,
    WMN_KEY_LICENSE,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
    HttpTimeoutError,
    WMNDataError,
    WMNSchemaError,
    WMNValidationError,
)
from naminter.core.models import (
    WMNDataset,
    WMNMode,
    WMNResult,
    WMNResponse,
    WMNSummary,
    WMNValidationResult,
)
from naminter.core.network import BaseSession
from naminter.core.utils import (
    get_missing_keys,
    validate_dataset,
)

T = TypeVar("T")


class Naminter:
    """Main class for Naminter username enumeration."""

    def __init__(
        self,
        http_client: BaseSession,
        wmn_data: WMNDataset | None = None,
        wmn_schema: dict[str, Any] | None = None,
        max_tasks: int = MAX_CONCURRENT_TASKS,
    ) -> None:
        """Initialize Naminter with configuration parameters."""
        self._logger = logging.getLogger(__name__)
        self._logger.addHandler(logging.NullHandler())

        self._wmn_data: WMNDataset | None = wmn_data
        self._wmn_schema: dict[str, Any] | None = wmn_schema
        self._semaphore = asyncio.Semaphore(max_tasks)
        self._http: BaseSession = http_client

        self._session_open: bool = False
        self._session_lock = asyncio.Lock()
        self._dataset_ready: bool = False

    async def _open_session(self) -> None:
        """Open the HTTP session."""
        if self._session_open:
            return

        async with self._session_lock:
            if self._session_open:
                return
            try:
                await self._http.open()
                self._session_open = True
                self._logger.info("HTTP session opened")
            except HttpSessionError as e:
                self._logger.error("Failed to open HTTP session: %s", e)
                msg = f"HTTP session initialization failed: {e}"
                raise WMNDataError(msg) from e

    async def _close_session(self) -> None:
        """Close the HTTP session if open."""
        async with self._session_lock:
            if not self._session_open:
                return
            try:
                await self._http.close()
            except asyncio.CancelledError:
                self._logger.debug("HTTP client close cancelled")
                raise
            except Exception as e:
                self._logger.exception(
                    "Unexpected error during HTTP client close: %s", e
                )
            finally:
                self._session_open = False

    async def _ensure_ready(self) -> None:
        """Ensure HTTP session is open and dataset is loaded."""
        if not self._session_open:
            await self._open_session()

        if self._dataset_ready:
            return

        if not self._wmn_data:
            msg = "WMN data must be provided to Naminter constructor"
            raise WMNDataError(msg)

        async with self._session_lock:
            if self._dataset_ready:
                return

            try:
                if self._wmn_schema:
                    errors = validate_dataset(self._wmn_data, self._wmn_schema)
                    if errors:
                        msg = "WMN dataset validation failed"
                        raise WMNValidationError(msg, errors=errors)

                self._dataset_ready = True
                self._logger.info(
                    "Dataset loaded: %d sites",
                    len(self._wmn_data.get(WMN_KEY_SITES, [])),
                )
            except WMNSchemaError as e:
                msg = f"WMN schema error: {e}"
                raise WMNDataError(msg) from e
            except WMNValidationError:
                raise
            except Exception as e:
                msg = f"Unexpected error loading WMN data: {e}"
                raise WMNDataError(msg) from e

    @staticmethod
    def _ensure_initialized(
        method: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Decorator to ensure the instance is ready before calling a method."""

        @wraps(method)
        async def wrapper(self: "Naminter", *args: Any, **kwargs: Any) -> Any:
            await self._ensure_ready()
            return await method(self, *args, **kwargs)

        return wrapper

    async def __aenter__(self) -> "Naminter":
        await self._ensure_ready()
        return self

    async def __aexit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any | None
    ) -> None:
        """Async context manager exit."""
        await self._close_session()

    def _filter_sites(
        self,
        site_names: list[str] | None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Filter sites by names and categories for the current WMN dataset."""
        assert self._wmn_data is not None
        sites: list[dict[str, Any]] = self._wmn_data.get(WMN_KEY_SITES, [])

        if not any((site_names, include_categories, exclude_categories)):
            return sites

        filtered_names: frozenset[str] = frozenset()
        if site_names:
            filtered_names = frozenset(site_names)
            available_names: frozenset[str] = frozenset({
                name for site in sites if (name := site.get(SITE_KEY_NAME)) is not None
            })
            missing_names: frozenset[str] = filtered_names - available_names
            if missing_names:
                msg = f"Unknown site names: {sorted(missing_names)}"
                raise WMNDataError(msg)

        include_set: frozenset[str] = (
            frozenset(include_categories) if include_categories else frozenset()
        )
        exclude_set: frozenset[str] = (
            frozenset(exclude_categories) if exclude_categories else frozenset()
        )

        filtered_sites = [
            site
            for site in sites
            if (not filtered_names or site.get(SITE_KEY_NAME) in filtered_names)
            and (not include_set or site.get(SITE_KEY_CATEGORY) in include_set)
            and (not exclude_set or site.get(SITE_KEY_CATEGORY) not in exclude_set)
        ]

        self._logger.debug(
            "Sites filtered: %d of %d sites remaining",
            len(filtered_sites),
            len(sites),
        )
        return filtered_sites

    @_ensure_initialized
    async def get_wmn_summary(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> WMNSummary:
        """Get enriched WMN metadata information for diagnostics and UI.

        Retrieves comprehensive summary information about the loaded WhatsMyName
        dataset, including site counts, categories, authors, and license information.
        Filters can be applied to compute statistics on a subset of sites.

        Args:
            site_names: Optional list of specific site names to include in the summary.
                If None, all sites are included (subject to category filters).
            include_categories: Optional list of categories to include. Only sites
                in these categories will be counted. If None, all categories are
                included (subject to exclude_categories).
            exclude_categories: Optional list of categories to exclude. Sites in these
                categories will not be counted.

        Returns:
            WMNSummary: Summary object containing license, authors, site names, counts,
                categories, and known usernames count.

        Raises:
            WMNDataError: If site_names contains unknown site names.

        Example:
            ```python
            async with Naminter(wmn_data, wmn_schema) as naminter:
                # Get summary of all sites
                summary = await naminter.get_wmn_summary()
                print(f"Total sites: {summary.sites_count}")

                # Get summary for specific categories
                summary = await naminter.get_wmn_summary(
                    include_categories=["social", "coding"]
                )
                print(f"Social/coding sites: {summary.sites_count}")
            ```
        """
        assert self._wmn_data is not None
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        category_list = [
            site.get(SITE_KEY_CATEGORY) for site in sites if site.get(SITE_KEY_CATEGORY)
        ]
        site_name_list = [
            site.get(SITE_KEY_NAME) for site in sites if site.get(SITE_KEY_NAME)
        ]
        known_count = sum(
            len(site.get(SITE_KEY_KNOWN, []))
            for site in sites
            if isinstance(site.get(SITE_KEY_KNOWN), list)
        )

        wmn_summary = WMNSummary(
            license=tuple(self._wmn_data.get(WMN_KEY_LICENSE, [])),
            authors=tuple(self._wmn_data.get(WMN_KEY_AUTHORS, [])),
            site_names=tuple(str(name) for name in site_name_list),
            sites_count=len(sites),
            categories=tuple(str(cat) for cat in category_list),
            categories_count=len(set(category_list)),
            known_count=known_count,
        )

        self._logger.debug(
            "WMN summary computed (sites=%d, categories=%d)",
            wmn_summary.sites_count,
            wmn_summary.categories_count,
        )
        return wmn_summary

    @_ensure_initialized
    async def enumerate_site(
        self,
        site: dict[str, Any],
        username: str,
        mode: WMNMode = WMNMode.ALL,
    ) -> WMNResult:
        """Enumerate a single site for the given username.

        Performs a single username lookup for a single site definition
        from the loaded WhatsMyName (WMN) dataset. It builds the URL and optional
        POST body using the site's configuration, sends an HTTP request, and then
        evaluates the response using the site's detection rules to determine
        whether the username is present on that site.

        Args:
            site:
                A single site configuration dictionary from the WMN dataset. This dict
                must contain, at minimum, the following keys:
                - "name": site name
                - "cat": site category
                - "uri_check": URL template with "{account}" placeholder
                - "e_code": expected HTTP status for a "found" account
                - "e_string": expected string in body for a "found" account
                - "m_code": expected HTTP status for a "missing" account
                - "m_string": expected string in body for a "missing" account
                Optional keys include:
                - "headers": dict of HTTP headers to send with the request.
                - "post_body": POST body template containing "{account}".
                - "strip_bad_char": characters to strip from the username
                  before substitution in the URL/body.
                - "uri_pretty": an optional "pretty" URL template for reporting.
            username:
                The raw username to test on this site. It is used to build the
                request URL and optional POST body. If the site defines
                "strip_bad_char", those characters are removed from the
                username before substitution.
            mode:
                Detection mode that controls how the "expected" (E) and "missing" (M)
                criteria are interpreted when classifying the HTTP response:
                - WMNMode.ALL: All configured conditions for a state must match
                  (strict AND logic).
                - WMNMode.ANY: Any matching condition is sufficient
                  (looser OR logic).

        Returns:
            WMNResult:
                A single WMNResult instance that encapsulates:
                - name: site name (from "name"),
                - category: site category (from "cat"),
                - username: the username that was tested,
                - url: the final URL used for reporting (may be "uri_pretty"),
                - status: high-level classification, e.g. FOUND, NOT_FOUND,
                  AMBIGUOUS, UNKNOWN, ERROR, or NOT_VALID,
                - response_code / response_text / elapsed (if the HTTP request
                  completed successfully),
                - error message (if an error occurred).

        Raises:
            asyncio.CancelledError:
                Propagated if the caller cancels the task while the HTTP request
                is in progress.
            WMNDataError:
                Not raised directly from this method, but may be raised earlier
                when initializing the Naminter instance or when validating the
                underlying dataset.

        Example:
            ```python
            site = {
                "name": "GitHub",
                "uri_check": "https://github.com/{account}",
                "e_code": 200,
                "e_string": "GitHub Profile",
                "m_code": 404,
                "m_string": "Not Found",
                "cat": "coding",
            }

            async with Naminter(http_client, wmn_data, wmn_schema) as naminter:
                result = await naminter.enumerate_site(site, "torvalds")
                print(result.name, result.username, result.status, result.url)
            ```
        """
        missing_keys = get_missing_keys(site, REQUIRED_KEYS_ENUMERATE)
        if missing_keys:
            site_name = site.get(SITE_KEY_NAME, DEFAULT_UNKNOWN_VALUE)
            self._logger.warning(
                "Site '%s' is missing required keys: %s",
                site_name,
                missing_keys,
            )
            return WMNResult.from_error(
                name=site_name,
                category=site.get(SITE_KEY_CATEGORY, DEFAULT_UNKNOWN_VALUE),
                username=username,
                message=f"Site entry missing required keys: {missing_keys}",
            )

        name = site[SITE_KEY_NAME]
        category = site[SITE_KEY_CATEGORY]
        strip_bad_char = site.get(SITE_KEY_STRIP_BAD_CHAR, EMPTY_STRING)
        if strip_bad_char:
            clean_username = username.translate(
                str.maketrans(dict.fromkeys(strip_bad_char))
            )
        else:
            clean_username = username

        uri_check_template = site[SITE_KEY_URI_CHECK]
        uri_check = uri_check_template.replace(ACCOUNT_PLACEHOLDER, clean_username)
        uri_pretty = site.get(SITE_KEY_URI_PRETTY, uri_check_template).replace(
            ACCOUNT_PLACEHOLDER, clean_username
        )

        headers = site.get(SITE_KEY_HEADERS, {})
        post_body = site.get(SITE_KEY_POST_BODY)
        if post_body:
            post_body = post_body.replace(ACCOUNT_PLACEHOLDER, clean_username)
            self._logger.debug("Checking %s with POST request", uri_check)
        else:
            self._logger.debug("Checking %s with GET request", uri_check)

        result: WMNResult | None = None
        response: WMNResponse | None = None
        try:
            async with self._semaphore:
                if post_body:
                    response = await self._http.post(
                        uri_check, headers=headers, data=post_body
                    )
                else:
                    response = await self._http.get(uri_check, headers=headers)

                self._logger.debug(
                    "Response from %s: status=%d, elapsed=%.2fs",
                    name,
                    response.status_code,
                    response.elapsed,
                )
        except asyncio.CancelledError:
            self._logger.debug("Request cancelled")
            raise
        except HttpTimeoutError as e:
            self._logger.warning("Request to '%s' timed out: %s", name, e)
            result = WMNResult.from_error(
                name=name,
                category=category,
                username=username,
                url=uri_pretty,
                message=f"Request timeout: {e}",
            )
        except HttpSessionError as e:
            self._logger.warning("Session error for '%s': %s", name, e)
            result = WMNResult.from_error(
                name=name,
                category=category,
                username=username,
                url=uri_pretty,
                message=f"Session error: {e}",
            )
        except HttpError as e:
            self._logger.warning("Network error for '%s': %s", name, e)
            result = WMNResult.from_error(
                name=name,
                category=category,
                username=username,
                url=uri_pretty,
                message=f"Network error: {e}",
            )
        except Exception as e:
            self._logger.exception("Unexpected error during request for '%s'", name)
            result = WMNResult.from_error(
                name=name,
                category=category,
                username=username,
                url=uri_pretty,
                message=f"Unexpected error: {e}",
            )

        if result is not None:
            return result

        result = WMNResult.from_response(
            name=name,
            category=category,
            username=username,
            url=uri_pretty,
            response_code=response.status_code,
            response_text=response.text,
            elapsed=response.elapsed,
            mode=mode,
            e_code=site[SITE_KEY_E_CODE],
            e_string=site[SITE_KEY_E_STRING],
            m_code=site[SITE_KEY_M_CODE],
            m_string=site[SITE_KEY_M_STRING],
        )

        self._logger.debug(
            "Check result for '%s': %s (HTTP %d)",
            name,
            result.status.name,
            response.status_code,
        )

        return result

    @staticmethod
    async def _execute_tasks(
        coroutines: list[Awaitable[T]],
        as_generator: bool,
    ) -> list[T] | AsyncGenerator[T, None]:
        """Execute tasks and return results as list or generator."""
        if as_generator:

            async def _generator() -> AsyncGenerator[T, None]:
                tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]
                try:
                    for task in asyncio.as_completed(tasks):
                        yield await task
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)

            return _generator()
        return list(await asyncio.gather(*coroutines))

    @overload
    async def enumerate_usernames(
        self,
        usernames: list[str],
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: Literal[True] = ...,
    ) -> AsyncGenerator[WMNResult, None]: ...

    @overload
    async def enumerate_usernames(
        self,
        usernames: list[str],
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: Literal[False] = ...,
    ) -> list[WMNResult]: ...

    @_ensure_initialized
    async def enumerate_usernames(
        self,
        usernames: list[str],
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: bool = False,
    ) -> list[WMNResult] | AsyncGenerator[WMNResult, None]:
        """Enumerate one or multiple usernames across one or multiple sites.

        This is the high-level method for running bulk username checks. It takes:
        - one list of usernames, and
        - a selection of sites (by name and/or category filters),
        then runs enumerate_site for every (site, username) pair.

        The method can operate in two modes:
        - "batch" mode (as_generator=False): returns a list of all WMNResult objects
          once all checks are complete.
        - "streaming" mode (as_generator=True): returns an async generator that yields
          WMNResult objects one by one as they finish, without waiting for all tasks.

        Args:
            usernames:
                A non-empty list of usernames to enumerate across sites.
                Each username is tested independently on every selected site.
            site_names:
                Optional list of site names to restrict enumeration to a subset of
                sites. If None, all sites from the WMN dataset are considered
                (subject to category filters). If provided, every name must correspond
                to a known site; otherwise a WMNDataError is raised.
            include_categories:
                Optional list of site categories (values of the "cat" field) to
                include. When provided, only sites whose category is in this list
                are considered. This filter is applied in addition to site_names.
            exclude_categories:
                Optional list of site categories (values of the "cat" field) to
                exclude. When provided, any site whose category is in this list is
                skipped. This filter is also applied in addition to site_names and
                include_categories.
            mode:
                Detection mode forwarded to enumerate_site for each check:
                - WMNMode.ALL: strict evaluation (all "found" indicators must match).
                - WMNMode.ANY: relaxed evaluation (any "found" indicator can match).
            as_generator:
                Controls the shape of the returned value:
                - If False (default), all checks are scheduled, awaited, and a full
                  list[WMNResult] is returned when everything is done.
                - If True, an AsyncGenerator[WMNResult, None] is returned instead.
                  The caller can then `async for` over individual WMNResult objects
                  as they become available.

        Returns:
            Union[list[WMNResult], AsyncGenerator[WMNResult, None]]:
                - If as_generator is False:
                    A flat list of WMNResult objects, one per (site, username) pair.
                    The list order is not guaranteed to match submission order.
                - If as_generator is True:
                    An async generator that yields WMNResult objects one at a time
                    as tasks complete. This allows streaming processing of results.

        Raises:
            WMNDataError:
                If any requested site name in site_names does not exist in the
                loaded WMN dataset. This validation is performed during site filtering
                before any network requests are made.
            WMNDataError / WMNValidationError:
                May be raised earlier when preparing the dataset (via _ensure_ready),
                before enumeration starts.
        """
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        self._logger.info(
            "Starting enumeration for %d username(s) on %d site(s)",
            len(usernames),
            len(sites),
        )

        coroutines = [
            self.enumerate_site(site, username, mode)
            for site in sites
            for username in usernames
        ]

        return await self._execute_tasks(coroutines, as_generator)

    @overload
    async def validate_sites(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: Literal[True] = ...,
    ) -> AsyncGenerator[WMNValidationResult, None]: ...

    @overload
    async def validate_sites(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: Literal[False] = ...,
    ) -> list[WMNValidationResult]: ...

    @_ensure_initialized
    async def validate_sites(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        as_generator: bool = False,
    ) -> list[WMNValidationResult] | AsyncGenerator[WMNValidationResult, None]:
        """Validate site detection rules using known usernames from the dataset.

        This method is intended for maintainers and for automated health checks of
        the WMN dataset. Instead of testing arbitrary usernames, it:
        - Selects a subset of sites (optionally filtered by site_names and
          categories).
        - For each selected site, reads its list of "known good" usernames
          from the "known" field.
        - For each (site, known_username) pair, calls enumerate_site.
        - Aggregates all WMNResult objects into a single WMNValidationResult per site.

        This allows you to confirm that:
        - The configured detection rules ("e_code", "e_string", "m_code", "m_string")
          still correctly identify accounts, and
        - The site entries themselves are structurally valid and complete.

        Args:
            site_names:
                Optional list of site names to validate. If None, all sites from the
                dataset are considered (subject to category filters). If provided,
                all names must exist in the dataset; unknown names lead to a
                WMNDataError raised during site filtering.
            include_categories:
                Optional list of categories (values of the "cat" field) to include
                during validation. Only sites whose category is in this list are
                validated. This is combined with site_names if both are provided.
            exclude_categories:
                Optional list of categories (values of the "cat" field) to exclude
                from validation. Any site whose category is in this list is skipped.
                This exclusion is applied after site_names and include_categories.
            mode:
                Detection mode passed down to enumerate_site for each known username:
                - WMNMode.ALL: strict evaluation (recommended for validation).
                - WMNMode.ANY: relaxed evaluation (useful for exploratory checks).
            as_generator:
                Controls the return type:
                - If False (default), returns a list[WMNValidationResult] after all
                  sites have been validated.
                - If True, returns an AsyncGenerator[WMNValidationResult, None] that
                  yields one WMNValidationResult per site as soon as that site's
                  validation has finished.

        Returns:
            Union[list[WMNValidationResult], AsyncGenerator[WMNValidationResult, None]]:
                - If as_generator is False:
                    A list where each item is a WMNValidationResult describing one
                    site and the WMNResult objects for all of its known usernames.
                - If as_generator is True:
                    An async generator that yields WMNValidationResult objects for
                    each validated site in completion order.

            Each WMNValidationResult includes:
                - name: site name,
                - category: site category (the value of the "cat" field),
                - results: list[WMNResult] for each known username (may be empty),
                - status: aggregate status derived from underlying WMNResult values
                  (e.g. ERROR if any check failed),
                - error: textual description if validation could not be performed
                  for that site (e.g. missing required keys or unexpected error).

        Raises:
            WMNDataError:
                If any of the requested site_names does not exist in the dataset.
            WMNDataError / WMNValidationError:
                May be raised earlier from _ensure_ready if the dataset or schema
                is invalid.

        Site-level error handling:
            - If a site is missing required keys needed for self-validation
              (as defined by REQUIRED_KEYS_SELF_ENUM in code), a WMNValidationResult
              is returned with `error` populated and `results` left empty.
            - If an unexpected exception occurs when validating a site, it is caught
              and converted into a WMNValidationResult with `error` set accordingly.
        """
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        self._logger.info(
            "Starting validation for %d site(s) (mode=%s)",
            len(sites),
            mode,
        )

        async def _enumerate_known(site: dict[str, Any]) -> WMNValidationResult:
            """Helper function to validate a site with all its known users."""
            site_name = site.get(SITE_KEY_NAME, DEFAULT_UNKNOWN_VALUE)
            site_category = site.get(SITE_KEY_CATEGORY, DEFAULT_UNKNOWN_VALUE)

            missing_keys = get_missing_keys(site, REQUIRED_KEYS_SELF_ENUM)
            if missing_keys:
                self._logger.warning(
                    "Site '%s' is missing required keys for validation: %s",
                    site_name,
                    missing_keys,
                )
                return WMNValidationResult(
                    name=site_name,
                    category=site_category,
                    error=f"Site data missing required keys: {missing_keys}",
                )

            known = site[SITE_KEY_KNOWN]
            self._logger.debug(
                "Validating '%s' with %d known user(s)",
                site_name,
                len(known),
            )

            try:
                results = await asyncio.gather(
                    *(self.enumerate_site(site, username, mode) for username in known)
                )
                return WMNValidationResult(
                    name=site_name, category=site_category, results=results
                )
            except Exception as e:
                self._logger.exception("Validation failed for site='%s'", site_name)
                return WMNValidationResult(
                    name=site_name,
                    category=site_category,
                    error=f"Unexpected error during site validation: {e}",
                )

        coroutines = [_enumerate_known(site) for site in sites]
        return await self._execute_tasks(coroutines, as_generator)
