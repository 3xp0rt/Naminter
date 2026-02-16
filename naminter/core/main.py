"""Main Naminter class for asynchronous username enumeration and site testing."""

import asyncio
from collections.abc import AsyncGenerator, Awaitable
import logging
from typing import Any, cast

from naminter.core.constants import (
    ACCOUNT_PLACEHOLDER,
    EMPTY_STRING,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    MAX_CONCURRENT_TASKS,
    SITE_KEY_CATEGORY,
    SITE_KEY_HEADERS,
    SITE_KEY_KNOWN,
    SITE_KEY_NAME,
    SITE_KEY_POST_BODY,
    SITE_KEY_STRIP_BAD_CHAR,
    SITE_KEY_URI_CHECK,
    SITE_KEY_URI_PRETTY,
    SITE_KEY_VALID,
    WMN_KEY_AUTHORS,
    WMN_KEY_LICENSE,
    WMN_KEY_SITES,
    HttpMethod,
)
from naminter.core.exceptions import (
    HttpError,
    HttpSessionError,
    WMNArgumentError,
    WMNDataError,
    WMNEnumerationError,
    WMNSchemaError,
    WMNUninitializedError,
    WMNUnknownCategoriesError,
    WMNUnknownSiteError,
    WMNValidationError,
)
from naminter.core.models import (
    WMNDataset,
    WMNError,
    WMNMode,
    WMNResponse,
    WMNResult,
    WMNSite,
    WMNSummary,
    WMNTestResult,
)
from naminter.core.network import BaseSession
from naminter.core.utils import execute_tasks
from naminter.core.validator import WMNValidator


class Naminter:
    """Main class for Naminter username enumeration."""

    def __init__(
        self,
        http_client: BaseSession,
        wmn_data: dict[str, Any] | None = None,
        wmn_schema: dict[str, Any] | None = None,
        max_tasks: int = MAX_CONCURRENT_TASKS,
    ) -> None:
        """Initialize Naminter with configuration parameters.

        Args:
            http_client: Async HTTP session implementing the BaseSession protocol.
            wmn_data: Parsed WhatsMyName dataset dictionary.
            wmn_schema: Optional JSON Schema dictionary for dataset validation.
            max_tasks: Maximum number of concurrent enumeration tasks.

        Raises:
            WMNSchemaError: If the JSON schema is invalid.
        """
        self._logger = logging.getLogger(__name__)
        if not self._logger.handlers:
            self._logger.addHandler(logging.NullHandler())

        self._wmn_data: dict[str, Any] | None = wmn_data
        self._wmn_schema: dict[str, Any] | None = wmn_schema
        self._semaphore = asyncio.Semaphore(max_tasks)
        self._http: BaseSession = http_client

        self._validator: WMNValidator | None = None
        if self._wmn_schema:
            try:
                self._validator = WMNValidator(self._wmn_schema)
            except WMNSchemaError:
                self._logger.exception("WMN schema error during initialization")
                raise

    async def open(self) -> None:
        """Initialize the HTTP session and validate the WMN dataset.

        Use this method for long-running services where you need explicit
        lifecycle control. For scripts and CLI usage, prefer the context
        manager pattern: `async with Naminter(...) as naminter:`.

        Raises:
            HttpSessionError: If HTTP session initialization fails.
            WMNUninitializedError: If WMN data is not provided.
            WMNDataError: If WMN data loading fails.
            WMNValidationError: If dataset validation fails.

        Example:
            ```python
            # Long-running service (FastAPI, etc.)
            naminter = Naminter(http_client, wmn_data)
            await naminter.open()  # Call once at startup

            # ... handle many requests ...

            await naminter.close()  # Call once at shutdown
            ```
        """
        try:
            await self._http.open()
            self._logger.info("HTTP session opened")
        except HttpSessionError:
            self._logger.exception("Failed to open HTTP session")
            raise

        try:
            self._validate_dataset()
        except Exception:
            await self.close()
            raise

    def _validate_dataset(self) -> None:
        """Validate WMN data and schema after HTTP session is opened.

        Raises:
            WMNUninitializedError: If WMN data is not provided.
            WMNDataError: If WMN data loading fails.
            WMNValidationError: If dataset validation fails.
        """
        if not self._wmn_data:
            msg = "WMN data must be provided to Naminter constructor"
            raise WMNUninitializedError(msg)

        schema_errors: list[WMNError] = []
        dataset_errors: list[WMNError] = []

        data = cast("WMNDataset", self._wmn_data)
        try:
            if self._validator:
                schema_errors = self._validator.validate_schema(data)
            dataset_errors = WMNValidator.validate_dataset(data)
        except (TypeError, ValueError, KeyError, AttributeError) as e:
            self._logger.exception("Unexpected error loading WMN data")
            msg = f"Unexpected error loading WMN data: {e}"
            raise WMNDataError(msg) from e

        if schema_errors or dataset_errors:
            msg = "WMN dataset validation failed"
            raise WMNValidationError(
                msg,
                schema_errors=schema_errors,
                dataset_errors=dataset_errors,
            )

        sites = self._wmn_data.get(WMN_KEY_SITES, [])
        self._logger.info("Dataset loaded: %d sites", len(sites))

    async def close(self) -> None:
        """Close the HTTP session and release resources.

        Use this method for long-running services to clean up at shutdown.
        For scripts and CLI usage, prefer the context manager pattern.

        Handles errors gracefully during cleanup.

        Raises:
            asyncio.CancelledError: Propagated to allow proper cancellation
                handling.
        """
        try:
            await self._http.close()
        except asyncio.CancelledError:
            self._logger.debug("HTTP client close cancelled")
            raise
        except (HttpSessionError, OSError, RuntimeError):
            self._logger.exception(
                "Unexpected error during HTTP client close",
            )

    async def __aenter__(self) -> "Naminter":
        """Async context manager entry."""
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit."""
        await self.close()

    def _filter_sites(
        self,
        site_names: list[str] | None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> list[WMNSite]:
        """Filter sites by names and categories for the current WMN dataset.

        Args:
            site_names: Optional list of site names to filter by.
            include_categories: Optional list of categories to include.
            exclude_categories: Optional list of categories to exclude.

        Returns:
            list[WMNSite]: Filtered list of site configurations.

        Raises:
            WMNUninitializedError: If WMN data is not initialized.
            WMNUnknownSiteError: If unknown site names are provided.
            WMNUnknownCategoriesError: If unknown categories are provided.
        """
        if self._wmn_data is None:
            msg = "WMN data not initialized"
            raise WMNUninitializedError(msg)

        sites: list[WMNSite] = self._wmn_data.get(WMN_KEY_SITES, [])

        if not (site_names or include_categories or exclude_categories):
            return sites

        filtered_names: frozenset[str] | None = None
        if site_names:
            filtered_names = frozenset(site_names)
            available_names: frozenset[str] = frozenset(
                site[SITE_KEY_NAME] for site in sites
            )
            if missing_names := filtered_names - available_names:
                msg = f"Unknown site names: {sorted(missing_names)}"
                raise WMNUnknownSiteError(msg, site_names=sorted(missing_names))

        include_set: frozenset[str] = (
            frozenset(include_categories) if include_categories else frozenset()
        )
        exclude_set: frozenset[str] = (
            frozenset(exclude_categories) if exclude_categories else frozenset()
        )

        if include_set and include_set.issubset(exclude_set):
            self._logger.debug(
                "All included categories are excluded, returning empty list",
            )
            return []

        if include_set or exclude_set:
            available_categories: frozenset[str] = frozenset(
                site[SITE_KEY_CATEGORY] for site in sites
            )
            requested_categories: frozenset[str] = include_set | exclude_set
            if unknown_categories := requested_categories - available_categories:
                msg = f"Unknown categories: {sorted(unknown_categories)}"
                raise WMNUnknownCategoriesError(
                    msg,
                    categories=sorted(unknown_categories),
                )

        filtered_sites: list[WMNSite] = [
            site
            for site in sites
            if (filtered_names is None or site.get(SITE_KEY_NAME) in filtered_names)
            and (not include_set or site.get(SITE_KEY_CATEGORY) in include_set)
            and (not exclude_set or site.get(SITE_KEY_CATEGORY) not in exclude_set)
        ]

        self._logger.debug(
            "Sites filtered: %d of %d sites remaining",
            len(filtered_sites),
            len(sites),
        )
        return filtered_sites

    def _prepare_request(
        self,
        site: WMNSite,
        username: str,
    ) -> tuple[str, str, dict[str, str], str | None]:
        """Prepare all request data for site enumeration.

        Args:
            site: Site configuration.
            username: Username to substitute.

        Returns:
            tuple[str, str, dict[str, str], str | None]: The uri_check URL,
                uri_pretty URL, headers dict, and optional post_body.

        Raises:
            WMNEnumerationError: If strip_bad_char configuration is invalid.
        """
        clean_username = self._prepare_username(username, site)

        uri_check_template: str = site[SITE_KEY_URI_CHECK]
        uri_check = uri_check_template.replace(ACCOUNT_PLACEHOLDER, clean_username)

        uri_pretty_template_raw = site.get(SITE_KEY_URI_PRETTY)
        uri_pretty_template: str = (
            uri_pretty_template_raw
            if uri_pretty_template_raw is not None
            else uri_check_template
        )
        uri_pretty = uri_pretty_template.replace(ACCOUNT_PLACEHOLDER, clean_username)

        headers: dict[str, Any] = site.get(SITE_KEY_HEADERS) or {}

        post_body_template = site.get(SITE_KEY_POST_BODY)
        post_body = (
            post_body_template.replace(ACCOUNT_PLACEHOLDER, clean_username)
            if post_body_template
            else None
        )

        return uri_check, uri_pretty, headers, post_body

    def _prepare_username(
        self,
        username: str,
        site: WMNSite,
    ) -> str:
        """Prepare username by stripping bad characters.

        Args:
            username: Raw username to process.
            site: Site configuration containing strip_bad_char.

        Returns:
            str: Username with bad characters removed.

        Raises:
            WMNEnumerationError: If strip_bad_char configuration is invalid.
        """
        strip_bad_char = site.get(SITE_KEY_STRIP_BAD_CHAR, EMPTY_STRING)
        if not strip_bad_char:
            return username

        try:
            return username.translate(
                str.maketrans(dict.fromkeys(strip_bad_char)),
            )
        except (ValueError, TypeError) as e:
            self._logger.warning(
                "Invalid strip_bad_char for site: %s - %s",
                site,
                e,
            )
            msg = f"Invalid strip_bad_char configuration: {e}"
            raise WMNEnumerationError(msg) from e

    async def _perform_request(
        self,
        uri_check: str,
        headers: dict[str, str],
        post_body: str | None,
        site: WMNSite,
    ) -> WMNResponse:
        """Perform HTTP request for site enumeration.

        Args:
            uri_check: URL to check.
            headers: HTTP headers to send.
            post_body: Optional POST body data.
            site: Site configuration for logging.

        Returns:
            WMNResponse: HTTP response with status, text, and elapsed time.

        Raises:
            asyncio.CancelledError: If the request is cancelled.
            HttpError: If an HTTP error occurs.
        """
        async with self._semaphore:
            method: HttpMethod = HTTP_METHOD_POST if post_body else HTTP_METHOD_GET
            response = await self._http.request(
                method=method,
                url=uri_check,
                headers=headers,
                data=post_body,
            )

            self._logger.debug(
                "%s %s -> %d (%.2fs) | headers=%s | data=%s | site=%s",
                method,
                uri_check,
                response.status_code,
                response.elapsed,
                headers,
                post_body,
                site,
            )
            return response

    def summary(
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
            WMNUninitializedError: If WMN data is not initialized.
            WMNUnknownSiteError: If site_names contains unknown site names.
            WMNUnknownCategoriesError: If include_categories or exclude_categories
                contains unknown categories.

        Example:
            ```python
            async with Naminter(http_client, wmn_data, wmn_schema) as naminter:
                # Get summary of all sites
                summary = naminter.summary()
                print(f"Total sites: {summary.sites_count}")

                # Get summary for specific categories
                summary = naminter.summary(
                    include_categories=["social", "coding"],
                )
                print(f"Social/coding sites: {summary.sites_count}")
            ```
        """
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        category_list: list[str] = [site[SITE_KEY_CATEGORY] for site in sites]
        site_name_list: list[str] = [site[SITE_KEY_NAME] for site in sites]
        known_count: int = sum(len(site[SITE_KEY_KNOWN]) for site in sites)

        license_list: list[str] = (
            list(self._wmn_data[WMN_KEY_LICENSE]) if self._wmn_data else []
        )
        authors_list: list[str] = (
            list(self._wmn_data[WMN_KEY_AUTHORS]) if self._wmn_data else []
        )

        summary = WMNSummary(
            license=tuple(license_list),
            authors=tuple(authors_list),
            site_names=tuple(site_name_list),
            sites_count=len(sites),
            categories=tuple(category_list),
            categories_count=len(set(category_list)),
            known_count=known_count,
        )

        self._logger.debug(
            "WMN summary computed (sites=%d, categories=%d)",
            summary.sites_count,
            summary.categories_count,
        )
        return summary

    async def enumerate_site(
        self,
        site: WMNSite,
        username: str,
        mode: WMNMode = WMNMode.ALL,
        *,
        exclude_text: bool = False,
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
                must contain, at minimum, the following keys: "name" (site name),
                "cat" (site category), "uri_check" (URL template with "{account}"
                placeholder), "e_code" (expected HTTP status for an existing account),
                "e_string" (expected string in body for an existing account),
                "m_code" (expected HTTP status for a missing account), and
                "m_string" (expected string in body for a missing account).
                Optional keys include "headers" (dict of HTTP headers to send with
                the request), "post_body" (POST body template containing "{account}"),
                "strip_bad_char" (characters to strip from the username before
                substitution in the URL/body), "uri_pretty" (an optional "pretty"
                URL template for reporting), and "valid" (boolean flag; sites with
                valid=False are skipped and return NOT_VALID status).
            username:
                The raw username to test on this site. It is used to build the
                request URL and optional POST body. If the site defines
                "strip_bad_char", those characters are removed from the
                username before substitution.
            mode:
                Detection mode that controls how the "expected" (E) and "missing" (M)
                criteria are interpreted when classifying the HTTP response.
                WMNMode.ALL requires all configured conditions for a state to match
                (strict AND logic), while WMNMode.ANY allows any matching condition
                to be sufficient (looser OR logic).
            exclude_text:
                When True, omit response text from the returned result.

        Returns:
            WMNResult:
                A single WMNResult instance that encapsulates the site name (from
                "name"), category (from "cat"), the username that was tested, the
                uri_check and uri_pretty URLs, a high-level
                status classification (e.g. EXISTS, PARTIAL_EXISTS, PARTIAL_MISSING,
                CONFLICTING, MISSING, UNKNOWN, ERROR, or NOT_VALID),
                status_code, text, and elapsed time
                (if the HTTP request completed successfully), and an error message
                (if an error occurred).

        Raises:
            asyncio.CancelledError:
                Propagated if the caller cancels the task while the HTTP request
                is in progress.
            HttpSessionError:
                Propagated if the HTTP session is not initialized or was closed.

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
                print(result.name, result.username, result.status, result.uri_pretty)
            ```
        """
        if site.get(SITE_KEY_VALID) is False:
            self._logger.debug("Skipping invalid site: %s", site)
            return WMNResult.from_not_valid(username=username, site=site)

        try:
            uri_check, uri_pretty, headers, post_body = self._prepare_request(
                site,
                username,
            )
        except WMNEnumerationError as e:
            return WMNResult.from_error(
                username=username,
                message=str(e),
                site=site,
            )

        try:
            response = await self._perform_request(uri_check, headers, post_body, site)
        except asyncio.CancelledError:
            self._logger.debug("Request cancelled for site: %s", site)
            raise
        except HttpSessionError:
            raise
        except HttpError as e:
            error_type = type(e).__name__
            self._logger.warning(
                "%s for site: %s - %s",
                error_type,
                site,
                e,
            )
            return WMNResult.from_error(
                username=username,
                message=f"{error_type}: {e}",
                site=site,
                uri_check=uri_check,
                uri_pretty=uri_pretty,
            )
        except (OSError, RuntimeError, ValueError, TypeError) as e:
            self._logger.exception(
                "Unexpected error during enumeration for site: %s",
                site,
            )
            return WMNResult.from_error(
                username=username,
                message=f"Unexpected error: {e}",
                site=site,
                uri_check=uri_check,
                uri_pretty=uri_pretty,
            )

        result = WMNResult.from_response(
            username=username,
            uri_check=uri_check,
            uri_pretty=uri_pretty,
            response=response,
            site=site,
            mode=mode,
            exclude_text=exclude_text,
        )

        self._logger.debug(
            "Check result for site: %s (HTTP %d) - %s",
            result.status.name,
            response.status_code,
            site,
        )

        return result

    async def enumerate_usernames(
        self,
        usernames: list[str],
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        *,
        exclude_text: bool = False,
    ) -> AsyncGenerator[WMNResult, None]:
        """Enumerate one or multiple usernames across one or multiple sites.

        This is the high-level method for running bulk username checks. It takes one
        list of usernames and a selection of sites (by name and/or category filters),
        then runs enumerate_site for every (site, username) pair.

        The method returns an async generator that yields WMNResult objects one by one
        as they finish, without waiting for all tasks to complete.

        Args:
            usernames:
                A non-empty list of usernames to enumerate across sites.
                Each username is tested independently on every selected site.
            site_names:
                Optional list of site names to restrict enumeration to a subset of
                sites. If None, all sites from the WMN dataset are considered
                (subject to category filters). If provided, every name must correspond
                to a known site; otherwise a WMNUnknownSiteError is raised.
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
                Detection mode forwarded to enumerate_site for each check.
                WMNMode.ALL uses strict evaluation where all "exists" indicators must
                match, while WMNMode.ANY uses relaxed evaluation where any "exists"
                indicator can match.
            exclude_text:
                When True, omit response text from each yielded result.

        Yields:
            WMNResult: Result objects one at a time as tasks complete. This
                allows streaming processing of results. The order is not
                guaranteed to match submission order.

        Raises:
            WMNArgumentError: If usernames list is empty.
            WMNUninitializedError: If WMN data is not initialized.
            WMNUnknownSiteError: If any requested site name in site_names does not
                exist in the loaded WMN dataset.
            WMNUnknownCategoriesError: If include_categories or exclude_categories
                contains unknown categories.
        """
        if not usernames:
            msg = "At least one username must be provided"
            raise WMNArgumentError(msg)

        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        if not sites:
            self._logger.info("No sites match the given filters, nothing to enumerate")
            return

        self._logger.info(
            "Starting enumeration for %d username(s) on %d site(s)",
            len(usernames),
            len(sites),
        )

        coroutines: list[Awaitable[WMNResult]] = [
            self.enumerate_site(
                site,
                username,
                mode,
                exclude_text=exclude_text,
            )
            for site in sites
            for username in usernames
        ]

        try:
            async for result in execute_tasks(coroutines):
                yield result
        except asyncio.CancelledError:
            self._logger.debug("Enumeration cancelled")
            raise

    async def test_enumeration(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        mode: WMNMode = WMNMode.ALL,
        *,
        exclude_text: bool = False,
    ) -> AsyncGenerator[WMNTestResult, None]:
        """Test site detection rules using known usernames from the dataset.

        This method is intended for maintainers and automated health checks of
        the WMN dataset. It selects sites (optionally filtered by names and
        categories), tests each site using its "known" usernames, and yields
        a WMNTestResult per site.

        Args:
            site_names:
                Optional list of site names to test. If None, all sites are
                tested (subject to category filters).
            include_categories:
                Optional list of categories to include. Only sites in these
                categories are tested.
            exclude_categories:
                Optional list of categories to exclude from testing.
            mode:
                Detection mode for each test. WMNMode.ALL uses strict evaluation,
                WMNMode.ANY uses relaxed evaluation.
            exclude_text:
                When True, omit response text from results within each test.

        Yields:
            WMNTestResult: Result for each site in completion order, containing
                the site name, category, list of WMNResult objects, aggregate
                status, and error message if testing failed.

        Raises:
            WMNUninitializedError: If WMN data is not initialized.
            WMNUnknownSiteError: If site_names contains unknown sites.
            WMNUnknownCategoriesError: If categories are unknown.
        """
        sites = self._filter_sites(
            site_names,
            include_categories=include_categories,
            exclude_categories=exclude_categories,
        )

        if not sites:
            self._logger.info("No sites match the given filters, nothing to test")
            return

        self._logger.info(
            "Starting test for %d site(s) (mode=%s)",
            len(sites),
            mode,
        )

        async def test_site(site: WMNSite) -> WMNTestResult:
            """Test a single site using its known usernames."""
            known: list[str] = site[SITE_KEY_KNOWN]
            self._logger.debug(
                "Testing site with %d known user(s): %s",
                len(known),
                site,
            )

            coroutines: list[Awaitable[WMNResult]] = [
                self.enumerate_site(
                    site,
                    username,
                    mode,
                    exclude_text=exclude_text,
                )
                for username in known
            ]
            try:
                results: list[WMNResult] = [
                    result async for result in execute_tasks(coroutines)
                ]
            except asyncio.CancelledError:
                self._logger.debug("Test cancelled for site: %s", site)
                raise
            return WMNTestResult.from_site(site, results=results)

        coroutines: list[Awaitable[WMNTestResult]] = [test_site(site) for site in sites]

        try:
            async for result in execute_tasks(coroutines):
                yield result
        except asyncio.CancelledError:
            self._logger.debug("Test enumeration cancelled")
            raise
