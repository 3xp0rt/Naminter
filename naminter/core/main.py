import asyncio
import json
import logging
from collections.abc import AsyncGenerator, Sequence
from pathlib import Path
from typing import (
    Any,
)

import aiofiles
import jsonschema

from ..core.constants import (
    ACCOUNT_PLACEHOLDER,
    MAX_CONCURRENT_TASKS,
    REQUIRED_KEYS_ENUMERATE,
    REQUIRED_KEYS_SELF_ENUM,
    WMN_KEY_AUTHORS,
    WMN_KEY_CATEGORIES,
    WMN_KEY_LICENSE,
    WMN_KEY_NAME,
    WMN_KEY_SITES,
    WMN_REMOTE_URL,
)
from ..core.exceptions import (
    DataError,
    FileAccessError,
    NetworkError,
    SchemaError,
    SessionError,
    TimeoutError,
    ValidationError,
)
from ..core.models import (
    ResultStatus,
    SelfEnumerationResult,
    SiteResult,
    Summary,
    ValidationMode,
)
from ..core.network import BaseSession
from ..core.utils import (
    deduplicate_strings,
    merge_lists,
    validate_usernames,
)


class Naminter:
    """Main class for Naminter username enumeration."""

    def __init__(
        self,
        http_client: BaseSession,
        wmn_data: dict[str, Any] | None = None,
        wmn_schema: dict[str, Any] | None = None,
        local_list_paths: list[Path] | None = None,
        remote_list_urls: list[str] | None = None,
        skip_validation: bool = False,
        local_schema_path: Path | None = None,
        remote_schema_url: str | None = None,
        max_tasks: int = MAX_CONCURRENT_TASKS,
    ) -> None:
        """Initialize Naminter with configuration parameters."""
        self._logger = logging.getLogger(__name__)
        self._logger.addHandler(logging.NullHandler())

        self._logger.debug("Initializing Naminter (max_tasks=%d)", max_tasks)

        self.max_tasks = max_tasks

        self._local_list_paths = local_list_paths
        self._remote_list_urls = remote_list_urls
        self._skip_validation = skip_validation
        self._local_schema_path = local_schema_path
        self._remote_schema_url = remote_schema_url

        self._wmn_data: dict[str, Any] | None = wmn_data
        self._wmn_schema: dict[str, Any] | None = wmn_schema
        self._semaphore = asyncio.Semaphore(self.max_tasks)
        self._session_lock = asyncio.Lock()
        self._http: BaseSession = http_client

    async def _open_session(self) -> None:
        """Open the HTTP session (idempotent, safe under concurrency)."""
        async with self._session_lock:
            try:
                await self._http.open()
                self._logger.info("HTTP client opened")
            except SessionError as e:
                self._logger.error("Failed to open HTTP session: %s", e)
                raise DataError(f"HTTP session initialization failed: {e}") from e

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        """Fetch and parse JSON from a URL."""
        if not url.strip():
            raise ValidationError(f"Invalid URL: {url}")

        try:
            response = await self._http.get(url)
        except TimeoutError as e:
            raise DataError(f"Timeout while fetching from {url}: {e}") from e
        except SessionError as e:
            raise DataError(f"Session error while fetching from {url}: {e}") from e
        except NetworkError as e:
            raise DataError(f"Network error while fetching from {url}: {e}") from e

        if response.status_code < 200 or response.status_code >= 300:
            raise DataError(f"Failed to fetch from {url}: HTTP {response.status_code}")

        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as e:
            raise DataError(f"Failed to parse JSON from {url}: {e}") from e

    async def _read_json_file(self, path: str | Path) -> dict[str, Any]:
        """Read JSON from a local file without blocking the event loop."""
        try:
            async with aiofiles.open(path, encoding="utf-8") as file:
                content = await file.read()
        except FileNotFoundError as e:
            raise FileAccessError(f"File not found: {path}") from e
        except PermissionError as e:
            raise FileAccessError(f"Permission denied accessing file: {path}") from e
        except OSError as e:
            raise FileAccessError(f"Error reading file {path}: {e}") from e

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise DataError(f"Invalid JSON in file {path}: {e}") from e

    async def _load_schema(self) -> dict[str, Any]:
        """Load WMN schema from local or remote source."""
        if self._skip_validation:
            return {}

        try:
            if self._local_schema_path:
                return await self._read_json_file(self._local_schema_path)
            elif self._remote_schema_url:
                return await self._fetch_json(self._remote_schema_url)
            else:
                raise DataError(
                    "No schema source provided - either local_schema_path or remote_schema_url is required"
                )
        except (OSError, json.JSONDecodeError) as e:
            raise DataError(
                f"Failed to load required WMN schema from local file: {e}"
            ) from e
        except NetworkError as e:
            raise DataError(
                f"Failed to load required WMN schema from {self._remote_schema_url}: {e}"
            ) from e

    async def _load_dataset(self) -> dict[str, Any]:
        """Load WMN data from configured sources."""
        dataset: dict[str, Any] = {
            WMN_KEY_SITES: [],
            WMN_KEY_CATEGORIES: [],
            WMN_KEY_AUTHORS: [],
            WMN_KEY_LICENSE: [],
        }

        sources: list[tuple[str | Path, bool]] = []
        if self._remote_list_urls:
            sources.extend([(url, True) for url in self._remote_list_urls])
        if self._local_list_paths:
            sources.extend([(path, False) for path in self._local_list_paths])
        if not sources:
            sources = [(WMN_REMOTE_URL, True)]

        coroutines = []
        for source, is_remote in sources:
            if is_remote:
                coroutines.append(self._fetch_json(str(source)))
            else:
                coroutines.append(self._read_json_file(source))

        results = await asyncio.gather(*coroutines, return_exceptions=True)

        failures: list[str] = []
        for src, res in zip(sources, results, strict=False):
            if isinstance(res, Exception):
                source, is_remote = src
                failures.append(
                    f"{source} ({'remote' if is_remote else 'local'}): {res}"
                )
                self._logger.warning("Failed to load WMN data from %s: %s", source, res)
            else:
                merge_lists(res, dataset)

        if not dataset[WMN_KEY_SITES]:
            detail = (
                "; ".join(failures) if failures else "no sources produced any sites"
            )
            raise DataError(f"No sites loaded from any source; details: {detail}")

        return dataset

    def _deduplicate_data(self, data: dict[str, Any]) -> None:
        """Deduplicate and clean the WMN data in place."""
        unique_sites = {
            site[WMN_KEY_NAME]: site
            for site in data[WMN_KEY_SITES]
            if isinstance(site, dict) and site.get(WMN_KEY_NAME)
        }
        data[WMN_KEY_SITES] = list(unique_sites.values())
        data[WMN_KEY_CATEGORIES] = list(dict.fromkeys(data[WMN_KEY_CATEGORIES]))
        data[WMN_KEY_AUTHORS] = list(dict.fromkeys(data[WMN_KEY_AUTHORS]))
        data[WMN_KEY_LICENSE] = list(dict.fromkeys(data[WMN_KEY_LICENSE]))

    async def _load_wmn_lists(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Unified async loader for WMN data and schema.

        Returns a mapping with keys: data (dataset dict) and schema (schema dict).
        """
        if self._wmn_data and self._wmn_schema:
            return (self._wmn_data, self._wmn_schema)

        dataset, dataset_schema = await asyncio.gather(
            self._load_dataset(),
            self._load_schema(),
        )
        self._deduplicate_data(dataset)

        return (dataset, dataset_schema)

    @staticmethod
    def _validate_data(data: dict[str, Any], schema: dict[str, Any]) -> None:
        """Validate WMN data against schema. Raises on failure."""
        if not schema:
            return
        try:
            jsonschema.Draft7Validator.check_schema(schema)
            jsonschema.Draft7Validator(schema).validate(data)
        except jsonschema.ValidationError as e:
            raise SchemaError(f"WMN data does not match schema: {e.message}") from e
        except jsonschema.SchemaError as e:
            raise SchemaError(f"Invalid WMN schema: {e.message}") from e

    async def _ensure_dataset(self) -> None:
        """Load and validate the WMN dataset and schema if not already loaded."""
        if self._wmn_data and self._wmn_schema:
            return

        try:
            data, schema = await self._load_wmn_lists()
            if not self._skip_validation:
                self._validate_data(data, schema)
            self._wmn_data = data
            self._wmn_schema = schema
            self._logger.info(
                "WMN dataset loaded (sites=%d)",
                len(self._wmn_data.get(WMN_KEY_SITES, [])),
            )
        except SchemaError as e:
            raise DataError(f"WMN validation failed: {e}") from e
        except Exception as e:
            raise DataError(f"WMN load failed: {e}") from e

    async def _close_session(self) -> None:
        """Close the HTTP session if open."""
        async with self._session_lock:
            try:
                await self._http.close()
                self._logger.info("HTTP client closed")
            except asyncio.CancelledError:
                self._logger.warning("HTTP client close cancelled")
                raise
            except Exception as error:
                self._logger.warning("Error during HTTP client close: %s", error)

    async def __aenter__(self) -> "Naminter":
        await self._open_session()
        try:
            await self._ensure_dataset()
        except DataError:
            self._logger.error("Dataset load failed")
            raise
        return self

    async def __aexit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any | None
    ) -> None:
        """Async context manager exit."""
        await self._close_session()

    async def get_wmn_summary(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> Summary:
        """Get enriched WMN metadata information for diagnostics and UI.

        Filters can be applied to compute statistics on a subset of sites.
        """
        try:
            await self._ensure_dataset()
        except DataError:
            self._logger.error("Dataset load failed")
            raise
        try:
            sites: list[dict[str, Any]] = self._filter_sites(
                site_names,
                include_categories=include_categories,
                exclude_categories=exclude_categories,
            )
        except DataError as e:
            self._logger.error("Site filtering failed: %s", e)
            raise
        try:
            category_list: list[str] = [
                site.get("cat") for site in sites if site.get("cat")
            ]
            site_name_list: list[str] = [
                site.get("name") for site in sites if site.get("name")
            ]

            total_known_accounts: int = 0

            for site in sites:
                known_list = site.get("known")
                if isinstance(known_list, list) and len(known_list) > 0:
                    total_known_accounts += len(known_list)

            wmn_summary = Summary(
                license=list(dict.fromkeys(self._wmn_data.get("license", []))),
                authors=list(dict.fromkeys(self._wmn_data.get("authors", []))),
                site_names=list(dict.fromkeys(site_name_list)),
                sites_count=len(sites),
                categories=list(dict.fromkeys(category_list)),
                categories_count=len(set(category_list)),
                known_accounts_total=total_known_accounts,
            )

            self._logger.info(
                "WMN summary computed (sites=%d, categories=%d)",
                wmn_summary.sites_count,
                wmn_summary.categories_count,
            )
            return wmn_summary
        except DataError:
            raise
        except Exception as e:
            self._logger.exception("Failed to compute WMN summary")
            raise DataError(f"Failed to retrieve metadata: {e}") from e

    def _filter_sites(
        self,
        site_names: list[str] | None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Filter sites by names and categories for the current WMN dataset."""
        sites: list[dict[str, Any]] = self._wmn_data.get("sites", [])
        if site_names:
            filtered_site_names: set[str] = set(deduplicate_strings(site_names))
            available_names: set[str] = {site.get("name") for site in sites}
            missing_names = filtered_site_names - available_names
            if missing_names:
                raise DataError(f"Unknown site names: {sorted(missing_names)}")
        else:
            filtered_site_names = set()

        filtered_sites: list[dict[str, Any]] = sites

        if filtered_site_names:
            filtered_sites = [
                site
                for site in filtered_sites
                if site.get("name") in filtered_site_names
            ]

        if include_categories:
            include_set: set[str] = set(deduplicate_strings(include_categories))
            filtered_sites = [
                site for site in filtered_sites if site.get("cat") in include_set
            ]

        if exclude_categories:
            exclude_set: set[str] = set(deduplicate_strings(exclude_categories))
            filtered_sites = [
                site for site in filtered_sites if site.get("cat") not in exclude_set
            ]

        self._logger.debug(
            "Filter result %d/%d (names=%s include=%s exclude=%s)",
            len(filtered_sites),
            len(sites),
            bool(site_names),
            bool(include_categories),
            bool(exclude_categories),
        )
        return filtered_sites

    def _get_missing_keys(
        self, site: dict[str, Any], required_keys: Sequence[str]
    ) -> list[str]:
        """Return a list of required keys missing from a site mapping."""
        return [key for key in required_keys if key not in site]

    async def enumerate_site(
        self,
        site: dict[str, Any],
        username: str,
        fuzzy_mode: bool = False,
    ) -> SiteResult:
        """Enumerate a single site for the given username."""
        await self._open_session()
        try:
            await self._ensure_dataset()
        except DataError:
            self._logger.error("Dataset load failed")
            raise

        missing_keys = self._get_missing_keys(site, REQUIRED_KEYS_ENUMERATE)
        if missing_keys:
            return SiteResult(
                name=site.get("name", "unknown"),
                category=site.get("cat", "unknown"),
                username=username,
                status=ResultStatus.ERROR,
                error=f"Site entry missing required keys: {missing_keys}",
            )

        name = site["name"]
        category = site["cat"]

        uri_check_template = site["uri_check"]
        strip_bad_char = site.get("strip_bad_char", "")
        clean_username = username.translate(str.maketrans("", "", strip_bad_char))
        if not clean_username:
            return SiteResult(
                name,
                category,
                username,
                ResultStatus.ERROR,
                error="Username became empty after stripping",
            )

        uri_check = uri_check_template.replace(ACCOUNT_PLACEHOLDER, clean_username)
        uri_pretty = site.get("uri_pretty", uri_check_template).replace(
            ACCOUNT_PLACEHOLDER, clean_username
        )

        self._logger.debug(
            "Enumerating site=%s user=%s mode=%s",
            name,
            username,
            "FUZZY" if fuzzy_mode else "STRICT",
        )

        headers = site.get("headers", {})
        post_body = site.get("post_body")
        if post_body:
            post_body = post_body.replace(ACCOUNT_PLACEHOLDER, clean_username)
            self._logger.debug("POST %s (body_present=%s)", uri_check, True)
        else:
            self._logger.debug("GET %s", uri_check)

        try:
            async with self._semaphore:
                if post_body:
                    response = await self._http.post(
                        uri_check, headers=headers, data=post_body
                    )
                else:
                    response = await self._http.get(uri_check, headers=headers)
                elapsed = response.elapsed
                self._logger.debug(
                    "Request ok (status=%d, elapsed=%.2fs)",
                    response.status_code,
                    elapsed,
                )
        except asyncio.CancelledError:
            self._logger.warning("Request cancelled")
            raise
        except TimeoutError as e:
            self._logger.warning("Request timeout for %s: %s", name, e)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
                error=f"Request timeout: {e}",
            )
        except SessionError as e:
            self._logger.warning("Session error for %s: %s", name, e)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
                error=f"Session error: {e}",
            )
        except NetworkError as e:
            self._logger.warning("Network error for %s: %s", name, e)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
                error=f"Network error: {e}",
            )
        except Exception as e:
            self._logger.exception("Unexpected error during request for %s", name)
            return SiteResult(
                name=name,
                category=category,
                username=username,
                result_url=uri_pretty,
                status=ResultStatus.ERROR,
                error=f"Unexpected error: {e}",
            )

        result_status = SiteResult.get_result_status(
            response_code=response.status_code,
            response_text=response.text,
            e_code=site["e_code"],
            e_string=site["e_string"],
            m_code=site["m_code"],
            m_string=site["m_string"],
            fuzzy_mode=fuzzy_mode,
        )

        self._logger.debug(
            "Result=%s (HTTP %d)", result_status.name, response.status_code
        )

        return SiteResult(
            name=name,
            category=category,
            username=username,
            result_url=uri_pretty,
            status=result_status,
            response_code=response.status_code,
            elapsed=elapsed,
            response_text=response.text,
        )

    async def enumerate_usernames(
        self,
        usernames: list[str],
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> list[SiteResult] | AsyncGenerator[SiteResult, None]:
        """Enumerate one or multiple usernames across all loaded sites."""
        await self._open_session()
        try:
            await self._ensure_dataset()
        except DataError:
            self._logger.exception("Dataset load failed")
            raise

        try:
            usernames = validate_usernames(usernames)
        except ValidationError as e:
            self._logger.error("Invalid usernames: %s", e)
            raise DataError("Invalid usernames") from e
        else:
            self._logger.info("Usernames validated (count=%d)", len(usernames))

        try:
            sites = self._filter_sites(
                site_names,
                include_categories=include_categories,
                exclude_categories=exclude_categories,
            )
        except DataError as e:
            self._logger.error("Site filtering failed: %s", e)
            raise

        coroutines = [
            self.enumerate_site(site, username, fuzzy_mode)
            for site in sites
            for username in usernames
        ]

        async def iterate_results() -> AsyncGenerator[SiteResult, None]:
            for completed_task in asyncio.as_completed(coroutines):
                yield await completed_task

        if as_generator:
            return iterate_results()

        return await asyncio.gather(*coroutines)

    async def self_enumeration(
        self,
        site_names: list[str] | None = None,
        include_categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        fuzzy_mode: bool = False,
        as_generator: bool = False,
    ) -> list[SelfEnumerationResult] | AsyncGenerator[SelfEnumerationResult, None]:
        """Run self-enumeration using known accounts for each site."""
        await self._open_session()
        try:
            await self._ensure_dataset()
        except DataError:
            self._logger.exception("Dataset load failed")
            raise

        try:
            sites = self._filter_sites(
                site_names,
                include_categories=include_categories,
                exclude_categories=exclude_categories,
            )
        except DataError as e:
            self._logger.error("Site filtering failed: %s", e)
            raise

        self._logger.info(
            "Starting self-enumeration (sites=%d, mode=%s)",
            len(sites),
            ValidationMode.FUZZY if fuzzy_mode else ValidationMode.STRICT,
        )

        async def _enumerate_known(site: dict[str, Any]) -> SelfEnumerationResult:
            """Helper function to enumerate a site with all its known users."""
            missing_keys = self._get_missing_keys(site, REQUIRED_KEYS_SELF_ENUM)
            if missing_keys:
                return SelfEnumerationResult(
                    name=site.get("name", "unknown"),
                    category=site.get("cat", "unknown"),
                    error=f"Site data missing required keys: {missing_keys}",
                )

            name = site["name"]
            category = site["cat"]
            known = site["known"]

            self._logger.debug(
                "Self-enumerating site=%s category=%s known_count=%d",
                name,
                category,
                len(known),
            )

            try:
                coroutines = [
                    self.enumerate_site(site, username, fuzzy_mode)
                    for username in known
                ]
                results = await asyncio.gather(*coroutines)

                return SelfEnumerationResult(
                    name=name, category=category, results=results
                )
            except Exception as e:
                self._logger.exception("Self-enumeration failed for site=%s", name)
                return SelfEnumerationResult(
                    name=name,
                    category=category,
                    error=f"Unexpected error during self-enumeration: {e}",
                )

        coroutines = [
            _enumerate_known(site) for site in sites if isinstance(site, dict)
        ]

        async def iterate_results() -> AsyncGenerator[SelfEnumerationResult, None]:
            for completed_task in asyncio.as_completed(coroutines):
                yield await completed_task

        if as_generator:
            return iterate_results()

        return await asyncio.gather(*coroutines)
