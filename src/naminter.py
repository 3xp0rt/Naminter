import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, List, AsyncGenerator, Union

from curl_cffi import requests
from curl_cffi.requests import AsyncSession, RequestsError

from .models import CheckStatus, SiteResult, SelfTestResult, TestResult
from .exceptions import NaminterError, ConfigurationError, NetworkError, DataError
from .settings import (
    SITES_LIST_REMOTE_URL,
    HTTP_REQUEST_TIMEOUT_SECONDS,
    HTTP_SSL_VERIFY,
    HTTP_ALLOW_REDIRECTS,
    BROWSER_IMPERSONATE_AGENT,
    MAX_TASKS,
    LOGGING_FORMAT,
)

class Naminter:
    def __init__(
        self,
        debug: Optional[bool] = False,
        max_tasks: Optional[int] = MAX_TASKS,
        impersonate: Optional[str] = BROWSER_IMPERSONATE_AGENT,
        verify_ssl: Optional[str] = HTTP_SSL_VERIFY,
        timeout: Optional[int] = HTTP_REQUEST_TIMEOUT_SECONDS,
        allow_redirects: Optional[bool] = HTTP_ALLOW_REDIRECTS,
        proxy: Optional[str] = None,
    ) -> None:
        try:
            if max_tasks is not None and max_tasks < 1:
                raise ConfigurationError("max_tasks must be at least 1")
            
            if timeout is not None and timeout < 1:
                raise ConfigurationError("timeout must be at least 1 second")
            
            if proxy and not isinstance(proxy, str):
                raise ConfigurationError("proxy must be a string")

            logging.basicConfig(
                level=logging.DEBUG if debug else logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.logger = logging.getLogger(__name__)

            self.debug = debug
            self.max_tasks = max_tasks
            self.impersonate = impersonate
            self.verify_ssl = verify_ssl
            self.timeout = timeout
            self.allow_redirects = allow_redirects
            self.proxy = {"http": proxy, "https": proxy} if proxy else None

            self._semaphore = asyncio.Semaphore(max_tasks if max_tasks else 10)
            self._session: Optional[AsyncSession] = None
            self._wmn_data: Optional[Dict[str, Any]] = None

        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Naminter: {str(e)}") from e

    async def __aenter__(self):
        try:
            self._session = await self._create_session()
            return self
        except Exception as e:
            raise NetworkError(f"Failed to create session: {str(e)}") from e

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            try:
                await self._session.close()
            except Exception as e:
                self.logger.error(f"Error closing session: {str(e)}")

    async def _create_session(self) -> AsyncSession:
        try:
            session = AsyncSession(
                impersonate=self.impersonate,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                proxies=self.proxy
            )
            return session
        except Exception as e:
            raise NetworkError(f"Failed to create session: {str(e)}") from e

    async def fetch_remote_list(self, remote_list_url: Optional[str] = SITES_LIST_REMOTE_URL) -> Dict[str, Any]:
        if not self._session:
            raise NetworkError("Session not initialized. Use async with context manager.")

        self.logger.debug("Fetching WMN data from: %s", remote_list_url)

        try:
            response = await self._session.get(remote_list_url)
            response.raise_for_status()

            data = response.json()

            if not isinstance(data, dict):
                raise DataError("Remote data must be a JSON object")

            sites = data.get('sites')
            if not sites:
                raise DataError("Remote data missing required 'sites' field")

            self._wmn_data = data
            return self._wmn_data
        except RequestsError as e:
            self.logger.error("Network error fetching remote list from %s: %s", remote_list_url, e)
            raise NetworkError(f"Network error fetching remote list: {e}") from e
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON in remote response from %s: %s", remote_list_url, e)
            raise DataError(f"Invalid JSON in remote response: {e}") from e
        except Exception as e:
            self.logger.exception("Unexpected error fetching remote list from %s", remote_list_url)
            raise NaminterError(f"Unexpected error fetching remote list: {e}") from e

    async def load_local_list(self, local_list_path: Union[str, Path]) -> Dict[str, Any]:
        path = Path(local_list_path)
        if not path.is_file():
            self.logger.error("Local list file not found: %s", path)
            raise FileNotFoundError(f"File not found: {path}")

        self.logger.debug("Loading site list from local file: %s", path)
        try:
            data = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except Exception as read_error:
            self.logger.error("Error reading file %s: %s", path, read_error)
            raise DataError(f"Error reading file: {path}") from read_error

        try:
            self._wmn_data = json.loads(data)
        except json.JSONDecodeError as json_error:
            self.logger.error("Failed to parse JSON in file %s: %s", path, json_error)
            raise DataError(f"Invalid JSON in file {path}: {json_error}") from json_error

        self.logger.debug("Successfully loaded JSON data from: %s", path)
        return self._wmn_data
    
    async def get_wmn_info(self) -> Dict[str, Any]:
        if not self._wmn_data:
            return None
        
        return {
            "license": self._wmn_data.get("license", []),
            "authors": self._wmn_data.get("authors", []),
            "categories": self._wmn_data.get("categories", []),
            "sites_count": len(self._wmn_data.get("sites", [])),
        }

    async def check_site(
        self, 
        site: Dict[str, Any], 
        username: str, 
        weak_mode: bool = False,
    ) -> SiteResult:
        site_name = site.get("name", "unknown")
        category = site.get("cat") or site.get("category", "unknown")
        strip_chars = site.get("strip_bad_char", "")
        clean_username = username.translate(str.maketrans("", "", strip_chars))

        uri_check_template = site.get("uri_check")
        uri_check = uri_check_template.replace("{account}", clean_username)
        uri_pretty_template = site.get("uri_pretty", uri_check_template)
        uri_pretty = uri_pretty_template.replace("{account}", clean_username)
        headers = site.get("headers", {})

        if not site.get("valid", True):
            self.logger.debug("Skipping invalid site: %s", site_name)
            return SiteResult(
                site_name=site_name,
                site_url=uri_pretty,
                category=category,
                check_status=CheckStatus.NOT_VALID,
                error="Site marked as invalid",
            )

        try:
            async with self._semaphore:
                start_time = time.monotonic()

                post_body = site.get("post_body")
                if post_body:
                    post_body = post_body.replace("{account}", clean_username)
                    response = await self._session.post(uri_check, headers=headers, data=post_body)
                else:
                    response = await self._session.get(uri_check, headers=headers)
                
                elapsed = time.monotonic() - start_time
        except asyncio.CancelledError as e:
            self.logger.debug("Request cancelled for %s: %s", site_name, e)
            return SiteResult(
                site_name=site_name,
                site_url=uri_pretty,
                category=category,
                check_status=CheckStatus.ERROR,
                error=str(e),
            )
        except Exception as e:
            self.logger.debug("Error accessing site %s", site_name)
            elapsed = 0.0
            return SiteResult(
                site_name=site_name,
                site_url=uri_pretty,
                category=category,
                check_status=CheckStatus.ERROR,
                elapsed=elapsed,
                error=str(e),
            )

        response_text = response.text
        status_code = response.status_code

        exists_status_matches = status_code == site.get("e_code")
        exists_string_matches = site.get("e_string", "") in response_text
        not_exists_status_matches = status_code == site.get("m_code")
        not_exists_string_matches = site.get("m_string", "") in response_text

        if weak_mode:
            if exists_status_matches or exists_string_matches:
                check_status = CheckStatus.FOUND
            elif not_exists_status_matches or not_exists_string_matches:
                check_status = CheckStatus.NOT_FOUND
            else:
                check_status = CheckStatus.UNKNOWN
        else:
            if exists_status_matches and exists_string_matches:
                check_status = CheckStatus.FOUND
            elif not_exists_status_matches and not_exists_string_matches:
                check_status = CheckStatus.NOT_FOUND
            else:
                check_status = CheckStatus.UNKNOWN
        
        self.logger.debug(
            "[%s] Status: %s, Code: %s, Exists: (code=%s, string=%s), Not exists: (code=%s, string=%s), Time: %.2fs, Mode: %s",
            site_name,
            check_status.name,
            status_code,
            exists_status_matches,
            exists_string_matches,
            not_exists_status_matches,
            not_exists_string_matches,
            elapsed,
            "weak" if weak_mode else "full",
        )

        return SiteResult(
            site_name=site_name,
            site_url=uri_pretty,
            category=category,
            check_status=check_status,
            status_code=status_code,
            elapsed=elapsed,
        )
    
    async def check_username(
        self, 
        username: str,
        weak_mode: bool = False,
        as_generator: bool = False
    ) -> Union[List[SiteResult], AsyncGenerator[SiteResult, None]]:
        if self._wmn_data is None:
            return None

        sites = self._wmn_data.get('sites', [])

        async def generate_results():
            tasks = [self.check_site(site, username, weak_mode) for site in sites]
            for result in asyncio.as_completed(tasks):
                yield await result

        return generate_results() if as_generator else [result async for result in generate_results()]    

    async def self_check(
        self,
        weak_mode: bool = False,
        as_generator: bool = False
    ) -> Union[List[SelfTestResult], AsyncGenerator[SelfTestResult, None]]:
        if self._wmn_data is None:
            return None

        sites = self._wmn_data.get('sites', [])

        async def check_site_with_users(site) -> Optional[SelfTestResult]:
            if not (known_list := site.get("known")):
                self.logger.debug(
                    "Site '%s' has no 'known' accounts defined. Skipping check.",
                    site.get('name', 'Unknown')
                )
                return None

            site_name = site.get("name", "Unknown")
            category = site.get("cat") or site.get("category", "unknown")
            
            site_results = await asyncio.gather(
                *[self.check_site(site, username, weak_mode) for username in known_list]
            )
            
            results = [
                TestResult(
                    site_url=result.site_url,
                    check_status=result.check_status,
                    status_code=result.status_code,
                    elapsed=result.elapsed,
                    error=result.error
                )
                for result in site_results
            ]

            return SelfTestResult(
                site_name=site_name,
                category=category,
                results=results
            )

        async def generate_results():
            tasks = [check_site_with_users(site) for site in sites]
            for result in asyncio.as_completed(tasks):
                if site_result := await result:
                    yield site_result

        return generate_results() if as_generator else [result async for result in generate_results()]