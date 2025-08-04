import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from curl_cffi import requests
from ..core.constants import WMN_REMOTE_URL
from ..core.exceptions import DataError


def load_wmn_lists(
    local_list_paths: Optional[List[Path]] = None, 
    remote_list_urls: Optional[List[str]] = None, 
    skip_validation: bool = False,
    local_schema_path: Optional[Path] = None,
    remote_schema_url: Optional[str] = None
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Load and merge WMN lists from local and remote sources."""
    wmn_data = {"sites": [], "categories": [], "authors": [], "license": []}
    wmn_schema = None
    
    def _fetch_json(url: str, timeout: int = 30) -> Dict[str, Any]:
        """Helper to fetch and parse JSON from URL."""
        if not url or not isinstance(url, str) or not url.strip():
            raise ValueError(f"Invalid URL: {url}")
        
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise DataError(f"Failed to fetch from {url}: {e}") from e
        except json.JSONDecodeError as e:
            raise DataError(f"Failed to parse JSON from {url}: {e}") from e

    def _merge_data(data: Dict[str, Any]) -> None:
        """Helper to merge data into wmn_data."""
        if isinstance(data, dict):
            for key in ["sites", "categories", "authors", "license"]:
                if key in data and isinstance(data[key], list):
                    wmn_data[key].extend(data[key])
    
    if not skip_validation:
        try:
            if local_schema_path:
                wmn_schema = json.loads(Path(local_schema_path).read_text())
            elif remote_schema_url:
                wmn_schema = _fetch_json(remote_schema_url)
        except Exception:
            pass
    
    sources = []
    if remote_list_urls:
        sources.extend([(url, True) for url in remote_list_urls])
    if local_list_paths:
        sources.extend([(path, False) for path in local_list_paths])
    
    if not sources:
        sources = [(WMN_REMOTE_URL, True)]
    
    for source, is_remote in sources:
        try:
            if is_remote:
                data = _fetch_json(source)
            else:
                data = json.loads(Path(source).read_text())
            _merge_data(data)
        except Exception as e:
            if not sources or source == WMN_REMOTE_URL:
                raise DataError(f"Failed to load WMN data from {source}: {e}") from e
    
    if not wmn_data["sites"]:
        raise DataError("No sites loaded from any source")
    
    unique_sites = {site["name"]: site for site in wmn_data["sites"] 
                   if isinstance(site, dict) and site.get("name")}
    wmn_data["sites"] = list(unique_sites.values())
    wmn_data["categories"] = sorted(set(wmn_data["categories"]))
    wmn_data["authors"] = sorted(set(wmn_data["authors"]))
    wmn_data["license"] = list(dict.fromkeys(wmn_data["license"]))
    
    return wmn_data, wmn_schema 