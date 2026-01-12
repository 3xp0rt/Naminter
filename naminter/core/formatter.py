from collections.abc import Mapping, Sequence
import json
from typing import Any

from naminter.core.constants import (
    DEFAULT_JSON_ENSURE_ASCII,
    DEFAULT_JSON_INDENT,
    SCHEMA_KEY_ITEMS,
    SCHEMA_KEY_PROPERTIES,
    SITE_KEY_HEADERS,
    SITE_KEY_NAME,
    WMN_KEY_AUTHORS,
    WMN_KEY_CATEGORIES,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import WMNFormatError, WMNSchemaError
from naminter.core.models import WMNDataset


class WMNFormatter:
    """Formatter for WhatsMyName JSON data."""

    def __init__(self, schema: Mapping[str, Any]) -> None:
        """Initialize formatter with schema.

        Args:
            schema: JSON Schema for the dataset.
        """
        self.schema = schema
        self._site_key_order: list[str] | None = None
        self._site_key_order_set: set[str] | None = None

    @staticmethod
    def _sort_array_alphabetically(array: list[str]) -> list[str]:
        """Sort strings alphabetically case-insensitively."""
        return sorted(array, key=str.casefold)

    @staticmethod
    def _sort_sites_by_name(sites: Sequence[Any]) -> list[dict[str, Any]]:
        """Sort sites by name case-insensitively."""
        site_dicts: list[dict[str, Any]] = []
        for i, site in enumerate(sites):
            if not isinstance(site, Mapping):
                msg = (
                    f"Each site must be an object, "
                    f"got {type(site).__name__} at index {i}"
                )
                raise WMNFormatError(msg)
            site_dicts.append(dict(site))

        return sorted(
            site_dicts,
            key=lambda site: str(site.get(SITE_KEY_NAME, "")).casefold(),
        )

    @staticmethod
    def _sort_site_headers(
        site_data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return new site dict with headers sorted by name."""
        result = dict(site_data)

        headers = result.get(SITE_KEY_HEADERS)
        if headers is not None:
            if not isinstance(headers, dict):
                msg = (
                    f"'{SITE_KEY_HEADERS}' must be an object, "
                    f"got {type(headers).__name__}"
                )
                raise WMNFormatError(msg)
            result[SITE_KEY_HEADERS] = dict(
                sorted(
                    headers.items(),
                    key=lambda item: str(item[0]).casefold(),
                ),
            )

        return result

    def _reorder_site_keys(
        self,
        site_data: Mapping[str, Any],
        key_order: list[str],
    ) -> dict[str, Any]:
        """Return site dict with keys in schema-defined order."""
        if self._site_key_order_set is None:
            self._site_key_order_set = set(key_order)
        allowed = self._site_key_order_set
        unknown = set(site_data) - allowed
        if unknown:
            msg = f"Unknown keys found in site data: {sorted(unknown)}"
            raise WMNFormatError(msg)

        return {key: site_data[key] for key in key_order if key in site_data}

    @staticmethod
    def _dumps(obj: object, *, what: str) -> str:
        """Serialize object to JSON string with consistent error handling."""
        try:
            return json.dumps(
                obj,
                indent=DEFAULT_JSON_INDENT,
                ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
            )
        except (TypeError, ValueError, RecursionError) as error:
            msg = f"{what} is not JSON-serializable: {error}"
            raise WMNFormatError(msg) from error

    def format_schema(self) -> str:
        """Return formatted schema JSON string."""
        return self._dumps(self.schema, what="Schema")

    def format_dataset(self, data: WMNDataset) -> str:
        """Return formatted data JSON string per schema.

        Args:
            data: WMN dataset to format. This will not be modified.

        Returns:
            Formatted JSON string.

        Raises:
            WMNFormatError: If data is not JSON-serializable or invalid.
        """
        formatted_authors = self._format_string_array(data, WMN_KEY_AUTHORS)
        formatted_categories = self._format_string_array(data, WMN_KEY_CATEGORIES)
        formatted_sites = self._format_sites(data)

        excluded_keys = {WMN_KEY_AUTHORS, WMN_KEY_CATEGORIES, WMN_KEY_SITES}
        other_keys = {
            key: value for key, value in data.items() if key not in excluded_keys
        }

        formatted_data = {
            WMN_KEY_AUTHORS: formatted_authors,
            WMN_KEY_CATEGORIES: formatted_categories,
            WMN_KEY_SITES: formatted_sites,
            **other_keys,
        }
        return self._dumps(formatted_data, what="Data")

    def _get_site_key_order(self) -> list[str]:
        """Extract key order from schema for site objects.

        Returns:
            List of keys in the order they appear in the schema.

        Raises:
            WMNSchemaError: If site schema properties are not found or invalid.
        """
        if self._site_key_order is not None:
            return self._site_key_order

        site_schema = (
            self.schema
            .get(SCHEMA_KEY_PROPERTIES, {})
            .get(WMN_KEY_SITES, {})
            .get(SCHEMA_KEY_ITEMS, {})
            .get(SCHEMA_KEY_PROPERTIES)
        )

        if site_schema is None:
            msg = "Site schema properties not found in schema"
            raise WMNSchemaError(msg)
        if not isinstance(site_schema, dict):
            msg = (
                f"Site schema properties must be an object, "
                f"got {type(site_schema).__name__}"
            )
            raise WMNSchemaError(msg)

        self._site_key_order = list(site_schema.keys())
        self._site_key_order_set = set(self._site_key_order)
        return self._site_key_order

    def _format_string_array(self, data: Mapping[str, Any], key: str) -> list[str]:
        """Sort string array alphabetically if present."""
        array_data = data.get(key)
        if array_data is None:
            msg = f"'{key}' is required but not found"
            raise WMNFormatError(msg)
        if not isinstance(array_data, list):
            msg = f"'{key}' must be a list, got {type(array_data).__name__}"
            raise WMNFormatError(msg)
        if not array_data:
            msg = f"'{key}' must be a non-empty list"
            raise WMNFormatError(msg)
        for item in array_data:
            if not isinstance(item, str):
                msg = f"'{key}' must contain only strings, got {type(item).__name__}"
                raise WMNFormatError(msg)
            if not item.strip():
                msg = f"'{key}' must contain non-empty strings"
                raise WMNFormatError(msg)
        return self._sort_array_alphabetically(array_data)

    def _format_site(
        self,
        site_data: Mapping[str, Any],
        key_order: list[str],
    ) -> dict[str, Any]:
        """Format one site with sorted headers and ordered keys."""
        formatted_site = self._sort_site_headers(site_data)
        return self._reorder_site_keys(formatted_site, key_order)

    def _format_sites(self, data: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Sort and format site data per schema."""
        sites = data.get(WMN_KEY_SITES)
        if not isinstance(sites, list):
            msg = f"'{WMN_KEY_SITES}' must be a list, got {type(sites).__name__}"
            raise WMNFormatError(msg)

        sorted_sites = self._sort_sites_by_name(sites)
        key_order = self._get_site_key_order()
        return [self._format_site(site_data, key_order) for site_data in sorted_sites]
