"""Formatter for sorting and ordering WhatsMyName JSON data per schema."""

from collections.abc import Mapping, Sequence
from typing import Any

import orjson

from naminter.core.constants import (
    SCHEMA_KEY_ITEMS,
    SCHEMA_KEY_PROPERTIES,
    SITE_KEY_HEADERS,
    SITE_KEY_NAME,
    WMN_KEY_AUTHORS,
    WMN_KEY_CATEGORIES,
    WMN_KEY_LICENSE,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import WMNFormatError, WMNSchemaError


class WMNFormatter:
    """Formatter for WhatsMyName JSON data."""

    def __init__(self, schema: Mapping[str, Any]) -> None:
        """Initialize formatter with schema.

        Args:
            schema: JSON Schema for the data.
        """
        self._schema = schema
        self._site_key_order: list[str] | None = None

    @staticmethod
    def _sort_array_alphabetically(array: list[str]) -> list[str]:
        """Sort strings alphabetically case-insensitively.

        Args:
            array: List of strings to sort.

        Returns:
            list[str]: Sorted list of strings.
        """
        return sorted(array, key=str.casefold)

    @staticmethod
    def _sort_sites_by_name(sites: Sequence[Any]) -> list[dict[str, Any]]:
        """Sort sites by name case-insensitively.

        Args:
            sites: Sequence of site mapping objects to sort.

        Returns:
            list[dict[str, Any]]: Sites sorted alphabetically by name.

        Raises:
            WMNFormatError: If any site entry is not a mapping.
        """
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
        """Return new site dict with headers sorted by name.

        Args:
            site_data: Site configuration mapping to process.

        Returns:
            dict[str, Any]: New site dict with alphabetically sorted headers.

        Raises:
            WMNFormatError: If headers value is not a dict.
        """
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

    @staticmethod
    def _reorder_site_keys(
        site_data: Mapping[str, Any],
        key_order: list[str],
    ) -> dict[str, Any]:
        """Return site dict with keys in schema-defined order.

        Args:
            site_data: Site configuration mapping to reorder.
            key_order: List of keys in the desired order.

        Returns:
            dict[str, Any]: New dict with keys ordered per schema.

        Raises:
            WMNFormatError: If site_data contains unknown keys.
        """
        unknown = set(site_data) - set(key_order)
        if unknown:
            msg = f"Unknown keys found in site data: {sorted(unknown)}"
            raise WMNFormatError(msg)

        return {key: site_data[key] for key in key_order if key in site_data}

    @staticmethod
    def _dumps(obj: object, *, what: str) -> str:
        """Serialize object to JSON string with consistent error handling.

        Args:
            obj: Object to serialize.
            what: Label for the object used in error messages.

        Returns:
            str: Formatted JSON string.

        Raises:
            WMNFormatError: If the object is not JSON-serializable.
        """
        try:
            return orjson.dumps(obj, option=orjson.OPT_INDENT_2).decode("utf-8")
        except (
            TypeError,
            ValueError,
            RecursionError,
            orjson.JSONEncodeError,
        ) as error:
            msg = f"{what} is not JSON-serializable: {error}"
            raise WMNFormatError(msg) from error

    def format_schema(self) -> str:
        """Return formatted schema JSON string.

        Returns:
            str: Schema serialized as a formatted JSON string.
        """
        return self._dumps(self._schema, what="Schema")

    def format_data(self, data: dict[str, Any]) -> str:
        """Return formatted data JSON string per schema.

        Args:
            data: WMN data to format. This will not be modified.

        Returns:
            str: Formatted JSON string.

        Raises:
            WMNFormatError: If data is not JSON-serializable or invalid.
            WMNSchemaError: If site schema properties are not found or invalid.
        """
        formatted_authors = self._format_string_array(data, WMN_KEY_AUTHORS)
        formatted_categories = self._format_string_array(data, WMN_KEY_CATEGORIES)
        formatted_sites = self._format_sites(data)

        allowed_keys = {
            WMN_KEY_AUTHORS,
            WMN_KEY_CATEGORIES,
            WMN_KEY_SITES,
            WMN_KEY_LICENSE,
        }
        unknown_keys = set(data.keys()) - allowed_keys
        if unknown_keys:
            msg = f"Unknown keys found in data: {sorted(unknown_keys)}"
            raise WMNFormatError(msg)

        formatted_data: dict[str, Any] = {
            WMN_KEY_LICENSE: data[WMN_KEY_LICENSE],
            WMN_KEY_AUTHORS: formatted_authors,
            WMN_KEY_CATEGORIES: formatted_categories,
            WMN_KEY_SITES: formatted_sites,
        }
        return self._dumps(formatted_data, what="Data")

    def _get_site_key_order(self) -> list[str]:
        """Extract key order from schema for site objects.

        Returns:
            list[str]: Keys in schema-defined order.

        Raises:
            WMNSchemaError: If site schema properties are not found or invalid.
        """
        if self._site_key_order is not None:
            return self._site_key_order

        site_schema = (
            self._schema
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
        return self._site_key_order

    def _format_string_array(self, data: Mapping[str, Any], key: str) -> list[str]:
        """Sort a string array field alphabetically.

        Args:
            data: Data mapping containing the array field.
            key: Key name of the string array to sort.

        Returns:
            list[str]: Alphabetically sorted list of strings.

        Raises:
            WMNFormatError: If the field is missing, not a list, empty,
                or contains non-string or blank items.
        """
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
        """Format one site with sorted headers and ordered keys.

        Args:
            site_data: Site configuration mapping to format.
            key_order: List of keys in the desired schema order.

        Returns:
            dict[str, Any]: Formatted site dict with sorted headers and ordered keys.

        Raises:
            WMNFormatError: If headers value is not a dict or site_data
                contains unknown keys.
        """
        formatted_site = self._sort_site_headers(site_data)
        return self._reorder_site_keys(formatted_site, key_order)

    def _format_sites(self, data: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Sort and format site data per schema.

        Args:
            data: Data mapping containing the sites array.

        Returns:
            list[dict[str, Any]]: Sorted and formatted site dicts.

        Raises:
            WMNFormatError: If sites field is not a list or contains invalid entries.
            WMNSchemaError: If site schema properties are not found or invalid.
        """
        sites = data.get(WMN_KEY_SITES)
        if not isinstance(sites, list):
            msg = f"'{WMN_KEY_SITES}' must be a list, got {type(sites).__name__}"
            raise WMNFormatError(msg)

        sorted_sites = self._sort_sites_by_name(sites)
        key_order = self._get_site_key_order()
        return [self._format_site(site_data, key_order) for site_data in sorted_sites]
