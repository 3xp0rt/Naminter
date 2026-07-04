"""WMN data validator using JSON Schema and custom validation rules."""

from __future__ import annotations

from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from jsonschema.exceptions import SchemaError as JsonSchemaError
from jsonschema.validators import validator_for
import orjson

from naminter.core.constants import (
    ACCOUNT_PLACEHOLDER,
    HTTP_STATUS_CODE_MAX,
    HTTP_STATUS_CODE_MIN,
    SITE_KEY_CATEGORY,
    SITE_KEY_E_CODE,
    SITE_KEY_E_STRING,
    SITE_KEY_HEADERS,
    SITE_KEY_KNOWN,
    SITE_KEY_M_CODE,
    SITE_KEY_M_STRING,
    SITE_KEY_NAME,
    SITE_KEY_POST_BODY,
    SITE_KEY_PROTECTION,
    SITE_KEY_STRIP_BAD_CHAR,
    SITE_KEY_URI_CHECK,
    SITE_KEY_URI_PRETTY,
    SITE_KEY_VALID,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import WMNSchemaError
from naminter.core.models import (
    WMN_METADATA_KEYS,
    WMN_REQUIRED_KEYS,
    WMNError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from jsonschema.protocols import Validator

logger = logging.getLogger(__name__)


class WMNValidator:
    """Validates WMN data against JSON Schema and custom rules."""

    __slots__ = ("_schema", "_validator")

    def __init__(self, schema: Mapping[str, Any]) -> None:
        """Initialize validator with schema.

        Args:
            schema: JSON Schema to validate against. Must not be empty.

        Raises:
            WMNSchemaError: If the provided schema is empty, invalid, or cannot be used.
        """
        self._schema = dict(schema)
        if not self._schema:
            msg = "Schema cannot be empty"
            raise WMNSchemaError(msg)
        try:
            validator_cls = validator_for(self._schema)
            validator_cls.check_schema(self._schema)
            self._validator: Validator = validator_cls(self._schema)
        except JsonSchemaError as e:
            msg = f"Invalid JSON schema: {e}"
            raise WMNSchemaError(msg) from e
        except Exception as e:
            msg = f"Failed to initialize JSON schema validator: {e}"
            raise WMNSchemaError(msg) from e

    def validate_schema(self, data: Mapping[str, Any]) -> list[WMNError]:
        """Validate WMN data against the JSON schema.

        Args:
            data: WMN data to validate.

        Returns:
            list[WMNError]: Validation errors, empty if valid.
        """
        return [
            WMNValidator._error(
                str(error.json_path),
                str(error.message),
                error.instance,
            )
            for error in self._validator.iter_errors(dict(data))
        ]

    @staticmethod
    def validate_rules(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate WMN data with custom Naminter rules.

        Args:
            data: WMN data to validate.

        Returns:
            list[WMNError]: Validation errors, empty if valid.
        """
        errors: list[WMNError] = []
        for field_key in WMN_METADATA_KEYS:
            errors.extend(WMNValidator._validate_string_array(data, field_key))
        errors.extend(WMNValidator._validate_sites(data))

        return errors

    @staticmethod
    def _preview(value: object) -> str | None:
        """Return a JSON preview of a value, or None if serialization fails."""
        try:
            return orjson.dumps(value, option=orjson.OPT_INDENT_2).decode("utf-8")
        except (TypeError, ValueError, orjson.JSONEncodeError) as e:
            logger.debug(
                "Failed to generate data preview: %s",
                e,
                exc_info=True,
            )
        return None

    @staticmethod
    def _error(
        path: str,
        message: str,
        data: object | None = None,
    ) -> WMNError:
        """Create a WMNError with an optional JSON preview of the offending value."""
        return WMNError(
            path=path,
            data=WMNValidator._preview(data) if data is not None else None,
            message=message,
        )

    @staticmethod
    def _site_error(
        base_path: str,
        suffix: str,
        message: str,
        data: object | None = None,
    ) -> WMNError:
        """Create a WMNError for a site validation issue."""
        path = f"{base_path}.{suffix}" if suffix else base_path
        return WMNValidator._error(path, message, data)

    @staticmethod
    def _validate_http_uri(
        value: str,
        *,
        base_path: str,
        field_key: str,
    ) -> WMNError | None:
        """Return a URI validation error, or None if value is a valid http(s) URL."""
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return None
        return WMNValidator._site_error(
            base_path,
            field_key,
            f"Invalid {field_key}: must be a valid http or https URL",
            value,
        )

    @staticmethod
    def _validate_string_array(
        data: Mapping[str, Any],
        field_key: str,
    ) -> list[WMNError]:
        """Validate a top-level field as a required array of strings."""
        errors: list[WMNError] = []

        if field_key not in data:
            errors.append(
                WMNValidator._error(
                    f"$.{field_key}",
                    f"Missing required key: {field_key}",
                ),
            )
            return errors

        field_data: Any = data[field_key]

        if not isinstance(field_data, list):
            errors.append(
                WMNValidator._error(
                    f"$.{field_key}",
                    (
                        f"Invalid {field_key}: must be array, "
                        f"got {type(field_data).__name__}"
                    ),
                    field_data,
                ),
            )
            return errors

        for index, item in enumerate(field_data):
            if not isinstance(item, str):
                errors.append(
                    WMNValidator._error(
                        f"$.{field_key}[{index}]",
                        (
                            f"Invalid {field_key} item at "
                            f"index {index}: must be string, "
                            f"got {type(item).__name__}"
                        ),
                        item,
                    ),
                )

        return errors

    @staticmethod
    def _validate_site_uri_body(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate uri_check and post_body types and placeholder rules."""
        errors: list[WMNError] = []

        uri_check: Any = site.get(SITE_KEY_URI_CHECK)
        if not isinstance(uri_check, str):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: must be string, "
                    f"got {type(uri_check).__name__}",
                    uri_check,
                )
            )
        elif uri_error := WMNValidator._validate_http_uri(
            uri_check,
            base_path=base_path,
            field_key=SITE_KEY_URI_CHECK,
        ):
            errors.append(uri_error)

        post_body: Any = site.get(SITE_KEY_POST_BODY)
        if post_body is not None and not isinstance(post_body, str):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_POST_BODY,
                    f"Invalid {SITE_KEY_POST_BODY}: "
                    f"must be string or None, "
                    f"got {type(post_body).__name__}",
                    post_body,
                )
            )

        if isinstance(post_body, str) and post_body:
            if ACCOUNT_PLACEHOLDER not in post_body:
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        SITE_KEY_POST_BODY,
                        f"Invalid {SITE_KEY_POST_BODY}: "
                        f"must contain '{ACCOUNT_PLACEHOLDER}'",
                        post_body,
                    )
                )
            if site.get(SITE_KEY_HEADERS) is None:
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        SITE_KEY_POST_BODY,
                        f"Invalid {SITE_KEY_POST_BODY}: "
                        f"when {SITE_KEY_POST_BODY} is provided, "
                        f"{SITE_KEY_HEADERS} is required",
                        post_body,
                    )
                )
        elif isinstance(uri_check, str) and ACCOUNT_PLACEHOLDER not in uri_check:
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: "
                    f"must contain '{ACCOUNT_PLACEHOLDER}' "
                    f"when {SITE_KEY_POST_BODY} is not provided",
                    uri_check,
                )
            )

        return errors

    @staticmethod
    def _validate_site_uri_pretty(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate uri_pretty type and http/https URL when present."""
        uri_pretty: Any = site.get(SITE_KEY_URI_PRETTY)
        if uri_pretty is None:
            return []

        if not isinstance(uri_pretty, str):
            return [
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_URI_PRETTY,
                    f"Invalid {SITE_KEY_URI_PRETTY}: "
                    f"must be string, got {type(uri_pretty).__name__}",
                    uri_pretty,
                ),
            ]

        if uri_error := WMNValidator._validate_http_uri(
            uri_pretty,
            base_path=base_path,
            field_key=SITE_KEY_URI_PRETTY,
        ):
            return [uri_error]
        return []

    @staticmethod
    def _validate_site_headers(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate headers types when present."""
        errors: list[WMNError] = []

        headers: Any = site.get(SITE_KEY_HEADERS)
        if headers is None:
            return errors

        if not isinstance(headers, dict):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_HEADERS,
                    f"Invalid {SITE_KEY_HEADERS}: "
                    f"must be dict or None, "
                    f"got {type(headers).__name__}",
                    headers,
                )
            )
            return errors

        for header_key, header_value in headers.items():
            if not isinstance(header_key, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f'{SITE_KEY_HEADERS}["{header_key}"]',
                        f"Invalid {SITE_KEY_HEADERS} key: "
                        f"must be string, "
                        f"got {type(header_key).__name__}",
                        header_key,
                    )
                )
            if not isinstance(header_value, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f'{SITE_KEY_HEADERS}["{header_key}"]',
                        f"Invalid {SITE_KEY_HEADERS} value "
                        f"for key '{header_key}': must be string, "
                        f"got {type(header_value).__name__}",
                        header_value,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_strip_bad_char(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate strip_bad_char type when present."""
        strip_bad_char: Any = site.get(SITE_KEY_STRIP_BAD_CHAR)
        if strip_bad_char is not None and not isinstance(strip_bad_char, str):
            return [
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_STRIP_BAD_CHAR,
                    f"Invalid {SITE_KEY_STRIP_BAD_CHAR}: "
                    f"must be string or None, "
                    f"got {type(strip_bad_char).__name__}",
                    strip_bad_char,
                ),
            ]
        return []

    @staticmethod
    def _validate_site_codes(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate e_code and m_code types and HTTP status code range."""
        errors: list[WMNError] = []

        for key in (SITE_KEY_E_CODE, SITE_KEY_M_CODE):
            code_value: Any = site.get(key)
            if type(code_value) is not int:
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        key,
                        f"Invalid {key}: must be integer, "
                        f"got {type(code_value).__name__}",
                        code_value,
                    )
                )
            elif not (HTTP_STATUS_CODE_MIN <= code_value <= HTTP_STATUS_CODE_MAX):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        key,
                        f"Invalid {key}: must be valid HTTP status code "
                        f"({HTTP_STATUS_CODE_MIN}-{HTTP_STATUS_CODE_MAX}), "
                        f"got {code_value}",
                        code_value,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_strings(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate e_string and m_string types."""
        errors: list[WMNError] = []

        for key in (SITE_KEY_E_STRING, SITE_KEY_M_STRING):
            string_value: Any = site.get(key)
            if not isinstance(string_value, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        key,
                        f"Invalid {key}: must be string, "
                        f"got {type(string_value).__name__}",
                        string_value,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_known(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate known usernames list types."""
        errors: list[WMNError] = []

        known: Any = site.get(SITE_KEY_KNOWN)
        if not isinstance(known, list):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_KNOWN,
                    f"Invalid {SITE_KEY_KNOWN}: must be array, "
                    f"got {type(known).__name__}",
                    known,
                )
            )
            return errors

        for index, item in enumerate(known):
            if not isinstance(item, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_KNOWN}[{index}]",
                        f"Invalid {SITE_KEY_KNOWN} item at "
                        f"index {index}: must be string, "
                        f"got {type(item).__name__}",
                        item,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_category(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate site category type."""
        category: Any = site.get(SITE_KEY_CATEGORY)
        if not isinstance(category, str):
            return [
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_CATEGORY,
                    f"Invalid {SITE_KEY_CATEGORY}: must be string, "
                    f"got {type(category).__name__}",
                    category,
                ),
            ]
        return []

    @staticmethod
    def _validate_site_protection(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate protection list types when present."""
        errors: list[WMNError] = []

        protection: Any = site.get(SITE_KEY_PROTECTION)
        if protection is None:
            return errors

        if not isinstance(protection, list):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_PROTECTION,
                    f"Invalid {SITE_KEY_PROTECTION}: must be array, "
                    f"got {type(protection).__name__}",
                    protection,
                )
            )
            return errors

        for index, item in enumerate(protection):
            if not isinstance(item, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_PROTECTION}[{index}]",
                        f"Invalid {SITE_KEY_PROTECTION} item at "
                        f"index {index}: must be string, "
                        f"got {type(item).__name__}",
                        item,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_valid(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate valid field type when present."""
        valid: Any = site.get(SITE_KEY_VALID)
        if valid is not None and type(valid) is not bool:
            return [
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_VALID,
                    f"Invalid {SITE_KEY_VALID}: must be boolean, "
                    f"got {type(valid).__name__}",
                    valid,
                ),
            ]
        return []

    @staticmethod
    def _validate_site(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate a single site configuration."""
        errors: list[WMNError] = []

        name: Any = site.get(SITE_KEY_NAME)
        if not isinstance(name, str):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: "
                    f"must be string, got {type(name).__name__}",
                    name,
                )
            )

        missing = [key for key in WMN_REQUIRED_KEYS if key not in site]
        if missing:
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    "",
                    f"Missing required keys: {missing}",
                    site,
                )
            )

        errors.extend(WMNValidator._validate_site_uri_body(site, base_path))
        errors.extend(WMNValidator._validate_site_uri_pretty(site, base_path))
        errors.extend(WMNValidator._validate_site_headers(site, base_path))
        errors.extend(WMNValidator._validate_site_strip_bad_char(site, base_path))
        errors.extend(WMNValidator._validate_site_codes(site, base_path))
        errors.extend(WMNValidator._validate_site_strings(site, base_path))
        errors.extend(WMNValidator._validate_site_known(site, base_path))
        errors.extend(WMNValidator._validate_site_category(site, base_path))
        errors.extend(WMNValidator._validate_site_protection(site, base_path))
        errors.extend(WMNValidator._validate_site_valid(site, base_path))
        return errors

    @staticmethod
    def _validate_duplicates(sites_data: list[Any]) -> list[WMNError]:
        """Validate that site names are unique across the sites array."""
        name_indices: dict[str, list[int]] = defaultdict(list)
        for index, site in enumerate(sites_data):
            if not isinstance(site, dict):
                continue
            name: Any = site.get(SITE_KEY_NAME)
            if not isinstance(name, str):
                continue
            name_indices[name].append(index)

        errors: list[WMNError] = []
        for site_name, indices in name_indices.items():
            if len(indices) > 1:
                errors.extend(
                    WMNValidator._site_error(
                        f"$.{WMN_KEY_SITES}[{index}]",
                        SITE_KEY_NAME,
                        (
                            f"Duplicate site name found: '{site_name}' "
                            f"(appears {len(indices)} times)"
                        ),
                        sites_data[index],
                    )
                    for index in indices
                )
        return errors

    @staticmethod
    def _validate_sites(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate all site configurations."""
        if WMN_KEY_SITES not in data:
            return [
                WMNValidator._error(
                    f"$.{WMN_KEY_SITES}",
                    f"Missing required key: {WMN_KEY_SITES}",
                ),
            ]

        sites_data: Any = data[WMN_KEY_SITES]
        if not isinstance(sites_data, list):
            return [
                WMNValidator._error(
                    f"$.{WMN_KEY_SITES}",
                    (
                        f"Invalid {WMN_KEY_SITES}: must be array, "
                        f"got {type(sites_data).__name__}"
                    ),
                    sites_data,
                ),
            ]

        errors: list[WMNError] = []
        errors.extend(WMNValidator._validate_duplicates(sites_data))
        for index, site in enumerate(sites_data):
            base_path = f"$.{WMN_KEY_SITES}[{index}]"
            if not isinstance(site, dict):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        "",
                        (
                            f"Invalid {WMN_KEY_SITES} item at index {index}: "
                            f"must be object, got {type(site).__name__}"
                        ),
                        site,
                    ),
                )
                continue
            site_errors = WMNValidator._validate_site(site, base_path)
            if site_errors:
                name: Any = site.get(SITE_KEY_NAME)
                label = name if isinstance(name, str) else base_path
                msgs = [e.message for e in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    label,
                    "; ".join(msgs),
                )
                errors.extend(site_errors)
        return errors
