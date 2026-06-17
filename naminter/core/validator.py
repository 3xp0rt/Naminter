"""WMN data validator using JSON Schema and custom validation rules."""

from __future__ import annotations

from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any

from jsonschema.exceptions import SchemaError as JsonSchemaError
from jsonschema.validators import validator_for
import orjson

from naminter.core.constants import (
    ACCOUNT_PLACEHOLDER,
    HTTP_STATUS_CODE_MAX,
    HTTP_STATUS_CODE_MIN,
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
    WMN_KEY_AUTHORS,
    WMN_KEY_CATEGORIES,
    WMN_KEY_LICENSE,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import WMNSchemaError
from naminter.core.models import WMN_REQUIRED_KEYS, WMNError

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
        """Validate data against JSON schema and return errors.

        Args:
            data: WMN data to validate.

        Returns:
            list[WMNError]: Schema validation errors, empty if valid.
        """
        errors: list[WMNError] = []
        for error in self._validator.iter_errors(dict(data)):
            data_preview = WMNValidator._preview(error.instance)
            errors.append(
                WMNError(
                    path=str(error.json_path),
                    data=data_preview,
                    message=str(error.message),
                ),
            )
        return errors

    @staticmethod
    def validate_data(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate data fields with custom rules and return list of errors.

        Performs code-based validation for license, authors, categories,
        duplicate site names, and individual site configurations
        (uri_check, post_body, headers, status codes, known usernames, etc.).
        Does not use JSON schema.

        Args:
            data: WMN data to validate. This will not be modified.

        Returns:
            list[WMNError]: Validation errors, empty if valid.
        """
        errors: list[WMNError] = []
        errors.extend(WMNValidator._validate_license(data))
        errors.extend(WMNValidator._validate_authors(data))
        errors.extend(WMNValidator._validate_categories(data))

        sites_data: Any = data.get(WMN_KEY_SITES, [])
        if isinstance(sites_data, list):
            errors.extend(WMNValidator._validate_duplicates(sites_data))
            errors.extend(WMNValidator._validate_sites(sites_data))

        return errors

    @staticmethod
    def _preview(value: object) -> str | None:
        """Generate JSON preview of a value.

        Args:
            value: Value to preview.

        Returns:
            str | None: JSON string preview, or None if generation fails.
        """
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
    def _validate_duplicates(sites_data: list[Any]) -> list[WMNError]:
        """Validate that site names are unique.

        Args:
            sites_data: Site list from the WMN data.

        Returns:
            list[WMNError]: Duplicate site name errors.
        """
        name_indices: dict[str, list[int]] = defaultdict(list)
        for index, site in enumerate(sites_data):
            if not isinstance(site, dict):
                continue
            name: Any = site.get(SITE_KEY_NAME)
            if not isinstance(name, str) or not name:
                continue
            name_indices[name].append(index)

        errors: list[WMNError] = []
        for site_name, indices in name_indices.items():
            if len(indices) > 1:
                for index in indices:
                    path_string = f"$.{WMN_KEY_SITES}[{index}].{SITE_KEY_NAME}"
                    data_preview = WMNValidator._preview(sites_data[index])

                    errors.append(
                        WMNError(
                            path=path_string,
                            data=data_preview,
                            message=(
                                f"Duplicate site name found: '{site_name}' "
                                f"(appears {len(indices)} times)"
                            ),
                        ),
                    )
        return errors

    @staticmethod
    def _validate_license(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate license field.

        Args:
            data: WMN data to check.

        Returns:
            list[WMNError]: License validation errors.
        """
        errors: list[WMNError] = []
        license_data: Any = data.get(WMN_KEY_LICENSE)

        if not isinstance(license_data, list):
            errors.append(
                WMNError(
                    path=f"$.{WMN_KEY_LICENSE}",
                    data=WMNValidator._preview(license_data),
                    message=(
                        f"Invalid {WMN_KEY_LICENSE}: must be array, "
                        f"got {type(license_data).__name__}"
                    ),
                ),
            )

        return errors

    @staticmethod
    def _validate_string_list(
        data: Mapping[str, Any],
        field_key: str,
    ) -> list[WMNError]:
        """Validate a field as a non-empty list of unique non-empty strings.

        Args:
            data: WMN data to check.
            field_key: The key name of the field to validate.

        Returns:
            list[WMNError]: Validation errors for the field.
        """
        errors: list[WMNError] = []
        field_data: Any = data.get(field_key)

        if not isinstance(field_data, list):
            errors.append(
                WMNError(
                    path=f"$.{field_key}",
                    data=WMNValidator._preview(field_data),
                    message=(
                        f"Invalid {field_key}: must be array, "
                        f"got {type(field_data).__name__}"
                    ),
                ),
            )
        else:
            if not field_data:
                errors.append(
                    WMNError(
                        path=f"$.{field_key}",
                        data=WMNValidator._preview(field_data),
                        message=f"Invalid {field_key}: must have at least 1 item",
                    ),
                )

            seen: set[str] = set()
            for index, item in enumerate(field_data):
                if not isinstance(item, str):
                    errors.append(
                        WMNError(
                            path=f"$.{field_key}[{index}]",
                            data=WMNValidator._preview(item),
                            message=(
                                f"Invalid {field_key} item at "
                                f"index {index}: must be string, "
                                f"got {type(item).__name__}"
                            ),
                        ),
                    )
                elif not item.strip():
                    errors.append(
                        WMNError(
                            path=f"$.{field_key}[{index}]",
                            data=WMNValidator._preview(item),
                            message=(
                                f"Invalid {field_key} item at "
                                f"index {index}: must be "
                                f"non-empty string"
                            ),
                        ),
                    )
                else:
                    if item in seen:
                        errors.append(
                            WMNError(
                                path=f"$.{field_key}[{index}]",
                                data=WMNValidator._preview(item),
                                message=f"Duplicate {field_key} item: '{item}'",
                            ),
                        )
                    seen.add(item)

        return errors

    @staticmethod
    def _validate_authors(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate authors field.

        Args:
            data: WMN data to check.

        Returns:
            list[WMNError]: Authors validation errors.
        """
        return WMNValidator._validate_string_list(data, WMN_KEY_AUTHORS)

    @staticmethod
    def _validate_categories(data: Mapping[str, Any]) -> list[WMNError]:
        """Validate categories field.

        Args:
            data: WMN data to check.

        Returns:
            list[WMNError]: Categories validation errors.
        """
        return WMNValidator._validate_string_list(data, WMN_KEY_CATEGORIES)

    @staticmethod
    def _site_error(
        base_path: str,
        suffix: str,
        message: str,
        data: object | None = None,
    ) -> WMNError:
        """Create a WMNError for a site validation issue.

        Args:
            base_path: JSON path prefix for the site.
            suffix: JSON path suffix appended to base_path.
            message: Human-readable error description.
            data: Optional offending value for preview.

        Returns:
            WMNError: Constructed validation error.
        """
        path = f"{base_path}.{suffix}" if suffix else base_path
        return WMNError(
            path=path,
            data=WMNValidator._preview(data),
            message=message,
        )

    @staticmethod
    def _validate_sites(sites: list[Any]) -> list[WMNError]:
        """Validate all site configurations.

        Args:
            sites: List of site configurations to validate.

        Returns:
            list[WMNError]: Validation errors, empty if all sites are valid.
        """
        errors: list[WMNError] = []
        for index, site in enumerate(sites):
            base_path = f"$.{WMN_KEY_SITES}[{index}]"
            site_errors = WMNValidator._validate_site(site, base_path)
            if site_errors:
                name: Any = site.get(SITE_KEY_NAME)
                label = name if isinstance(name, str) and name.strip() else base_path
                msgs = [e.message for e in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    label,
                    "; ".join(msgs),
                )
                errors.extend(site_errors)
        return errors

    @staticmethod
    def _validate_site(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate a single site configuration.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for this site.
        """
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
        elif not name.strip():
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: must be non-empty string",
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
            return errors

        errors.extend(
            WMNValidator._validate_site_uri_body(site, base_path),
        )
        errors.extend(
            WMNValidator._validate_site_headers(site, base_path),
        )

        strip_bad_char: Any = site.get(SITE_KEY_STRIP_BAD_CHAR)
        if strip_bad_char is not None and not isinstance(
            strip_bad_char,
            str,
        ):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_STRIP_BAD_CHAR,
                    f"Invalid {SITE_KEY_STRIP_BAD_CHAR}: "
                    f"must be string or None, "
                    f"got {type(strip_bad_char).__name__}",
                    strip_bad_char,
                )
            )

        errors.extend(
            WMNValidator._validate_site_codes(site, base_path),
        )
        errors.extend(
            WMNValidator._validate_site_strings(site, base_path),
        )
        errors.extend(
            WMNValidator._validate_site_known(site, base_path),
        )
        return errors

    @staticmethod
    def _validate_site_uri_body(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate uri_check and post_body fields.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for uri/body fields.
        """
        errors: list[WMNError] = []

        uri_check: Any = site.get(SITE_KEY_URI_CHECK)
        uri_check_valid = isinstance(uri_check, str) and uri_check
        if not uri_check_valid:
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: must be non-empty string",
                    uri_check,
                )
            )

        post_body: Any = site.get(SITE_KEY_POST_BODY)
        if post_body is not None:
            if not isinstance(post_body, str):
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
            elif post_body:
                if ACCOUNT_PLACEHOLDER not in post_body:
                    errors.append(
                        WMNValidator._site_error(
                            base_path,
                            SITE_KEY_POST_BODY,
                            f"Invalid {SITE_KEY_POST_BODY}: "
                            f"must contain "
                            f"'{ACCOUNT_PLACEHOLDER}'",
                            post_body,
                        )
                    )
                if site.get(SITE_KEY_HEADERS) is None:
                    errors.append(
                        WMNValidator._site_error(
                            base_path,
                            SITE_KEY_POST_BODY,
                            f"Invalid {SITE_KEY_POST_BODY}: "
                            f"when {SITE_KEY_POST_BODY} is "
                            f"provided, "
                            f"{SITE_KEY_HEADERS} is required",
                            post_body,
                        )
                    )

        if (
            post_body is None
            and uri_check_valid
            and ACCOUNT_PLACEHOLDER not in uri_check
        ):
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
    def _validate_site_headers(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate headers field.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for headers.
        """
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
                        f"{SITE_KEY_HEADERS}.{header_key}",
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
                        f"{SITE_KEY_HEADERS}[{header_key}]",
                        f"Invalid {SITE_KEY_HEADERS} value "
                        f"for key '{header_key}': must be string, "
                        f"got {type(header_value).__name__}",
                        header_value,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_codes(
        site: Mapping[str, Any],
        base_path: str,
    ) -> list[WMNError]:
        """Validate e_code and m_code fields.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for status code fields.
        """
        errors: list[WMNError] = []

        for key in (SITE_KEY_E_CODE, SITE_KEY_M_CODE):
            code_value: Any = site.get(key)
            if not isinstance(code_value, int):
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
                        f"Invalid {key}: must be valid HTTP "
                        f"status code "
                        f"({HTTP_STATUS_CODE_MIN}"
                        f"-{HTTP_STATUS_CODE_MAX}), "
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
        """Validate e_string and m_string fields.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for string fields.
        """
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
        """Validate known usernames field.

        Args:
            site: Site configuration to validate.
            base_path: JSON path prefix for the site.

        Returns:
            list[WMNError]: Validation errors for known field.
        """
        errors: list[WMNError] = []

        known: Any = site.get(SITE_KEY_KNOWN)
        if not isinstance(known, list):
            errors.append(
                WMNValidator._site_error(
                    base_path,
                    SITE_KEY_KNOWN,
                    f"Invalid {SITE_KEY_KNOWN}: must be list, "
                    f"got {type(known).__name__}",
                    known,
                )
            )
            return errors

        for idx, item in enumerate(known):
            if not isinstance(item, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_KNOWN}[{idx}]",
                        f"Invalid {SITE_KEY_KNOWN} item at "
                        f"index {idx}: must be string, "
                        f"got {type(item).__name__}",
                        item,
                    )
                )
            elif not item.strip():
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_KNOWN}[{idx}]",
                        f"Invalid {SITE_KEY_KNOWN} item at "
                        f"index {idx}: must be "
                        f"non-empty string",
                        item,
                    )
                )

        return errors
