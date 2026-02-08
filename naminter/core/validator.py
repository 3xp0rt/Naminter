from collections import defaultdict
from collections.abc import Mapping
import orjson
import logging
from typing import Any, cast

from jsonschema.exceptions import SchemaError as JsonSchemaError
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for

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
from naminter.core.models import WMN_REQUIRED_KEYS, WMNDataset, WMNError, WMNSite

logger = logging.getLogger(__name__)


class WMNValidator:
    """Validates WMN dataset against JSON Schema."""

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

    def validate_schema(self, data: WMNDataset) -> list[WMNError]:
        """Validate dataset against JSON schema and return errors.

        Args:
            data: WMN dataset to validate.

        Returns:
            list[WMNError]: Schema validation errors, empty if valid.
        """
        errors: list[WMNError] = []
        data_dict = cast("dict[str, Any]", dict(data))
        for error in self._validator.iter_errors(data_dict):
            validation_error: ValidationError = error
            data_preview = WMNValidator._preview(validation_error.instance)
            errors.append(
                WMNError(
                    path=str(validation_error.json_path),
                    data=data_preview,
                    message=str(validation_error.message),
                ),
            )
        return errors

    @staticmethod
    def validate_dataset(data: WMNDataset) -> list[WMNError]:
        """Validate dataset fields with custom rules and return list of errors.

        Performs code-based validation for license, authors, categories,
        and duplicate site names. Does not use JSON schema.

        Args:
            data: WMN dataset to validate. This will not be modified.

        Returns:
            list[WMNError]: Validation errors, empty if valid.
        """
        errors: list[WMNError] = []
        errors.extend(WMNValidator._validate_license(data))
        errors.extend(WMNValidator._validate_authors(data))
        errors.extend(WMNValidator._validate_categories(data))
        errors.extend(WMNValidator._validate_duplicates(data))

        sites_data: Any = data.get(WMN_KEY_SITES, [])
        if isinstance(sites_data, list):
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
    def _validate_duplicates(data: WMNDataset) -> list[WMNError]:
        """Validate that site names are unique.

        Args:
            data: WMN dataset to check.

        Returns:
            list[WMNError]: Duplicate site name errors.
        """
        sites_data: Any = data.get(WMN_KEY_SITES, [])
        if not isinstance(sites_data, list):
            return []

        sites_data_list: list[Any] = cast("list[Any]", sites_data)
        name_indices: dict[str, list[int]] = defaultdict(list)
        for index, site in enumerate(sites_data_list):
            if not isinstance(site, dict):
                continue
            site_dict: dict[str, Any] = cast("dict[str, Any]", site)
            name: Any = site_dict.get(SITE_KEY_NAME)
            if not isinstance(name, str) or not name:
                continue
            name_indices[name].append(index)

        errors: list[WMNError] = []
        for site_name, indices in name_indices.items():
            if len(indices) > 1:
                for index in indices:
                    path_string = f"$.{WMN_KEY_SITES}[{index}].{SITE_KEY_NAME}"
                    data_preview = WMNValidator._preview(sites_data_list[index])

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
    def _validate_license(data: WMNDataset) -> list[WMNError]:
        """Validate license field.

        Args:
            data: WMN dataset to check.

        Returns:
            list[WMNError]: License validation errors.
        """
        errors: list[WMNError] = []
        license_data: Any = data.get("license")

        if not isinstance(license_data, list):
            errors.append(
                WMNError(
                    path=f"$.{WMN_KEY_LICENSE}",
                    data=WMNValidator._preview(license_data),
                    message=f"Invalid {WMN_KEY_LICENSE}: must be array, got {type(license_data).__name__}",
                ),
            )

        return errors

    @staticmethod
    def _validate_string_list(data: WMNDataset, field_key: str) -> list[WMNError]:
        """Validate a field that must be a non-empty list of unique non-empty strings.

        Args:
            data: WMN dataset to check.
            field_key: The key name of the field to validate (e.g., 'authors', 'categories').

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
                    message=f"Invalid {field_key}: must be array, got {type(field_data).__name__}",
                ),
            )
        else:
            field_list: list[Any] = cast("list[Any]", field_data)
            if not field_list:
                errors.append(
                    WMNError(
                        path=f"$.{field_key}",
                        data=WMNValidator._preview(field_list),
                        message=f"Invalid {field_key}: must have at least 1 item",
                    ),
                )

            seen: set[str] = set()
            for index, item in enumerate(field_list):
                if not isinstance(item, str):
                    errors.append(
                        WMNError(
                            path=f"$.{field_key}[{index}]",
                            data=WMNValidator._preview(item),
                            message=f"Invalid {field_key} item at index {index}: must be string, got {type(item).__name__}",
                        ),
                    )
                elif not item.strip():
                    errors.append(
                        WMNError(
                            path=f"$.{field_key}[{index}]",
                            data=WMNValidator._preview(item),
                            message=f"Invalid {field_key} item at index {index}: must be non-empty string",
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
    def _validate_authors(data: WMNDataset) -> list[WMNError]:
        """Validate authors field.

        Args:
            data: WMN dataset to check.

        Returns:
            list[WMNError]: Authors validation errors.
        """
        return WMNValidator._validate_string_list(data, WMN_KEY_AUTHORS)

    @staticmethod
    def _validate_categories(data: WMNDataset) -> list[WMNError]:
        """Validate categories field.

        Args:
            data: WMN dataset to check.

        Returns:
            list[WMNError]: Categories validation errors.
        """
        return WMNValidator._validate_string_list(data, WMN_KEY_CATEGORIES)

    @staticmethod
    def _validate_sites(sites: list[WMNSite]) -> list[WMNError]:
        """Validate all site configurations.

        Args:
            sites: List of site configurations to validate.

        Returns:
            list[WMNError]: Validation errors, empty if all sites are valid.
        """
        errors: list[WMNError] = []

        for index, site in enumerate(sites):
            base_path = f"$.{WMN_KEY_SITES}[{index}]"
            site_errors: list[WMNError] = []

            def _create_error(
                path_suffix: str,
                message: str,
                data: object | None = None,
            ) -> None:
                """Helper to create WMNError with path and data."""
                path = f"{base_path}.{path_suffix}" if path_suffix else base_path
                data_preview = WMNValidator._preview(data)
                error = WMNError(path=path, data=data_preview, message=message)
                site_errors.append(error)

            name: Any = site.get(SITE_KEY_NAME)
            if not isinstance(name, str):
                _create_error(
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: must be string, got {type(name).__name__}",
                    name,
                )
            elif not name.strip():
                _create_error(
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: must be non-empty string",
                    name,
                )

            site_label = name if isinstance(name, str) and name.strip() else base_path

            missing_keys = [key for key in WMN_REQUIRED_KEYS if key not in site]
            if missing_keys:
                _create_error("", f"Missing required keys: {missing_keys}", site)
                error_messages = [error.message for error in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    site_label,
                    "; ".join(error_messages),
                )
                errors.extend(site_errors)
                continue

            uri_check: Any = site.get(SITE_KEY_URI_CHECK)
            if not isinstance(uri_check, str) or not uri_check:
                _create_error(
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: must be non-empty string",
                    uri_check,
                )

            post_body: Any = site.get(SITE_KEY_POST_BODY)
            if post_body is not None:
                if not isinstance(post_body, str):
                    _create_error(
                        SITE_KEY_POST_BODY,
                        f"Invalid {SITE_KEY_POST_BODY}: must be string or None, "
                        f"got {type(post_body).__name__}",
                        post_body,
                    )
                elif post_body:
                    if ACCOUNT_PLACEHOLDER not in post_body:
                        _create_error(
                            SITE_KEY_POST_BODY,
                            f"Invalid {SITE_KEY_POST_BODY}: must contain '{ACCOUNT_PLACEHOLDER}'",
                            post_body,
                        )
                    if site.get(SITE_KEY_HEADERS) is None:
                        _create_error(
                            SITE_KEY_POST_BODY,
                            f"Invalid {SITE_KEY_POST_BODY}: when {SITE_KEY_POST_BODY} is provided, "
                            f"{SITE_KEY_HEADERS} is required",
                            post_body,
                        )
            else:
                if isinstance(uri_check, str) and ACCOUNT_PLACEHOLDER not in uri_check:
                    _create_error(
                        SITE_KEY_URI_CHECK,
                        f"Invalid {SITE_KEY_URI_CHECK}: must contain '{ACCOUNT_PLACEHOLDER}' "
                        f"when {SITE_KEY_POST_BODY} is not provided",
                        uri_check,
                    )

            headers: Any = site.get(SITE_KEY_HEADERS)
            if headers is not None:
                if not isinstance(headers, dict):
                    _create_error(
                        SITE_KEY_HEADERS,
                        f"Invalid {SITE_KEY_HEADERS}: must be dict or None, "
                        f"got {type(headers).__name__}",
                        headers,
                    )
                else:
                    headers_dict: dict[Any, Any] = cast("dict[Any, Any]", headers)
                    for header_key, header_value in headers_dict.items():
                        if not isinstance(header_key, str):
                            _create_error(
                                f"{SITE_KEY_HEADERS}.{header_key}",
                                f"Invalid {SITE_KEY_HEADERS} key: must be string, "
                                f"got {type(header_key).__name__}",
                                header_key,
                            )
                        if not isinstance(header_value, str):
                            _create_error(
                                f"{SITE_KEY_HEADERS}[{header_key}]",
                                f"Invalid {SITE_KEY_HEADERS} value for key '{header_key}': "
                                f"must be string, got {type(header_value).__name__}",
                                header_value,
                            )

            strip_bad_char: Any = site.get(SITE_KEY_STRIP_BAD_CHAR)
            if strip_bad_char is not None and not isinstance(strip_bad_char, str):
                _create_error(
                    SITE_KEY_STRIP_BAD_CHAR,
                    f"Invalid {SITE_KEY_STRIP_BAD_CHAR}: must be string or None, "
                    f"got {type(strip_bad_char).__name__}",
                    strip_bad_char,
                )

            for key in (SITE_KEY_E_CODE, SITE_KEY_M_CODE):
                code_value: Any = site.get(key)
                if not isinstance(code_value, int):
                    _create_error(
                        key,
                        f"Invalid {key}: must be integer, got {type(code_value).__name__}",
                        code_value,
                    )
                elif not (HTTP_STATUS_CODE_MIN <= code_value <= HTTP_STATUS_CODE_MAX):
                    _create_error(
                        key,
                        f"Invalid {key}: must be valid HTTP status code "
                        f"({HTTP_STATUS_CODE_MIN}-{HTTP_STATUS_CODE_MAX}), got {code_value}",
                        code_value,
                    )

            for key in (SITE_KEY_E_STRING, SITE_KEY_M_STRING):
                string_value: Any = site.get(key)
                if not isinstance(string_value, str):
                    _create_error(
                        key,
                        f"Invalid {key}: must be string, got {type(string_value).__name__}",
                        string_value,
                    )

            known: Any = site.get(SITE_KEY_KNOWN)
            if not isinstance(known, list):
                msg = (
                    f"Invalid {SITE_KEY_KNOWN}: must be list, "
                    f"got {type(known).__name__}"
                )
                _create_error(SITE_KEY_KNOWN, msg, known)
            else:
                known_list: list[Any] = cast("list[Any]", known)
                for known_index, item in enumerate(known_list):
                    if not isinstance(item, str):
                        _create_error(
                            f"{SITE_KEY_KNOWN}[{known_index}]",
                            f"Invalid {SITE_KEY_KNOWN} item at index {known_index}: "
                            f"must be string, got {type(item).__name__}",
                            item,
                        )
                    elif not item.strip():
                        _create_error(
                            f"{SITE_KEY_KNOWN}[{known_index}]",
                            f"Invalid {SITE_KEY_KNOWN} item at index {known_index}: "
                            f"must be non-empty string",
                            item,
                        )

            if site_errors:
                error_messages = [error.message for error in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    site_label,
                    "; ".join(error_messages),
                )
                errors.extend(site_errors)

        return errors
