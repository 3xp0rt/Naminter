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
from naminter.core.models import WMN_REQUIRED_KEYS, WMNDataset, WMNError

logger = logging.getLogger(__name__)


class WMNValidator:
    """Validates WMN dataset against JSON Schema."""

    __slots__ = ("schema", "validator")

    def __init__(self, schema: Mapping[str, Any]) -> None:
        """Initialize validator with schema.

        Args:
            schema: JSON Schema to validate against. Must not be empty.

        Raises:
            WMNSchemaError: If the provided schema is empty, invalid, or cannot be used.
        """
        self.schema = dict(schema)
        if not self.schema:
            msg = "Schema cannot be empty"
            raise WMNSchemaError(msg)
        try:
            validator_cls = validator_for(self.schema)
            validator_cls.check_schema(self.schema)
            self.validator: Validator = validator_cls(self.schema)
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
            List of schema validation errors.
        """
        errors: list[WMNError] = []
        data_dict = cast("dict[str, Any]", dict(data))
        for error in self.validator.iter_errors(data_dict):
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
        duplicate site names, and individual site configurations.
        Does not use JSON schema because the external schema may not cover
        all validation rules and does not guarantee reliable validation.

        Args:
            data: WMN dataset to validate. This will not be modified.

        Returns:
            List of validation errors. Empty list if validation passes.
        """
        errors: list[WMNError] = []
        errors.extend(WMNValidator._validate_license(data))
        errors.extend(WMNValidator._validate_authors(data))
        errors.extend(WMNValidator._validate_categories(data))
        errors.extend(WMNValidator._validate_duplicates(data))
        errors.extend(WMNValidator._validate_sites(data))
        return errors

    @staticmethod
    def _preview(value: object) -> str | None:
        """Generate JSON preview of a value.

        Args:
            value: Value to preview.

        Returns:
            JSON string preview or None if generation fails.
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
        """Validate that site names are unique and return errors if duplicates found.

        Args:
            data: WMN dataset to check.

        Returns:
            List of duplicate site errors.
        """
        sites_data: Any = data.get("sites", [])
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
            List of license validation errors.
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
    def _validate_authors(data: WMNDataset) -> list[WMNError]:
        """Validate authors field.

        Args:
            data: WMN dataset to check.

        Returns:
            List of authors validation errors.
        """
        errors: list[WMNError] = []
        authors_data: Any = data.get("authors")

        if not isinstance(authors_data, list):
            errors.append(
                WMNError(
                    path=f"$.{WMN_KEY_AUTHORS}",
                    data=WMNValidator._preview(authors_data),
                    message=f"Invalid {WMN_KEY_AUTHORS}: must be array, got {type(authors_data).__name__}",
                ),
            )
        else:
            authors_list: list[Any] = cast("list[Any]", authors_data)
            if not authors_list:
                errors.append(
                    WMNError(
                        path=f"$.{WMN_KEY_AUTHORS}",
                        data=WMNValidator._preview(authors_list),
                        message=f"Invalid {WMN_KEY_AUTHORS}: must have at least 1 item",
                    ),
                )

            authors_set: set[str] = set()
            for index, author in enumerate(authors_list):
                if not isinstance(author, str):
                    errors.append(
                        WMNError(
                            path=f"$.{WMN_KEY_AUTHORS}[{index}]",
                            data=WMNValidator._preview(author),
                            message=f"Invalid {WMN_KEY_AUTHORS} item at index {index}: must be string, got {type(author).__name__}",
                        ),
                    )
                elif not author.strip():
                    errors.append(
                        WMNError(
                            path=f"$.{WMN_KEY_AUTHORS}[{index}]",
                            data=WMNValidator._preview(author),
                            message=f"Invalid {WMN_KEY_AUTHORS} item at index {index}: must be non-empty string",
                        ),
                    )
                else:
                    if author in authors_set:
                        errors.append(
                            WMNError(
                                path=f"$.{WMN_KEY_AUTHORS}[{index}]",
                                data=WMNValidator._preview(author),
                                message=f"Duplicate {WMN_KEY_AUTHORS} item: '{author}'",
                            ),
                        )
                    authors_set.add(author)

        return errors

    @staticmethod
    def _validate_categories(data: WMNDataset) -> list[WMNError]:
        """Validate categories field.

        Args:
            data: WMN dataset to check.

        Returns:
            List of categories validation errors.
        """
        errors: list[WMNError] = []
        categories_data: Any = data.get("categories")

        if not isinstance(categories_data, list):
            errors.append(
                WMNError(
                    path=f"$.{WMN_KEY_CATEGORIES}",
                    data=WMNValidator._preview(categories_data),
                    message=f"Invalid {WMN_KEY_CATEGORIES}: must be array, got {type(categories_data).__name__}",
                ),
            )
        else:
            categories_list: list[Any] = cast("list[Any]", categories_data)
            if not categories_list:
                errors.append(
                    WMNError(
                        path=f"$.{WMN_KEY_CATEGORIES}",
                        data=WMNValidator._preview(categories_list),
                        message=f"Invalid {WMN_KEY_CATEGORIES}: must have at least 1 item",
                    ),
                )

            categories_set: set[str] = set()
            for index, category in enumerate(categories_list):
                if not isinstance(category, str):
                    errors.append(
                        WMNError(
                            path=f"$.{WMN_KEY_CATEGORIES}[{index}]",
                            data=WMNValidator._preview(category),
                            message=f"Invalid {WMN_KEY_CATEGORIES} item at index {index}: must be string, got {type(category).__name__}",
                        ),
                    )
                elif not category.strip():
                    errors.append(
                        WMNError(
                            path=f"$.{WMN_KEY_CATEGORIES}[{index}]",
                            data=WMNValidator._preview(category),
                            message=f"Invalid {WMN_KEY_CATEGORIES} item at index {index}: must be non-empty string",
                        ),
                    )
                else:
                    if category in categories_set:
                        errors.append(
                            WMNError(
                                path=f"$.{WMN_KEY_CATEGORIES}[{index}]",
                                data=WMNValidator._preview(category),
                                message=f"Duplicate {WMN_KEY_CATEGORIES} item: '{category}'",
                            ),
                        )
                    categories_set.add(category)

        return errors

    @staticmethod
    def _validate_sites(data: WMNDataset) -> list[WMNError]:
        """Validate all site configurations.

        Args:
            data: WMN dataset containing sites to validate.

        Returns:
            List of validation errors. Empty if all sites are valid.
        """
        errors: list[WMNError] = []
        sites_data_raw: Any = data.get("sites", [])

        if not isinstance(sites_data_raw, list):
            errors.append(
                WMNError(
                    path=f"$.{WMN_KEY_SITES}",
                    data=WMNValidator._preview(sites_data_raw),
                    message=f"Invalid {WMN_KEY_SITES}: must be array, got {type(sites_data_raw).__name__}",
                ),
            )
            return errors

        sites_data: list[Any] = cast("list[Any]", sites_data_raw)
        for index, site in enumerate(sites_data):
            if not isinstance(site, dict):
                errors.append(
                    WMNError(
                        path=f"$.{WMN_KEY_SITES}[{index}]",
                        data=WMNValidator._preview(site),
                        message=f"Invalid site at index {index}: must be object, got {type(site).__name__}",
                    ),
                )
                continue

            site_dict: dict[str, Any] = cast("dict[str, Any]", site)
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

            # Validate site name first
            site_name_raw: Any = site_dict.get(SITE_KEY_NAME)
            if not isinstance(site_name_raw, str):
                _create_error(
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: must be string, got {type(site_name_raw).__name__}",
                    site_name_raw,
                )
                site_name = "unknown"
            elif not site_name_raw.strip():
                _create_error(
                    SITE_KEY_NAME,
                    f"Invalid {SITE_KEY_NAME}: must be non-empty string",
                    site_name_raw,
                )
                site_name = "unknown"
            else:
                site_name = site_name_raw

            missing_keys = [key for key in WMN_REQUIRED_KEYS if key not in site_dict]
            if missing_keys:
                _create_error("", f"Missing required keys: {missing_keys}", site_dict)
                error_messages = [error.message for error in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    site_name,
                    "; ".join(error_messages),
                )
                errors.extend(site_errors)
                continue

            uri_check: Any = site_dict.get(SITE_KEY_URI_CHECK)
            if not isinstance(uri_check, str) or not uri_check:
                _create_error(
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: must be non-empty string",
                    uri_check,
                )

            post_body: Any = site_dict.get(SITE_KEY_POST_BODY)
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
                    if site_dict.get(SITE_KEY_HEADERS) is None:
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

            headers: Any = site_dict.get(SITE_KEY_HEADERS)
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

            strip_bad_char: Any = site_dict.get(SITE_KEY_STRIP_BAD_CHAR)
            if strip_bad_char is not None and not isinstance(strip_bad_char, str):
                _create_error(
                    SITE_KEY_STRIP_BAD_CHAR,
                    f"Invalid {SITE_KEY_STRIP_BAD_CHAR}: must be string or None, "
                    f"got {type(strip_bad_char).__name__}",
                    strip_bad_char,
                )

            for key in (SITE_KEY_E_CODE, SITE_KEY_M_CODE):
                code_value: Any = site_dict.get(key)
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
                string_value: Any = site_dict.get(key)
                if not isinstance(string_value, str):
                    _create_error(
                        key,
                        f"Invalid {key}: must be string, got {type(string_value).__name__}",
                        string_value,
                    )

            known: Any = site_dict.get(SITE_KEY_KNOWN)
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
                    site_name,
                    "; ".join(error_messages),
                )
                errors.extend(site_errors)

        return errors
