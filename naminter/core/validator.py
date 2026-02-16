"""WMN dataset validator using JSON Schema and custom validation rules."""

from __future__ import annotations

from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any, cast

from jsonschema.exceptions import SchemaError as JsonSchemaError
from jsonschema.exceptions import ValidationError
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
from naminter.core.models import WMN_REQUIRED_KEYS, WMNDataset, WMNError, WMNSite

if TYPE_CHECKING:
    from collections.abc import Mapping

    from jsonschema.protocols import Validator

logger = logging.getLogger(__name__)


class WMNValidator:
    """Validates WMN dataset against JSON Schema and custom rules."""

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
        duplicate site names, and individual site configurations
        (uri_check, post_body, headers, status codes, known usernames, etc.).
        Does not use JSON schema.

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
                    message=(
                        f"Invalid {WMN_KEY_LICENSE}: must be array, "
                        f"got {type(license_data).__name__}"
                    ),
                ),
            )

        return errors

    @staticmethod
    def _validate_string_list(data: WMNDataset, field_key: str) -> list[WMNError]:
        """Validate a field as a non-empty list of unique non-empty strings.

        Args:
            data: WMN dataset to check.
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
        site: WMNSite,
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
        site: WMNSite,
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
        if not isinstance(uri_check, str) or not uri_check:
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
    def _validate_site_headers(
        site: WMNSite,
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

        headers_dict: dict[Any, Any] = cast(
            "dict[Any, Any]",
            headers,
        )
        for hdr_key, hdr_val in headers_dict.items():
            if not isinstance(hdr_key, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_HEADERS}.{hdr_key}",
                        f"Invalid {SITE_KEY_HEADERS} key: "
                        f"must be string, "
                        f"got {type(hdr_key).__name__}",
                        hdr_key,
                    )
                )
            if not isinstance(hdr_val, str):
                errors.append(
                    WMNValidator._site_error(
                        base_path,
                        f"{SITE_KEY_HEADERS}[{hdr_key}]",
                        f"Invalid {SITE_KEY_HEADERS} value "
                        f"for key '{hdr_key}': must be string, "
                        f"got {type(hdr_val).__name__}",
                        hdr_val,
                    )
                )

        return errors

    @staticmethod
    def _validate_site_codes(
        site: WMNSite,
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
        site: WMNSite,
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
        site: WMNSite,
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

        known_list: list[Any] = cast("list[Any]", known)
        for idx, item in enumerate(known_list):
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
