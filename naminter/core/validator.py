import contextlib
from collections import defaultdict
from collections.abc import Mapping, Sequence
import json
import logging
from typing import Any

from jsonschema.exceptions import SchemaError as JsonSchemaError
from jsonschema.validators import validator_for

from naminter.core.constants import (
    DEFAULT_JSON_ENSURE_ASCII,
    DEFAULT_JSON_INDENT,
    SITE_KEY_E_CODE,
    SITE_KEY_E_STRING,
    SITE_KEY_HEADERS,
    SITE_KEY_KNOWN,
    SITE_KEY_M_CODE,
    SITE_KEY_M_STRING,
    SITE_KEY_NAME,
    SITE_KEY_URI_CHECK,
    WMN_KEY_SITES,
)
from naminter.core.exceptions import WMNSchemaError
from naminter.core.models import WMN_REQUIRED_KEYS, WMNDataset, WMNError, WMNSite

logger = logging.getLogger(__name__)


class WMNValidator:
    """Validates WMN dataset against JSON Schema."""

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
            self.validator = validator_cls(self.schema)
        except JsonSchemaError as e:
            msg = f"Invalid JSON schema: {e}"
            raise WMNSchemaError(msg) from e
        except Exception as e:
            msg = f"Failed to initialize JSON schema validator: {e}"
            raise WMNSchemaError(msg) from e

    def validate(self, data: WMNDataset) -> list[WMNError]:
        """Validate dataset and return list of errors.

        Args:
            data: WMN dataset to validate. This will not be modified.

        Returns:
            List of validation errors. Empty list if validation passes.
        """
        errors: list[WMNError] = []
        errors.extend(self._validate_schema(data))
        errors.extend(WMNValidator._validate_duplicates(data))
        return errors

    def _validate_schema(self, data: WMNDataset) -> list[WMNError]:
        """Validate dataset against JSON schema and return errors.

        Args:
            data: WMN dataset to validate.

        Returns:
            List of schema validation errors.
        """
        errors: list[WMNError] = []
        for error in sorted(
            self.validator.iter_errors(data),
            key=lambda err: list(err.absolute_path),
        ):
            data_preview = WMNValidator._preview(error.instance)
            errors.append(
                WMNError(
                    path=error.json_path,
                    data=data_preview,
                    message=error.message,
                ),
            )
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
            return json.dumps(
                value,
                ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
                indent=DEFAULT_JSON_INDENT,
            )
        except (TypeError, ValueError) as e:
            logger.debug(
                "Failed to generate data preview: %s",
                e,
                exc_info=True,
            )
        return None

    @staticmethod
    def _get_missing_keys(data: dict[str, Any], keys: Sequence[str]) -> list[str]:
        """Return a list of required keys missing from a dictionary.

        Args:
            data: Dictionary to check for missing keys.
            keys: Sequence of keys that should be present.

        Returns:
            List of keys that are missing from the dictionary. Empty list if
            all keys are present.
        """
        return [key for key in keys if key not in data]

    @staticmethod
    def _validate_duplicates(data: WMNDataset) -> list[WMNError]:
        """Validate that site names are unique and return errors if duplicates found.

        Args:
            data: WMN dataset to check.

        Returns:
            List of duplicate site errors.
        """
        sites_data = data.get(WMN_KEY_SITES, [])
        if not isinstance(sites_data, list):
            return []

        name_indices: dict[str, list[int]] = defaultdict(list)
        for index, site in enumerate(sites_data):
            if not isinstance(site, dict):
                continue
            raw = site.get(SITE_KEY_NAME)
            if not isinstance(raw, str):
                continue
            name = raw.strip()
            if not name:
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

    def validate_sites(self, sites: list[WMNSite]) -> list[WMNError]:
        """Validate all site configurations.

        Args:
            sites: List of site configurations to validate.

        Returns:
            List of validation errors. Empty if all sites are valid.
        """
        errors: list[WMNError] = []

        for index, site in enumerate(sites):
            base_path = f"$.{WMN_KEY_SITES}[{index}]"
            site_name = site.get(SITE_KEY_NAME, "unknown")
            site_errors: list[WMNError] = []

            def _create_error(
                path_suffix: str,
                message: str,
                data: object | None = None,
                *,
                _base_path: str = base_path,
                _site_errors: list[WMNError] = site_errors,
            ) -> None:
                """Helper to create WMNError with path and data."""
                path = (
                    f"{_base_path}.{path_suffix}" if path_suffix else _base_path
                )
                data_preview = None
                if data is not None:
                    with contextlib.suppress(TypeError, ValueError):
                        data_preview = json.dumps(
                            data,
                            ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
                            indent=DEFAULT_JSON_INDENT,
                        )
                error = WMNError(path=path, data=data_preview, message=message)
                _site_errors.append(error)
                errors.append(error)

            missing_keys = WMNValidator._get_missing_keys(site, WMN_REQUIRED_KEYS)
            if missing_keys:
                _create_error("", f"Missing required keys: {missing_keys}", site)
                if site_errors:
                    error_messages = [error.message for error in site_errors]
                    logger.warning(
                        "Invalid site %s: %s",
                        site_name,
                        "; ".join(error_messages),
                    )
                continue

            uri_check = site[SITE_KEY_URI_CHECK]
            if not isinstance(uri_check, str) or not uri_check:
                _create_error(
                    SITE_KEY_URI_CHECK,
                    f"Invalid {SITE_KEY_URI_CHECK}: must be non-empty string",
                    uri_check,
                )

            for key in (SITE_KEY_E_CODE, SITE_KEY_M_CODE):
                value = site[key]
                if not isinstance(value, int):
                    _create_error(
                        key,
                        f"Invalid {key}: must be integer, got {type(value).__name__}",
                        value,
                    )

            for key in (SITE_KEY_E_STRING, SITE_KEY_M_STRING):
                value = site[key]
                if not isinstance(value, str):
                    _create_error(
                        key,
                        f"Invalid {key}: must be string, got {type(value).__name__}",
                        value,
                    )

            if SITE_KEY_HEADERS in site:
                headers = site[SITE_KEY_HEADERS]
                if headers is not None and not isinstance(headers, dict):
                    _create_error(
                        SITE_KEY_HEADERS,
                        f"Invalid {SITE_KEY_HEADERS}: must be dict or None, "
                        f"got {type(headers).__name__}",
                        headers,
                    )

            known = site[SITE_KEY_KNOWN]
            if not isinstance(known, list):
                msg = (
                    f"Invalid {SITE_KEY_KNOWN}: must be list, "
                    f"got {type(known).__name__}"
                )
                _create_error(SITE_KEY_KNOWN, msg, known)

            if site_errors:
                error_messages = [error.message for error in site_errors]
                logger.warning(
                    "Invalid site %s: %s",
                    site_name,
                    "; ".join(error_messages),
                )

        return errors
