import json
import logging
from collections.abc import Sequence
from typing import Any

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError as JsonSchemaError

from .constants import (
    DEFAULT_JSON_ENSURE_ASCII,
    DEFAULT_JSON_INDENT,
    SITE_KEY_NAME,
    WMN_KEY_SITES,
)
from .exceptions import WMNSchemaError
from .models import WMNDataset, WMNValidationModel

logger = logging.getLogger(__name__)


def validate_dataset(
    data: WMNDataset, schema: dict[str, Any]
) -> list[WMNValidationModel]:
    """Validate WMN dataset against JSON Schema and return list of errors.

    Raises WMNSchemaError if the provided schema is invalid.

    Args:
        data: WMN dataset to validate
        schema: JSON Schema to validate against
    """
    if not schema:
        return []

    try:
        validator = Draft7Validator(schema)
    except JsonSchemaError as error:
        msg = f"Invalid JSON schema: {error}"
        raise WMNSchemaError(msg) from error

    errors: list[WMNValidationModel] = []
    for error in validator.iter_errors(data):  # type: ignore[reportUnknownMemberType]
        message_text = error.message
        path_string = error.json_path
        data_preview: str | None = None

        try:
            if error.absolute_path:
                current_data = data
                for segment in error.absolute_path:
                    current_data = current_data[segment]
                if current_data is not None:
                    data_preview = json.dumps(
                        current_data,
                        ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
                        indent=DEFAULT_JSON_INDENT,
                    )
        except Exception:
            data_preview = None

        errors.append(
            WMNValidationModel(
                path=path_string,
                data=data_preview,
                message=message_text,
            )
        )

    sites_data = data.get(WMN_KEY_SITES, [])

    name_indices: dict[str, list[int]] = {}
    for index, site in enumerate(sites_data):
        site_name = site.get(SITE_KEY_NAME)
        if site_name:
            name_indices.setdefault(site_name, []).append(index)

    for site_name, indices in name_indices.items():
        if len(indices) > 1:
            for index in indices:
                path_string = f"$.{WMN_KEY_SITES}[{index}]"
                try:
                    site_data = sites_data[index]
                    data_preview = json.dumps(
                        site_data,
                        ensure_ascii=DEFAULT_JSON_ENSURE_ASCII,
                        indent=DEFAULT_JSON_INDENT,
                    )
                except Exception:
                    data_preview = None

                errors.append(
                    WMNValidationModel(
                        path=path_string,
                        data=data_preview,
                        message=(
                            f"Duplicate site name found: '{site_name}' "
                            f"(appears {len(indices)} times)"
                        ),
                    )
                )

    return errors


def get_missing_keys(data: dict[str, Any], keys: Sequence[str]) -> list[str]:
    """Return a list of required keys missing from a dictionary.

    Args:
        data: Dictionary to check for missing keys
        keys: Sequence of keys that should be present

    Returns:
        List of keys that are missing from the dictionary
    """
    return [key for key in keys if key not in data]
