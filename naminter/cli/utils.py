def sanitize_filename(filename: str) -> str:
    """Sanitize filename for cross-platform compatibility."""
    if not filename or not str(filename).strip():
        return "unnamed"

    invalid_chars = '<>:"|?*\\/\0'
    sanitized = "".join(
        "_" if c in invalid_chars or ord(c) < 32 else c for c in str(filename)
    )
    sanitized = sanitized.strip(" .")[:200] if sanitized.strip(" .") else "unnamed"
    return sanitized
