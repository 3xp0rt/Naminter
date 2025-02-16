class NaminterError(Exception):
    """Base exception class for Naminter errors."""
    pass

class ConfigurationError(NaminterError):
    """Raised when there's an error in the configuration parameters."""
    pass

class NetworkError(NaminterError):
    """Raised when network-related errors occur."""
    pass

class DataError(NaminterError):
    """Raised when there are issues with data processing or validation."""
    pass