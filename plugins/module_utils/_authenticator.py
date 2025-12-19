"""Infisical SDK Authenticator for Ansible Collection.

This module provides a centralized authentication mechanism for all Infisical
plugins and modules. It uses the Infisical Python SDK for all operations.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# Authentication method constants
AUTH_METHOD_UNIVERSAL_AUTH = "universal_auth"
AUTH_METHOD_OIDC_AUTH = "oidc_auth"
AUTH_METHOD_TOKEN_AUTH = "token_auth"

SUPPORTED_AUTH_METHODS = [
    AUTH_METHOD_UNIVERSAL_AUTH,
    AUTH_METHOD_OIDC_AUTH,
    AUTH_METHOD_TOKEN_AUTH,
]

# SDK availability flags
HAS_INFISICAL = False
INFISICAL_IMP_ERR = None
INFISICAL_VERSION = None

try:
    from infisical_sdk import InfisicalSDKClient
    HAS_INFISICAL = True
except ImportError as e:
    HAS_INFISICAL = False
    INFISICAL_IMP_ERR = str(e)
    InfisicalSDKClient = None

if HAS_INFISICAL:
    try:
        from importlib.metadata import version
        INFISICAL_VERSION = version('infisicalsdk')
    except ImportError:
        try:
            import pkg_resources
            INFISICAL_VERSION = pkg_resources.get_distribution('infisicalsdk').version
        except Exception:
            INFISICAL_VERSION = "unknown"
    except Exception:
        INFISICAL_VERSION = "unknown"


def _parse_version_tuple(version_string):
    """Parse a version string into a tuple of integers for comparison.
    
    Args:
        version_string: A version string like "1.2.3" or "1.2"
        
    Returns:
        A tuple of 3 integers (major, minor, patch)
    """
    if version_string == "unknown":
        return (0, 0, 0)
    
    try:
        parts = version_string.split('.')
        while len(parts) < 3:
            parts.append('0')
        return tuple(int(part) for part in parts[:3])
    except (ValueError, AttributeError):
        return (0, 0, 0)


def check_minimum_version(current_version, minimum_version):
    """Check if current version meets minimum requirement.
    
    Args:
        current_version: The current version string
        minimum_version: The minimum required version string
        
    Returns:
        True if current_version >= minimum_version
    """
    current_tuple = _parse_version_tuple(current_version)
    minimum_tuple = _parse_version_tuple(minimum_version)
    return current_tuple >= minimum_tuple


class InfisicalAuthenticator:
    """Authenticator for a single Infisical authentication flow.
    
    This class handles authentication with Infisical using the Python SDK.
    All required parameters are passed to the constructor.
    
    Usage:
        authenticator = InfisicalAuthenticator(
            url="https://app.infisical.com",
            auth_method="universal_auth",
            client_id="...",
            client_secret="..."
        )
        client = authenticator.authenticate()
    """
    
    def __init__(self, url="https://app.infisical.com", auth_method="universal_auth", **credentials):
        """Initialize the authenticator with all required parameters.
        
        Args:
            url: The Infisical instance URL (default: https://app.infisical.com)
            auth_method: The authentication method to use
            **credentials: The credentials for the auth method:
                - universal_auth: client_id, client_secret
                - oidc_auth: identity_id, jwt
                - token_auth: token
        """
        self.url = url
        self.auth_method = auth_method
        self.credentials = credentials
        self._client = None
    
    def _validate(self):
        """Validate credentials for the configured authentication method.
        
        Raises:
            ValueError: If credentials are invalid or auth method is unsupported
        """
        method = self.auth_method
        credentials = self.credentials
        
        if method not in SUPPORTED_AUTH_METHODS:
            raise ValueError(f"Invalid auth method '{method}'. Supported: {', '.join(SUPPORTED_AUTH_METHODS)}")
        
        if method == AUTH_METHOD_UNIVERSAL_AUTH:
            if not credentials.get('client_id') or not credentials.get('client_secret'):
                raise ValueError("client_id and client_secret are required for universal_auth.")
        
        elif method == AUTH_METHOD_OIDC_AUTH:
            if not check_minimum_version(INFISICAL_VERSION, "1.0.10"):
                raise ValueError("Please upgrade infisicalsdk to at least 1.0.10 to use oidc_auth.")
            if not credentials.get('identity_id') or not credentials.get('jwt'):
                raise ValueError("identity_id and jwt are required for oidc_auth.")
        
        elif method == AUTH_METHOD_TOKEN_AUTH:
            if not credentials.get('token'):
                raise ValueError("token is required for token_auth.")
    
    def authenticate(self):
        """Authenticate with Infisical and return a configured SDK client.
        
        Returns:
            An authenticated InfisicalSDKClient instance
            
        Raises:
            ValueError: If credentials are invalid
            ImportError: If the Infisical SDK is not installed
        """
        if not HAS_INFISICAL:
            raise ImportError(
                f"The infisicalsdk package is required. Install with: pip install infisicalsdk. Error: {INFISICAL_IMP_ERR}"
            )
        
        self._validate()
        
        client = InfisicalSDKClient(host=self.url)
        
        if self.auth_method == AUTH_METHOD_UNIVERSAL_AUTH:
            client.auth.universal_auth.login(
                self.credentials['client_id'],
                self.credentials['client_secret']
            )
        elif self.auth_method == AUTH_METHOD_OIDC_AUTH:
            client.auth.oidc_auth.login(
                self.credentials['identity_id'],
                self.credentials['jwt']
            )
        elif self.auth_method == AUTH_METHOD_TOKEN_AUTH:
            client.auth.token_auth.login(self.credentials['token'])
        
        self._client = client
        return client
