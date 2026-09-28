"""jwt-tool: encode, decode, and verify JSON Web Tokens from the command line.

This top-level package re-exports the public building blocks from
``jwt_tool.core`` and ``jwt_tool.errors`` so callers can do::

    from jwt_tool import encode_token, decode_token, JwtToolError

without reaching into submodules.
"""

from jwt_tool.core import DecodedToken, decode_token, encode_token, parse_payload
from jwt_tool.errors import (
    AlgorithmError,
    InvalidTokenError,
    JwtToolError,
    PayloadError,
    SecretError,
    SignatureError,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "DecodedToken",
    "decode_token",
    "encode_token",
    "parse_payload",
    "JwtToolError",
    "InvalidTokenError",
    "SignatureError",
    "PayloadError",
    "SecretError",
    "AlgorithmError",
]
