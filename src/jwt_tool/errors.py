"""Exception hierarchy for jwt-tool.

Every class here is an *expected* failure mode: something a caller did
wrong (bad payload, missing secret, malformed token, disallowed algorithm,
...) rather than a bug in this tool. ``jwt_tool.cli.main`` catches only
``JwtToolError`` (and therefore all of its subclasses), prints
``error: <message>`` to stderr, and exits with code 1. Any other exception
is treated as a genuine bug and is left to propagate with its traceback.

Because messages here are shown directly to the user, they must be
actionable -- and they must NEVER include the secret value itself, even
when the secret is the reason for the failure (e.g. "too short" is fine,
printing the secret is not).
"""


class JwtToolError(Exception):
    """Base class for every expected jwt-tool failure.

    Caught by the CLI entry point and turned into a clean
    ``error: <message>`` line on stderr with exit code 1 -- never a
    traceback.
    """


class InvalidTokenError(JwtToolError):
    """The token string is malformed or unparseable as a JWT.

    Raised for structural problems such as the wrong number of
    ``.``-separated segments, invalid base64url in a segment, or a segment
    that does not decode to the JSON the JOSE format requires. This is
    independent of whether a signature was ever checked -- decoding with
    ``verify=False`` can still raise this for garbage input.
    """


class SignatureError(JwtToolError):
    """The token parsed correctly but verification rejected it.

    Covers a mismatched HMAC signature as well as the time-based claims
    PyJWT validates during verification, such as an expired (``exp``) or
    not-yet-valid (``nbf``) token.
    """


class PayloadError(JwtToolError):
    """The ``--payload`` argument is not a JSON object.

    Raised by :func:`jwt_tool.core.parse_payload` both for text that is not
    valid JSON at all, and for JSON that parses fine but is not an object
    (e.g. an array, string, number, or null).
    """


class SecretError(JwtToolError):
    """The secret is missing, empty, or could not be read.

    Never includes the secret value itself.
    """


class AlgorithmError(JwtToolError):
    """The requested algorithm is not in ``ALLOWED_ALGORITHMS``.

    This is the guard that makes ``alg: none`` and algorithm-confusion
    attacks impossible to sign or verify with -- there is no opt-out, on
    either :func:`~jwt_tool.core.encode_token` or
    :func:`~jwt_tool.core.decode_token`.
    """
