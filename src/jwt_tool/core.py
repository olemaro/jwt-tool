"""Core JWT encode/decode logic for jwt-tool.

This module wraps PyJWT behind an explicit-allowlist API so that neither
this tool nor its callers can be tricked into trusting an algorithm the
token itself claims to use. Two rules enforce that guarantee everywhere in
this file:

1. Signing only ever accepts an algorithm from ``ALLOWED_ALGORITHMS``, and
   that check happens before PyJWT is even called. There is no way to sign
   an ``alg: none`` token, and no way for ``extra_headers`` to sneak a
   different ``alg`` past the check (see the comment in ``encode_token``).
2. Verifying always passes an explicit ``algorithms=[...]`` allowlist to
   ``jwt.decode``. The token header's own ``alg`` value is NEVER read and
   used to pick the verification algorithm -- that is the classic
   alg-confusion / ``alg: none`` vulnerability, and PyJWT only stays safe
   here because this module never does that.

All PyJWT exceptions are translated into the ``jwt_tool.errors`` hierarchy
before they leave this module, so callers only ever need to catch
``jwt_tool.errors.JwtToolError`` -- see ``decode_token`` for the mapping.
"""

from __future__ import annotations

import json
import time
import warnings
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import InsecureKeyLengthWarning

from jwt_tool.errors import (
    AlgorithmError,
    InvalidTokenError,
    PayloadError,
    SecretError,
    SignatureError,
)

#: HMAC algorithms this tool will sign or verify with. Deliberately excludes
#: "none" and every asymmetric algorithm PyJWT knows about -- this tuple
#: *is* the fix for alg-confusion and "alg: none" attacks, so nothing in
#: this module is allowed to bypass it.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("HS256", "HS384", "HS512")

#: Algorithm encode_token() uses when the caller does not name one.
DEFAULT_ALGORITHM: str = "HS256"

#: Minimum recommended HMAC secret length in bytes, per algorithm. RFC 7518
#: section 3.2 requires "a key of the same size as the hash output or larger",
#: so the floor rises with the digest: 32/48/64 bytes. These match PyJWT's own
#: InsecureKeyLengthWarning thresholds (verified against PyJWT 2.15.0) -- a
#: single flat 32 would silently under-warn for HS384 and HS512.
MIN_SECRET_BYTES_BY_ALGORITHM: dict[str, int] = {
    "HS256": 32,
    "HS384": 48,
    "HS512": 64,
}

#: Floor for the default algorithm. Kept as a separate name because it is the
#: figure quoted in user-facing messages and in the README.
MIN_SECRET_BYTES: int = MIN_SECRET_BYTES_BY_ALGORITHM[DEFAULT_ALGORITHM]

#: Claim checks performed when verify=True. Every key is pinned explicitly
#: rather than relying on PyJWT's defaults, because those defaults are neither
#: obvious nor stable:
#:
#: * ``verify_aud`` defaults to True in PyJWT, and a token that carries an
#:   ``aud`` claim then fails with InvalidAudienceError unless the caller also
#:   passes ``audience=``. That would make this tool unable to verify most
#:   real-world OIDC/OAuth2 tokens -- including ones it signed itself -- so the
#:   check is turned OFF here and the limitation is documented instead.
#: * ``verify_iss``/``verify_sub``/``verify_jti`` are no-ops today without a
#:   matching kwarg, but pinning them off means a future PyJWT release cannot
#:   quietly start rejecting tokens this tool used to accept.
#:
#: What this tool does NOT check is reported to the user via
#: DecodedToken.claims_checked, so "signature_verified" can never be mistaken
#: for "this token is valid for my service".
_VERIFY_OPTIONS: dict[str, bool] = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iat": True,
    "verify_aud": False,
    "verify_iss": False,
    "verify_sub": False,
    "verify_jti": False,
}

#: The checks DecodedToken.claims_checked reports after a verify=True decode.
VERIFIED_CHECKS: tuple[str, ...] = ("signature", "exp", "nbf", "iat")


@dataclass(frozen=True)
class DecodedToken:
    """Result of decode_token().

    Attributes:
        header: The JOSE header. Present regardless of ``verify``, but only
            cryptographically trustworthy when ``signature_verified`` is
            True -- it is read the same way whether or not the signature
            checked out.
        payload: The JWT claims set.
        signature_verified: True only when decode_token() was called with
            ``verify=True`` and PyJWT confirmed both the signature and the
            standard time-based claims (``exp``, ``nbf``, ``iat``). False for
            a decode-only call, meaning the payload may be entirely
            attacker-controlled and must not be trusted.

            Note what this flag does NOT mean: it says nothing about ``aud``
            or ``iss``. A token minted for a different service that happens
            to share the same HMAC secret still reports True. Callers that
            need "is this token for me?" must compare those claims
            themselves -- see ``claims_checked``.
        claims_checked: The checks that were actually performed, e.g.
            ``("signature", "exp", "nbf", "iat")`` after a verified decode
            and ``()`` after a decode-only call. Reported so that a script
            reading the output can tell what was and was not validated,
            instead of having to infer it from a single boolean.
    """

    header: dict[str, Any]
    payload: dict[str, Any]
    signature_verified: bool
    claims_checked: tuple[str, ...] = ()


def parse_payload(raw: str) -> dict[str, Any]:
    """Parse ``raw`` (the text behind --payload) as a JSON object.

    Args:
        raw: Raw JSON text.

    Returns:
        The parsed JSON object.

    Raises:
        PayloadError: ``raw`` is not valid JSON (message includes the
            parser error position), or it parses to valid JSON that is not
            an object -- e.g. an array, string, number, or null.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PayloadError(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PayloadError("payload must be a JSON object")
    return data


def min_secret_bytes(algorithm: str = DEFAULT_ALGORITHM) -> int:
    """Minimum recommended secret length in bytes for ``algorithm``.

    Falls back to the strictest known floor for an unrecognised algorithm
    rather than the loosest, so a future addition to ALLOWED_ALGORITHMS
    cannot accidentally weaken the advisory by forgetting a table entry.
    """
    return MIN_SECRET_BYTES_BY_ALGORITHM.get(
        algorithm, max(MIN_SECRET_BYTES_BY_ALGORITHM.values())
    )


def secret_is_weak(secret: str, algorithm: str = DEFAULT_ALGORITHM) -> bool:
    """Report whether ``secret`` is shorter than RFC 7518 recommends.

    Advisory only: this never blocks anything, callers just warn with it.
    PyJWT 2.15 raises its own InsecureKeyLengthWarning for the same
    condition; both encode_token() and decode_token() suppress that
    warning so this function -- and whatever a caller does with it -- is
    the single source of truth for the "weak secret" message.

    The threshold is per-algorithm (32/48/64 bytes for HS256/HS384/HS512),
    because RFC 7518 section 3.2 ties the minimum key size to the hash
    output size. A single flat floor would under-warn for HS384 and HS512.

    PyJWT can also hard-fail instead of warning, via
    ``options={"enforce_minimum_key_length": True}`` on ``decode`` -- but
    that option is not accepted by ``encode`` at all, so it cannot cover
    the signing path. This advisory is deliberately used instead, so the
    behaviour is the same for both, and so the tool stays permissive like
    ``openssl`` rather than refusing to run.

    Args:
        secret: Candidate HMAC secret.
        algorithm: Algorithm the secret will be used with.

    Returns:
        True if ``secret`` encodes (UTF-8) to fewer bytes than the minimum
        recommended for ``algorithm``.
    """
    return len(secret.encode("utf-8")) < min_secret_bytes(algorithm)


def _require_secret(secret: str | None) -> str:
    """Return ``secret`` unchanged if it is usable, else raise SecretError.

    Usable means not None and not empty/whitespace-only. The value is
    never altered -- in particular never stripped -- because that would
    silently change the key material used to sign or verify.
    """
    if secret is None or secret.strip() == "":
        raise SecretError("secret is missing or empty")
    return secret


def _resolve_allowed_algorithms(algorithm: str | None) -> list[str]:
    """Turn a caller algorithm choice into an explicit allowlist.

    None means "any algorithm this tool supports", i.e. the full
    ALLOWED_ALGORITHMS. A named algorithm must itself already be in
    ALLOWED_ALGORITHMS -- this is what stops a caller from asking
    decode_token() to trust an algorithm outside the tool HMAC allowlist
    (for example an asymmetric algorithm, which would treat the HMAC
    secret string as something else entirely).
    """
    if algorithm is None:
        return list(ALLOWED_ALGORITHMS)
    if algorithm not in ALLOWED_ALGORITHMS:
        raise AlgorithmError(
            f"algorithm {algorithm!r} is not in the allowlist {ALLOWED_ALGORITHMS}"
        )
    return [algorithm]


def encode_token(
    payload: dict[str, Any],
    secret: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    extra_headers: dict[str, Any] | None = None,
    expires_in: int | None = None,
) -> str:
    """Sign ``payload`` as a compact JWT.

    Args:
        payload: JSON-object claims to encode. Never mutated -- a shallow
            copy is taken before ``exp``/``iat`` are added.
        secret: HMAC secret. Must be non-empty. Use secret_is_weak() to
            decide whether to warn about a secret shorter than
            MIN_SECRET_BYTES.
        algorithm: Must be one of ALLOWED_ALGORITHMS.
        extra_headers: Extra JOSE header fields (e.g. ``kid``) to merge in.
            Any ``alg`` key in here is discarded before it ever reaches
            PyJWT: PyJWT itself prefers a headers["alg"] value over the
            ``algorithm=`` keyword, so leaving it in would let a caller
            silently pick a different algorithm than the one just checked
            against the allowlist below -- including "none".
        expires_in: If given, seconds from now until expiry. Adds integer
            UTC epoch ``exp`` and ``iat`` claims. If None (the default), no
            claims are added automatically -- we do not silently inject
            claims the caller did not ask for -- and an ``exp`` already
            present in ``payload`` is left exactly as-is.

    Returns:
        The compact JWT (header.payload.signature) as str.

    Raises:
        AlgorithmError: ``algorithm`` is not in ALLOWED_ALGORITHMS. This is
            the check that makes ``alg: none`` impossible to produce with
            this function.
        SecretError: ``secret`` is empty or blank.
    """
    if algorithm not in ALLOWED_ALGORITHMS:
        raise AlgorithmError(
            f"algorithm {algorithm!r} is not in the allowlist {ALLOWED_ALGORITHMS}"
        )
    secret = _require_secret(secret)

    claims = dict(payload)
    if expires_in is not None:
        now = int(time.time())
        claims["iat"] = now
        claims["exp"] = now + expires_in

    headers = dict(extra_headers) if extra_headers else None
    if headers is not None:
        headers.pop("alg", None)  # see docstring: never let this pick the algorithm

    with warnings.catch_warnings():
        # secret_is_weak() is our single source of truth for this advisory;
        # suppress PyJWT's own runtime warning so it does not also land on
        # stderr. Scoped to just this call so nothing else gets silenced.
        warnings.simplefilter("ignore", category=InsecureKeyLengthWarning)
        token = jwt.encode(claims, secret, algorithm=algorithm, headers=headers)
    return token


def decode_token(
    token: str,
    *,
    secret: str | None = None,
    algorithm: str | None = None,
    verify: bool = False,
    leeway: int = 0,
) -> DecodedToken:
    """Decode ``token``, optionally verifying its signature and claims.

    Args:
        token: Compact JWT string.
        secret: HMAC secret. Required (and must be non-empty) when
            ``verify=True``; ignored entirely when ``verify=False``.
        algorithm: Restricts verification to one algorithm, which must be
            in ALLOWED_ALGORITHMS. None allows any algorithm in
            ALLOWED_ALGORITHMS. Only consulted when ``verify=True``. The
            token header's own ``alg`` value is NEVER used to choose the
            verification algorithm -- only this allowlist is, which is
            what prevents alg-confusion and ``alg: none`` attacks.
        verify: If False (the default), decode without checking the
            signature or any time-based claim; ``signature_verified`` is
            always False and no secret is needed. If True, verify the
            signature and the standard time-based claims (``exp``,
            ``nbf``, ``iat``) using ``secret`` against the algorithm
            allowlist described above.

            ``aud`` and ``iss`` are deliberately NOT checked -- see
            ``_VERIFY_OPTIONS`` for why, and ``claims_checked`` on the
            result for what was.
        leeway: Seconds of clock-skew tolerance for the time-based claims.
            PyJWT defaults to 0, which makes a token minted seconds ago on
            a slightly fast machine fail as "not yet valid" -- a routine
            annoyance for a tool whose whole job is moving tokens between
            hosts. Defaults to 0 here too, so behaviour only changes when
            a caller opts in.

    Returns:
        A DecodedToken with the parsed header, the payload, whether the
        signature was verified, and which checks were performed.

    Raises:
        SecretError: ``verify=True`` and ``secret`` is missing or blank.
        AlgorithmError: ``algorithm`` is not in ALLOWED_ALGORITHMS, or
            (when ``verify=True``) the token header's own ``alg`` --
            including ``none`` or a missing ``alg`` -- is not in the
            resolved allowlist.
        SignatureError: The signature does not verify, or the token is
            expired or not yet valid.
        InvalidTokenError: ``token`` is empty, has the wrong number of
            dot-separated segments, contains invalid base64url, has
            leading/trailing whitespace, or a segment does not decode to
            the JSON this format requires -- including a payload segment
            that is valid JSON but not an object.
    """
    allowed: list[str] = []
    if verify:
        secret = _require_secret(secret)
        allowed = _resolve_allowed_algorithms(algorithm)

    try:
        # Per contract: always read the header this way, never by trusting
        # anything verification derives from it.
        header = jwt.get_unverified_header(token)
        if verify:
            with warnings.catch_warnings():
                # Same rationale as encode_token: secret_is_weak() already
                # covers this advisory, scoped to just this call.
                warnings.simplefilter("ignore", category=InsecureKeyLengthWarning)
                payload = jwt.decode(
                    token,
                    secret,
                    algorithms=allowed,
                    leeway=leeway,
                    options=_VERIFY_OPTIONS,
                )
        else:
            payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.ExpiredSignatureError as exc:
        raise SignatureError("token has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise SignatureError("token is not yet valid") from exc
    except jwt.InvalidSignatureError as exc:
        raise SignatureError("signature verification failed") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise AlgorithmError(str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        # Catches jwt.DecodeError and every other structural/parse failure
        # (empty string, wrong segment count, bad base64url, non-JSON or
        # non-object segments, stray whitespace, ...). Must come after the
        # four except clauses above: they are all subclasses of
        # InvalidTokenError, so this would otherwise shadow them.
        raise InvalidTokenError(str(exc)) from exc
    except jwt.PyJWTError as exc:
        # Defensive fallback for any other PyJWT-internal failure (e.g.
        # InvalidKeyError, which is not an InvalidTokenError subclass) so
        # that a raw PyJWT exception can never escape this function.
        raise InvalidTokenError(str(exc)) from exc

    return DecodedToken(
        header=header,
        payload=payload,
        signature_verified=verify,
        claims_checked=VERIFIED_CHECKS if verify else (),
    )
