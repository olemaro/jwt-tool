"""Shared fixtures and helpers for the jwt-tool test suite.

Everything here is written against docs/CONTRACT.md, not against whatever
jwt_tool's implementation currently does -- the implementation is being
written in parallel and may be missing or incomplete. Helpers in this file
are deliberately independent of jwt_tool internals (they build tokens by
hand with stdlib base64/json) so they keep working regardless.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Make `import jwt_tool` work from this src/ layout checkout, whether or not
# the package has been pip-installed (editable or otherwise). Inserted at
# the front of sys.path so a locally-edited source tree always wins over a
# stale installed copy.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ---------------------------------------------------------------------------
# Sentinel secret
# ---------------------------------------------------------------------------
# Deliberately long (>= MIN_SECRET_BYTES from the contract) and unmistakable:
#   - it never trips a "this secret is weak" advisory warning, which would
#     otherwise pollute stderr assertions that are about something else, and
#   - tests asserting "the secret must never leak" can grep stdout/stderr
#     for this exact, unlikely-to-appear-by-accident string.
SENTINEL_SECRET = "sentinel-CANARY-9f3a1c7d-do-not-leak-this-value"

assert len(SENTINEL_SECRET.encode("utf-8")) >= 32, "keep the sentinel >= MIN_SECRET_BYTES"


# ---------------------------------------------------------------------------
# Hand-rolled token construction
# ---------------------------------------------------------------------------
# These build JWTs byte-by-byte instead of going through jwt_tool/PyJWT, so
# tests can create tokens no honest encoder would ever produce: alg:none,
# non-JSON segments, a payload that is a JSON array, a stale signature glued
# onto a modified payload, etc.


def b64url_encode(data: bytes) -> str:
    """Base64url-encode ``data`` with padding stripped, JWT-segment style."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: object, payload: object, signature: bytes = b"") -> str:
    """Build a JWT by hand from raw header/payload objects and raw signature bytes.

    ``header`` and ``payload`` are JSON-dumped and base64url-encoded exactly
    as given -- they don't have to be dicts, so this can build the malformed
    tokens the contract requires ``decode_token`` to reject (e.g. a payload
    segment that decodes to a JSON array instead of an object), as well as a
    hand-built ``alg: none`` token with an empty signature segment.
    """
    header_segment = b64url_encode(json.dumps(header).encode("utf-8"))
    payload_segment = b64url_encode(json.dumps(payload).encode("utf-8"))
    signature_segment = b64url_encode(signature)
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def replace_payload_segment(token: str, new_payload: object) -> str:
    """Swap a token's payload segment for ``new_payload``; keep header/signature.

    This is the CVE-2022-39227-class tampering primitive: re-encode a
    modified payload but keep the *old* signature segment untouched. A
    correct implementation must reject the result, because the signature no
    longer matches the (new) payload.
    """
    header_segment, _old_payload_segment, signature_segment = token.split(".")
    new_payload_segment = b64url_encode(json.dumps(new_payload).encode("utf-8"))
    return f"{header_segment}.{new_payload_segment}.{signature_segment}"


# ---------------------------------------------------------------------------
# secrets.resolve_secret argument namespace
# ---------------------------------------------------------------------------


def make_secret_args(
    *,
    secret: str | None = None,
    secret_env: str | None = None,
    secret_file: str | None = None,
    secret_stdin: bool = False,
) -> argparse.Namespace:
    """Build the ``args`` namespace resolve_secret() expects.

    Mirrors the argparse dest names implied by the flags in CONTRACT.md
    (--secret, --secret-env, --secret-file, --secret-stdin). Exactly one
    kwarg should be set to represent "one source given"; leaving all four
    at their defaults represents "no source given" (argparse itself is
    responsible for enforcing that only one is given at the CLI layer).
    """
    return argparse.Namespace(
        secret=secret,
        secret_env=secret_env,
        secret_file=secret_file,
        secret_stdin=secret_stdin,
    )
