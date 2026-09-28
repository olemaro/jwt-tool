"""Tests for jwt_tool.core, written against docs/CONTRACT.md section 2.

These test the frozen contract, not the current implementation: encode/decode
round trips, the exact exception each failure mode must raise, the
CVE-2022-39227-class payload-tampering rejection, alg:none / cross-algorithm
rejection, expires_in semantics, and parse_payload's strict "must be a JSON
object" rule.
"""
from __future__ import annotations

import copy
import time

import pytest

from jwt_tool import core, errors

from conftest import SENTINEL_SECRET, b64url_encode, make_token, replace_payload_segment

WRONG_SECRET = "a-totally-different-secret-value-that-is-also-long-enough"


# ---------------------------------------------------------------------------
# Module constants (CONTRACT.md pins these exact values)
# ---------------------------------------------------------------------------


def test_module_constants_match_the_frozen_contract():
    assert core.ALLOWED_ALGORITHMS == ("HS256", "HS384", "HS512")
    assert core.DEFAULT_ALGORITHM == "HS256"
    assert core.MIN_SECRET_BYTES == 32


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

ROUND_TRIP_PAYLOADS = [
    pytest.param({}, id="empty-object"),
    pytest.param({"nested": {"a": {"b": {"c": [1, 2, {"d": 3}]}}}}, id="nested-objects-and-arrays"),
    pytest.param({"greeting": "héllo wörld 日本語 \U0001f389"}, id="unicode"),
    pytest.param({"count": 42, "negative": -7, "zero": 0}, id="ints"),
    pytest.param({"pi": 3.14159, "neg": -0.001, "zero": 0.0}, id="floats"),
    pytest.param({"yes": True, "no": False}, id="bools"),
    pytest.param({"nothing": None}, id="null"),
    pytest.param({"mixed": [1, "two", 3.0, False, None, {"k": "v"}]}, id="mixed-array"),
]


@pytest.mark.parametrize("payload", ROUND_TRIP_PAYLOADS)
def test_round_trip_preserves_payload_unchanged(payload):
    token = core.encode_token(payload, SENTINEL_SECRET)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert decoded.payload == payload


def test_encode_token_returns_a_plain_str_not_bytes():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    assert isinstance(token, str)


# ---------------------------------------------------------------------------
# encode_token must not mutate the caller's dict
# ---------------------------------------------------------------------------


def test_encode_token_does_not_mutate_callers_payload_dict():
    payload = {"a": 1, "nested": {"b": 2}}
    snapshot = copy.deepcopy(payload)
    core.encode_token(payload, SENTINEL_SECRET)
    assert payload == snapshot


def test_encode_token_with_expires_in_does_not_mutate_callers_payload_dict():
    payload = {"a": 1}
    snapshot = copy.deepcopy(payload)
    core.encode_token(payload, SENTINEL_SECRET, expires_in=60)
    assert payload == snapshot
    assert "exp" not in payload
    assert "iat" not in payload


# ---------------------------------------------------------------------------
# Wrong secret vs right secret
# ---------------------------------------------------------------------------


def test_decode_with_wrong_secret_raises_signature_error():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    with pytest.raises(errors.SignatureError):
        core.decode_token(token, secret=WRONG_SECRET, verify=True)


def test_decode_with_correct_secret_succeeds_and_reports_verified():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert decoded.payload == {"a": 1}
    assert decoded.signature_verified is True


# ---------------------------------------------------------------------------
# CVE-2022-39227-class tampering: re-encoded payload, stale signature
# ---------------------------------------------------------------------------


def test_tampering_payload_segment_but_keeping_old_signature_is_rejected():
    # An attacker swaps the payload segment of a valid token for whatever
    # they like, but leaves the original signature segment in place. A
    # correct implementation must reject this: the signature no longer
    # matches the (new) payload, so this must NOT be silently accepted.
    token = core.encode_token({"user": "alice", "admin": False}, SENTINEL_SECRET)
    forged = replace_payload_segment(token, {"user": "alice", "admin": True})
    with pytest.raises(errors.SignatureError):
        core.decode_token(forged, secret=SENTINEL_SECRET, verify=True)


# ---------------------------------------------------------------------------
# verify=False vs verify=True
# ---------------------------------------------------------------------------


def test_decode_without_verify_needs_no_secret_and_reports_unverified():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    decoded = core.decode_token(token, verify=False)
    assert decoded.signature_verified is False
    assert decoded.payload == {"a": 1}


def test_decode_with_verify_true_and_correct_secret_reports_verified_true():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert decoded.signature_verified is True


# ---------------------------------------------------------------------------
# HS256 / HS384 / HS512, and unsupported algorithms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", list(core.ALLOWED_ALGORITHMS))
def test_each_allowed_algorithm_round_trips_with_matching_algorithm(algorithm):
    token = core.encode_token({"a": 1}, SENTINEL_SECRET, algorithm=algorithm)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, algorithm=algorithm, verify=True)
    assert decoded.signature_verified is True
    assert decoded.payload == {"a": 1}


@pytest.mark.parametrize("algorithm", list(core.ALLOWED_ALGORITHMS))
def test_decode_with_algorithm_none_accepts_any_allowed_algorithm(algorithm):
    token = core.encode_token({"a": 1}, SENTINEL_SECRET, algorithm=algorithm)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, algorithm=None, verify=True)
    assert decoded.signature_verified is True


@pytest.mark.parametrize(
    "algorithm",
    [
        pytest.param("RS256", id="RS256-asymmetric-not-allowed"),
        pytest.param("none", id="none-is-blocked-with-no-opt-out"),
        pytest.param("", id="empty-string"),
        pytest.param("HS128", id="not-a-real-algorithm"),
        pytest.param("hs256", id="lowercase-is-not-HS256"),
    ],
)
def test_encode_with_unsupported_algorithm_raises_algorithm_error(algorithm):
    with pytest.raises(errors.AlgorithmError):
        core.encode_token({"a": 1}, SENTINEL_SECRET, algorithm=algorithm)


# ---------------------------------------------------------------------------
# alg:none, built by hand
# ---------------------------------------------------------------------------


def test_hand_built_alg_none_token_decodes_without_verify_but_is_not_verified():
    token = make_token({"alg": "none", "typ": "JWT"}, {"sub": "attacker"}, signature=b"")
    decoded = core.decode_token(token, verify=False)
    assert decoded.payload == {"sub": "attacker"}
    assert decoded.header["alg"] == "none"
    assert decoded.signature_verified is False


def test_hand_built_alg_none_token_raises_algorithm_error_when_verify_true():
    token = make_token({"alg": "none", "typ": "JWT"}, {"sub": "attacker"}, signature=b"")
    # pytest.raises fails the test outright if decode_token returns normally
    # instead of raising -- i.e. this asserts it is NOT silently accepted.
    with pytest.raises(errors.AlgorithmError):
        core.decode_token(token, secret=SENTINEL_SECRET, verify=True)


# ---------------------------------------------------------------------------
# Cross-algorithm confusion
# ---------------------------------------------------------------------------


def test_token_signed_hs256_but_verified_as_hs384_is_rejected_not_accepted():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET, algorithm="HS256")
    with pytest.raises(errors.AlgorithmError):
        core.decode_token(token, secret=SENTINEL_SECRET, algorithm="HS384", verify=True)


# ---------------------------------------------------------------------------
# expires_in
# ---------------------------------------------------------------------------


def test_expires_in_adds_integer_exp_and_iat_claims():
    before = int(time.time())
    token = core.encode_token({"a": 1}, SENTINEL_SECRET, expires_in=3600)
    after = int(time.time())
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, verify=True)

    assert isinstance(decoded.payload["exp"], int)
    assert isinstance(decoded.payload["iat"], int)
    assert before <= decoded.payload["iat"] <= after
    assert decoded.payload["exp"] - decoded.payload["iat"] == 3600


def test_already_expired_token_raises_signature_error_mentioning_expired():
    long_ago = int(time.time()) - 3600
    payload = {"a": 1, "exp": long_ago}
    # expires_in is NOT given, so this hand-set exp claim is left as-is.
    token = core.encode_token(payload, SENTINEL_SECRET)
    with pytest.raises(errors.SignatureError, match=r"(?i)expired"):
        core.decode_token(token, secret=SENTINEL_SECRET, verify=True)


def test_expires_in_none_injects_no_claims_at_all():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET, expires_in=None)
    decoded = core.decode_token(token, verify=False)
    for claim in ("exp", "iat", "jti", "nbf"):
        assert claim not in decoded.payload


def test_preexisting_exp_claim_is_preserved_when_expires_in_not_given():
    far_future = int(time.time()) + 100_000
    payload = {"exp": far_future, "user": "dana"}
    token = core.encode_token(payload, SENTINEL_SECRET)
    decoded = core.decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert decoded.payload["exp"] == far_future


# ---------------------------------------------------------------------------
# Secret validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_secret",
    [
        pytest.param("", id="empty-string"),
        pytest.param("   ", id="whitespace-only"),
        pytest.param(None, id="none"),
    ],
)
def test_encode_with_empty_or_blank_secret_raises_secret_error(bad_secret):
    with pytest.raises(errors.SecretError):
        core.encode_token({"a": 1}, bad_secret)


def test_decode_with_verify_true_and_secret_none_raises_secret_error():
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    with pytest.raises(errors.SecretError):
        core.decode_token(token, secret=None, verify=True)


# ---------------------------------------------------------------------------
# extra_headers
# ---------------------------------------------------------------------------


def test_extra_headers_land_in_the_decoded_header():
    token = core.encode_token(
        {"a": 1}, SENTINEL_SECRET, extra_headers={"kid": "key-1", "custom": "value"}
    )
    decoded = core.decode_token(token, verify=False)
    assert decoded.header["kid"] == "key-1"
    assert decoded.header["custom"] == "value"


def test_extra_headers_cannot_override_alg():
    token = core.encode_token(
        {"a": 1}, SENTINEL_SECRET, algorithm="HS384", extra_headers={"alg": "HS256"}
    )
    decoded = core.decode_token(token, verify=False)
    assert decoded.header["alg"] == "HS384"
    # The token must still genuinely be signed with the real algorithm, not
    # whatever extra_headers tried to claim.
    verified = core.decode_token(token, secret=SENTINEL_SECRET, algorithm="HS384", verify=True)
    assert verified.signature_verified is True


# ---------------------------------------------------------------------------
# secret_is_weak
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("secret", "expected"),
    [
        pytest.param("x" * 31, True, id="31-bytes-is-weak"),
        pytest.param("x" * 32, False, id="32-bytes-is-not-weak"),
        pytest.param("x" * 33, False, id="33-bytes-is-not-weak"),
        pytest.param("short", True, id="short-ascii-is-weak"),
    ],
)
def test_secret_is_weak_boundary_conditions(secret, expected):
    assert core.secret_is_weak(secret) is expected


def test_secret_is_weak_counts_utf8_bytes_not_characters():
    # "e-acute" is 2 bytes in UTF-8, so 16 of them is 32 bytes -- not weak --
    # even though the character count (16) is well under MIN_SECRET_BYTES.
    sixteen_two_byte_chars = "é" * 16
    assert len(sixteen_two_byte_chars) == 16
    assert len(sixteen_two_byte_chars.encode("utf-8")) == 32
    assert core.secret_is_weak(sixteen_two_byte_chars) is False


def test_encoding_with_a_short_secret_does_not_leak_a_pyjwt_warning(recwarn):
    # CONTRACT.md: "PyJWT 2.15 raises its own InsecureKeyLengthWarning;
    # suppress it inside core so we own the message."
    core.encode_token({"a": 1}, "too-short", algorithm="HS256")
    leaked = [str(w.message) for w in recwarn.list if "insecure" in str(w.message).lower()]
    assert leaked == []


# ---------------------------------------------------------------------------
# Malformed tokens -> InvalidTokenError, never a traceback
# ---------------------------------------------------------------------------


def _valid_base64url_but_not_json_token() -> str:
    header = b64url_encode(b"not-json-header")
    payload = b64url_encode(b"not-json-payload")
    signature = b64url_encode(b"whatever")
    return f"{header}.{payload}.{signature}"


def _payload_is_json_array_token() -> str:
    return make_token({"alg": "HS256", "typ": "JWT"}, [1, 2], signature=b"whatever")


def _token_with_surrounding_whitespace() -> str:
    inner = make_token({"alg": "HS256", "typ": "JWT"}, {"a": 1}, signature=b"whatever")
    return f"  \t{inner}\n  "


MALFORMED_TOKENS = [
    pytest.param("", id="empty-string"),
    pytest.param("   ", id="blank-whitespace-only"),
    pytest.param("abc", id="single-segment"),
    pytest.param("a.b", id="two-segments"),
    pytest.param("a.b.c.d", id="four-segments"),
    pytest.param("!!!.!!!.!!!", id="non-base64url-characters"),
    pytest.param(_valid_base64url_but_not_json_token(), id="valid-base64url-but-not-json"),
    pytest.param(_payload_is_json_array_token(), id="payload-is-a-json-array-not-an-object"),
    pytest.param(_token_with_surrounding_whitespace(), id="leading-and-trailing-whitespace"),
    pytest.param(None, id="none-junk"),
    pytest.param(12345, id="non-string-junk"),
]


@pytest.mark.parametrize("bad_token", MALFORMED_TOKENS)
def test_malformed_token_raises_invalid_token_error_not_a_traceback(bad_token):
    with pytest.raises(errors.InvalidTokenError) as excinfo:
        core.decode_token(bad_token, verify=False)
    assert "Traceback" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# parse_payload
# ---------------------------------------------------------------------------


def test_parse_payload_returns_a_dict_for_a_json_object():
    assert core.parse_payload('{"a": 1, "b": [1, 2, 3]}') == {"a": 1, "b": [1, 2, 3]}


def test_parse_payload_of_empty_object_returns_empty_dict():
    assert core.parse_payload("{}") == {}


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("[1,2]", id="json-array"),
        pytest.param('"str"', id="json-string"),
        pytest.param("42", id="json-number"),
        pytest.param("null", id="json-null"),
        pytest.param("true", id="json-bool"),
    ],
)
def test_parse_payload_rejects_non_object_json(raw):
    with pytest.raises(errors.PayloadError):
        core.parse_payload(raw)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("{not valid json", id="unterminated-object"),
        pytest.param("", id="empty-string"),
        pytest.param("{'a': 1}", id="single-quoted-not-valid-json"),
    ],
)
def test_parse_payload_rejects_malformed_json(raw):
    with pytest.raises(errors.PayloadError):
        core.parse_payload(raw)
