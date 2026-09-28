"""Regression tests for defects found while reviewing the first implementation.

Each test here corresponds to a specific bug that the original test suite and
the contract both missed. They are kept together, with the reason spelled out,
so a future change that reintroduces one of these fails loudly and with an
explanation rather than a bare assertion.
"""
from __future__ import annotations

import json
import time

import jwt
import pytest

from conftest import SENTINEL_SECRET, make_token
from jwt_tool import decode_token, encode_token
from jwt_tool.cli import main
from jwt_tool.core import (
    MIN_SECRET_BYTES_BY_ALGORITHM,
    min_secret_bytes,
    secret_is_weak,
)


# ---------------------------------------------------------------------------
# 1. PyJWT verifies `aud` by default and fails without an `audience=` kwarg
# ---------------------------------------------------------------------------
# This was the worst of the lot: `jwt.decode()` defaults to verify_aud=True,
# so any token carrying an `aud` claim raised InvalidAudienceError -- which,
# being an InvalidTokenError subclass, our mapping reported as a *malformed
# token*. The tool could not verify a token it had just signed itself, and it
# lied about the reason. Most real OIDC/OAuth2 tokens carry `aud`.


def test_our_own_aud_bearing_token_verifies_with_our_own_tool():
    payload = {"sub": "alice", "aud": "my-api", "iss": "https://auth.example.com"}
    token = encode_token(payload, SENTINEL_SECRET)

    decoded = decode_token(token, secret=SENTINEL_SECRET, verify=True)

    assert decoded.signature_verified is True
    assert decoded.payload == payload


def test_raw_pyjwt_would_have_rejected_that_token():
    """Pin the upstream behaviour this fix works around, so the reason is visible.

    If a future PyJWT stops verifying `aud` by default, this test fails and
    tells the next maintainer that the explicit options are now redundant --
    rather than leaving an unexplained workaround in core.py forever.
    """
    token = encode_token({"sub": "alice", "aud": "my-api"}, SENTINEL_SECRET)

    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(token, SENTINEL_SECRET, algorithms=["HS256"])


@pytest.mark.parametrize("claim,value", [
    ("aud", "my-api"),
    ("iss", "https://auth.example.com"),
    ("sub", "alice"),
    ("jti", "abc-123"),
])
def test_registered_claims_do_not_block_verification(claim, value):
    token = encode_token({claim: value}, SENTINEL_SECRET)
    assert decode_token(token, secret=SENTINEL_SECRET, verify=True).payload == {claim: value}


# ---------------------------------------------------------------------------
# 2. `signature_verified` alone is misleading; claims_checked says what ran
# ---------------------------------------------------------------------------


def test_claims_checked_lists_what_was_verified():
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    decoded = decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert decoded.claims_checked == ("signature", "exp", "nbf", "iat")


def test_claims_checked_never_claims_aud_or_iss():
    """The tool must not imply it checked what it did not check."""
    token = encode_token({"aud": "my-api", "iss": "someone"}, SENTINEL_SECRET)
    decoded = decode_token(token, secret=SENTINEL_SECRET, verify=True)
    assert "aud" not in decoded.claims_checked
    assert "iss" not in decoded.claims_checked


def test_claims_checked_is_empty_for_an_unverified_decode():
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    assert decode_token(token).claims_checked == ()


def test_cli_reports_claims_checked_in_its_json(capsys):
    token = encode_token({"sub": "alice", "aud": "my-api"}, SENTINEL_SECRET)
    assert main(["decode", token, "--verify", "--secret", SENTINEL_SECRET]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["signature_verified"] is True
    assert out["claims_checked"] == ["signature", "exp", "nbf", "iat"]


# ---------------------------------------------------------------------------
# 3. Zero clock-skew tolerance rejected freshly-minted valid tokens
# ---------------------------------------------------------------------------
# PyJWT defaults to leeway=0, so a token whose `iat` is a few seconds ahead
# (signing host's clock slightly fast) failed as "not yet valid". For a tool
# whose job is moving tokens between hosts, that needed an escape hatch.


def test_iat_in_the_future_is_rejected_without_leeway():
    from jwt_tool.errors import SignatureError

    token = encode_token({"sub": "a", "iat": int(time.time()) + 30}, SENTINEL_SECRET)
    with pytest.raises(SignatureError):
        decode_token(token, secret=SENTINEL_SECRET, verify=True)


def test_leeway_tolerates_that_clock_skew():
    token = encode_token({"sub": "a", "iat": int(time.time()) + 30}, SENTINEL_SECRET)
    assert decode_token(token, secret=SENTINEL_SECRET, verify=True, leeway=60).signature_verified


def test_leeway_does_not_resurrect_a_long_expired_token():
    from jwt_tool.errors import SignatureError

    token = encode_token({"sub": "a", "exp": int(time.time()) - 3600}, SENTINEL_SECRET)
    with pytest.raises(SignatureError):
        decode_token(token, secret=SENTINEL_SECRET, verify=True, leeway=60)


def test_negative_leeway_is_a_cli_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["decode", "x.y.z", "--leeway", "-1"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# 4. The weak-secret advisory floor is per-algorithm, not a flat 32
# ---------------------------------------------------------------------------
# RFC 7518 3.2 ties the minimum key size to the digest size, and PyJWT's own
# InsecureKeyLengthWarning uses 32/48/64. A flat 32 silently under-warned for
# HS384 and HS512.


@pytest.mark.parametrize("algorithm,expected", [("HS256", 32), ("HS384", 48), ("HS512", 64)])
def test_minimum_secret_length_follows_the_digest_size(algorithm, expected):
    assert min_secret_bytes(algorithm) == expected
    assert MIN_SECRET_BYTES_BY_ALGORITHM[algorithm] == expected


def test_a_32_byte_secret_is_fine_for_hs256_but_weak_for_hs512():
    secret = "y" * 32
    assert secret_is_weak(secret, "HS256") is False
    assert secret_is_weak(secret, "HS384") is True
    assert secret_is_weak(secret, "HS512") is True


def test_unknown_algorithm_falls_back_to_the_strictest_floor():
    """Fail safe: a future algorithm missing from the table must not weaken the check."""
    assert min_secret_bytes("HS999") == max(MIN_SECRET_BYTES_BY_ALGORITHM.values())


def test_cli_quotes_the_algorithm_specific_floor_without_printing_the_secret(capsys):
    assert main(["encode", "--payload", "{}", "--secret", "y" * 32, "--algorithm", "HS512"]) == 0
    err = capsys.readouterr().err
    assert "64 bytes" in err
    assert "y" * 32 not in err


# ---------------------------------------------------------------------------
# 5. `--secret-env` must require an explicit variable name
# ---------------------------------------------------------------------------
# It used to be nargs="?" with a JWT_SECRET default, which (a) swallowed the
# positional token in `decode --secret-env <token>` and (b) risked silently
# picking up an application's real production signing key from the ambient
# environment.


def test_bare_secret_env_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["decode", "a.b.c", "--verify", "--secret-env"])
    assert exc.value.code == 2


def test_secret_env_cannot_swallow_the_token_argument(monkeypatch):
    monkeypatch.setenv("JWT_TOOL_TEST_SECRET", SENTINEL_SECRET)
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    assert main(["decode", "--secret-env", "JWT_TOOL_TEST_SECRET", "--verify", token]) == 0


# ---------------------------------------------------------------------------
# 6. `--algorithm` without `--verify` did nothing, silently
# ---------------------------------------------------------------------------


def test_algorithm_without_verify_warns_that_it_was_ignored(capsys):
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    assert main(["decode", token, "--algorithm", "HS256"]) == 0
    captured = capsys.readouterr()
    assert "ignored" in captured.err
    # the warning must not pollute the machine-readable stream
    json.loads(captured.out)
    assert "ignored" not in captured.out


def test_no_spurious_algorithm_warning_when_verify_is_used(capsys):
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    assert main(["decode", token, "--verify", "--secret", SENTINEL_SECRET,
                 "--algorithm", "HS256"]) == 0
    assert "ignored" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 7. alg:none stays unreachable after all of the above
# ---------------------------------------------------------------------------
# Re-asserted here because several of the changes above touched the verify
# path's options; this is the property that must never regress.


def test_alg_none_is_still_rejected_under_verify():
    from jwt_tool.errors import AlgorithmError

    token = make_token({"alg": "none", "typ": "JWT"}, {"admin": True})
    with pytest.raises(AlgorithmError):
        decode_token(token, secret=SENTINEL_SECRET, verify=True)


def test_alg_none_is_still_rejected_even_with_leeway_and_registered_claims():
    from jwt_tool.errors import AlgorithmError

    token = make_token({"alg": "none", "typ": "JWT"}, {"aud": "my-api", "admin": True})
    with pytest.raises(AlgorithmError):
        decode_token(token, secret=SENTINEL_SECRET, verify=True, leeway=3600)
