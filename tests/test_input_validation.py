"""Input-validation branches a user reaches by typing something slightly wrong.

These were the gaps a coverage run pointed at: argparse `type=` converters and
small parsing helpers whose error paths nothing exercised. They are all
user-reachable, so each gets a test rather than a `# pragma: no cover`.
"""
from __future__ import annotations

import pytest

from conftest import SENTINEL_SECRET
from jwt_tool import encode_token
from jwt_tool.cli import main
from jwt_tool.errors import SecretError
from jwt_tool.secrets import strip_one_trailing_newline


# ---------------------------------------------------------------------------
# --expires-in / --leeway: non-numeric input
# ---------------------------------------------------------------------------
# The converters distinguish "not a number" from "out of range", and both are
# usage errors (exit 2), not runtime errors (exit 1).


@pytest.mark.parametrize("value", ["abc", "", "3.5", "1e3", " ", "0x10", "--"])
def test_non_integer_expires_in_is_a_usage_error(value):
    with pytest.raises(SystemExit) as exc:
        main(["encode", "--payload", "{}", "--secret", SENTINEL_SECRET, "--expires-in", value])
    assert exc.value.code == 2


@pytest.mark.parametrize("value", ["abc", "2.5", ""])
def test_non_integer_leeway_is_a_usage_error(value):
    with pytest.raises(SystemExit) as exc:
        main(["decode", "a.b.c", "--leeway", value])
    assert exc.value.code == 2


def test_leeway_zero_is_accepted_unlike_expires_in():
    """0 is meaningless for a lifetime but perfectly valid for a tolerance."""
    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    assert main(["decode", token, "--verify", "--secret", SENTINEL_SECRET, "--leeway", "0"]) == 0

    with pytest.raises(SystemExit) as exc:
        main(["encode", "--payload", "{}", "--secret", SENTINEL_SECRET, "--expires-in", "0"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# --header K=V parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["noequals", "=novalue", "="])
def test_malformed_header_pair_is_a_usage_error(value):
    with pytest.raises(SystemExit) as exc:
        main(["encode", "--payload", "{}", "--secret", SENTINEL_SECRET, "--header", value])
    assert exc.value.code == 2


def test_header_value_is_json_when_it_parses_and_a_string_otherwise(capsys):
    assert main(["encode", "--payload", "{}", "--secret", SENTINEL_SECRET,
                 "--header", "kid=key-1",
                 "--header", 'amr=["pwd","mfa"]',
                 "--header", "n=7",
                 "--header", "ok=true"]) == 0
    token = capsys.readouterr().out.strip()

    assert main(["decode", token]) == 0
    import json
    header = json.loads(capsys.readouterr().out)["header"]
    assert header["kid"] == "key-1"          # not valid JSON -> kept as a string
    assert header["amr"] == ["pwd", "mfa"]   # valid JSON -> parsed
    assert header["n"] == 7
    assert header["ok"] is True


def test_header_value_may_contain_equals_signs(capsys):
    """Only the first `=` separates; the rest belongs to the value."""
    assert main(["encode", "--payload", "{}", "--secret", SENTINEL_SECRET,
                 "--header", "x5t=abc=def="]) == 0
    token = capsys.readouterr().out.strip()
    assert main(["decode", token]) == 0
    import json
    assert json.loads(capsys.readouterr().out)["header"]["x5t"] == "abc=def="


# ---------------------------------------------------------------------------
# Reading both the token/payload and the secret from stdin
# ---------------------------------------------------------------------------
# One stream, two consumers: whoever read first would leave the other with an
# empty string. It must be refused explicitly rather than failing obscurely.


def test_token_and_secret_both_from_stdin_is_refused(capsys):
    assert main(["decode", "-", "--verify", "--secret-stdin"]) == 1
    err = capsys.readouterr().err
    assert "stdin" in err
    assert "error:" in err


def test_payload_and_secret_both_from_stdin_is_refused(capsys):
    assert main(["encode", "--payload", "-", "--secret-stdin"]) == 1
    assert "stdin" in capsys.readouterr().err


def test_two_secret_sources_at_once_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["encode", "--payload", "{}", "--secret", "a", "--secret-env", "B"])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# strip_one_trailing_newline
# ---------------------------------------------------------------------------
# A secret file written on Windows ends CRLF; one written on Linux ends LF.
# Both must yield the same secret, and only ONE terminator may be removed --
# stripping more would silently change the key material.


@pytest.mark.parametrize("raw,expected", [
    ("secret\n", "secret"),
    ("secret\r\n", "secret"),
    ("secret", "secret"),
    ("secret\n\n", "secret\n"),
    ("secret\r\n\r\n", "secret\r\n"),
    ("  secret  \n", "  secret  "),
    ("multi\nline\n", "multi\nline"),
    ("", ""),
    ("\n", ""),
    ("\r\n", ""),
])
def test_exactly_one_trailing_newline_is_stripped(raw, expected):
    assert strip_one_trailing_newline(raw) == expected


def test_crlf_and_lf_secret_files_produce_the_same_token(tmp_path, capsys):
    lf = tmp_path / "lf.key"
    crlf = tmp_path / "crlf.key"
    lf.write_bytes(SENTINEL_SECRET.encode() + b"\n")
    crlf.write_bytes(SENTINEL_SECRET.encode() + b"\r\n")

    assert main(["encode", "--payload", '{"a":1}', "--secret-file", str(lf)]) == 0
    from_lf = capsys.readouterr().out.strip()
    assert main(["encode", "--payload", '{"a":1}', "--secret-file", str(crlf)]) == 0
    from_crlf = capsys.readouterr().out.strip()

    assert from_lf == from_crlf


def test_a_secret_file_of_only_a_newline_is_an_empty_secret(tmp_path, capsys):
    empty = tmp_path / "empty.key"
    empty.write_text("\n", encoding="utf-8")
    assert main(["encode", "--payload", "{}", "--secret-file", str(empty)]) == 1
    assert "error:" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# resolve_secret rejects a blank secret rather than signing with nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_blank_secret_is_rejected_on_encode(blank, capsys):
    assert main(["encode", "--payload", "{}", "--secret", blank]) == 1
    err = capsys.readouterr().err
    assert "error:" in err


def test_secret_error_is_raised_not_swallowed():
    """resolve_secret's own failure type, so the CLI maps it to exit 1."""
    import argparse

    from jwt_tool.secrets import resolve_secret

    args = argparse.Namespace(secret=None, secret_env="DEFINITELY_NOT_SET_XYZ",
                              secret_file=None, secret_stdin=False)
    with pytest.raises(SecretError) as exc:
        resolve_secret(args, required=True)
    assert "DEFINITELY_NOT_SET_XYZ" in str(exc.value)


# ---------------------------------------------------------------------------
# The allowlist guard on decode_token's own `algorithm` argument
# ---------------------------------------------------------------------------
# argparse's `choices=` blocks a bad value at the CLI, but decode_token is
# exported from the package and callable directly, so the guard has to hold
# there too -- otherwise an asymmetric name would reach PyJWT, which would try
# to parse the HMAC secret as an RSA key and raise something unrelated.


@pytest.mark.parametrize("algorithm", ["RS256", "ES256", "none", "", "hs256", "HS128"])
def test_decode_token_rejects_an_algorithm_outside_the_allowlist(algorithm):
    from jwt_tool import decode_token
    from jwt_tool.errors import AlgorithmError

    token = encode_token({"sub": "alice"}, SENTINEL_SECRET)
    with pytest.raises(AlgorithmError) as exc:
        decode_token(token, secret=SENTINEL_SECRET, algorithm=algorithm, verify=True)
    assert "allowlist" in str(exc.value)


def test_cli_accepts_a_valid_expires_in_and_adds_the_claims(capsys):
    """The success path of the --expires-in converter, not just its rejections."""
    import json

    assert main(["encode", "--payload", '{"sub":"alice"}',
                 "--secret", SENTINEL_SECRET, "--expires-in", "3600"]) == 0
    token = capsys.readouterr().out.strip()

    assert main(["decode", token]) == 0
    payload = json.loads(capsys.readouterr().out)["payload"]
    assert isinstance(payload["exp"], int)
    assert isinstance(payload["iat"], int)
    assert payload["exp"] - payload["iat"] == 3600
