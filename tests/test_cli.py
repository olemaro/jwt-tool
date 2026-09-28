"""CLI-level tests for jwt-tool, written against CONTRACT.md section 4.

Driven through cli.main(argv) + capsys (never subprocess), because that is
what checks the int-return-code part of the contract cheaply. main() itself
must not call sys.exit() -- but argparse's own --help/--version/usage-error
handling calls sys.exit() internally regardless of what main() does (that's
just how argparse works), and CONTRACT.md's exit-code table lists "argparse
usage error" as its own row (code 2) -- so pytest.raises(SystemExit) is the
right expectation for those specific cases, not a workaround.
"""
from __future__ import annotations

import io
import json

import pytest

from jwt_tool import cli, core

from conftest import SENTINEL_SECRET

WRONG_SECRET = "a-totally-different-secret-value-that-is-also-long-enough"


# ---------------------------------------------------------------------------
# decode: happy path + stdout purity
# ---------------------------------------------------------------------------


def test_decode_of_a_known_good_token_exits_zero_with_expected_json_keys(capsys):
    token = core.encode_token({"sub": "alice"}, SENTINEL_SECRET)
    code = cli.main(["decode", token, "--verify", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 0
    data = json.loads(captured.out)
    assert data.keys() >= {"header", "payload", "signature_verified"}
    assert data["payload"] == {"sub": "alice"}
    assert data["signature_verified"] is True


def test_decode_stdout_is_parseable_json_with_the_warning_only_on_stderr(capsys):
    token = core.encode_token({"sub": "alice"}, SENTINEL_SECRET)
    code = cli.main(["decode", token])  # no --verify -> warns, but on stderr only
    captured = capsys.readouterr()

    assert code == 0
    json.loads(captured.out)  # must not raise: stdout is pure JSON
    expected_warning = (
        "warning: signature NOT verified (decode only); "
        "pass --verify with a secret to check it"
    )
    assert expected_warning in captured.err
    assert expected_warning not in captured.out


def test_decode_default_output_is_pretty_printed_multiline(capsys):
    token = core.encode_token({"a": 1, "b": 2}, SENTINEL_SECRET)
    cli.main(["decode", token, "--verify", "--secret", SENTINEL_SECRET])
    out = capsys.readouterr().out
    assert "\n" in out.strip()
    json.loads(out)


def test_decode_compact_output_is_single_line(capsys):
    token = core.encode_token({"a": 1, "b": {"c": 2}}, SENTINEL_SECRET)
    code = cli.main(["decode", token, "--verify", "--secret", SENTINEL_SECRET, "--compact"])
    out = capsys.readouterr().out

    assert code == 0
    assert out.strip().count("\n") == 0
    json.loads(out)


# ---------------------------------------------------------------------------
# encode: happy path + stdout purity
# ---------------------------------------------------------------------------


def test_encode_stdout_is_a_bare_three_segment_token_with_trailing_newline(capsys):
    code = cli.main(["encode", "--payload", '{"a": 1}', "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out.endswith("\n")
    token = captured.out.strip()
    assert token.count(".") == 2


def test_encode_compact_flag_is_accepted_and_output_stays_a_bare_token(capsys):
    code = cli.main(["encode", "--payload", '{"a": 1}', "--secret", SENTINEL_SECRET, "--compact"])
    out = capsys.readouterr().out

    assert code == 0
    assert out.strip().count(".") == 2
    assert out.strip().count("\n") == 0


# ---------------------------------------------------------------------------
# End-to-end round trip, through the CLI only
# ---------------------------------------------------------------------------


def test_encode_then_decode_round_trip_through_the_cli_preserves_payload(capsys):
    payload = {"user": "carol", "roles": ["admin", "editor"], "count": 3}

    code = cli.main(["encode", "--payload", json.dumps(payload), "--secret", SENTINEL_SECRET])
    token = capsys.readouterr().out.strip()
    assert code == 0

    code = cli.main(["decode", token, "--verify", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()
    assert code == 0
    data = json.loads(captured.out)
    assert data["payload"] == payload
    assert data["signature_verified"] is True


# ---------------------------------------------------------------------------
# Errors: exit code 1, stderr shape, no traceback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_token",
    [
        pytest.param("", id="empty-string"),
        pytest.param("abc", id="single-segment"),
        pytest.param("a.b", id="two-segments"),
        pytest.param("a.b.c.d", id="four-segments"),
        pytest.param("!!!.!!!.!!!", id="non-base64url"),
    ],
)
def test_decode_of_malformed_token_exits_1_with_error_prefix_and_empty_stdout(capsys, bad_token):
    code = cli.main(["decode", bad_token])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("error:")
    assert "Traceback" not in captured.err


def test_decode_with_wrong_secret_exits_1_with_no_traceback(monkeypatch, capsys):
    # Use --secret-env (not --secret) so stderr carries only the error line:
    # --secret is contractually required to also emit its own exposure
    # warning on stderr, which would be a second, unrelated line here.
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    monkeypatch.setenv("JWT_TOOL_TEST_WRONG_SECRET_VAR", WRONG_SECRET)
    code = cli.main(
        ["decode", token, "--verify", "--secret-env", "JWT_TOOL_TEST_WRONG_SECRET_VAR"]
    )
    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("error:")
    assert "Traceback" not in captured.err


def test_encode_with_malformed_payload_json_exits_1(capsys):
    code = cli.main(["encode", "--payload", "{not valid json", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.err.startswith("error:")


def test_encode_with_json_array_payload_exits_1(capsys):
    code = cli.main(["encode", "--payload", "[1, 2]", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 1
    assert captured.err.startswith("error:")


# ---------------------------------------------------------------------------
# argparse usage errors: SystemExit(2)
# ---------------------------------------------------------------------------


def test_unknown_flag_raises_systemexit_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["decode", "sometoken", "--this-flag-does-not-exist"])
    assert excinfo.value.code == 2


def test_encode_missing_required_payload_raises_systemexit_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["encode", "--secret", SENTINEL_SECRET])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("bad_value", ["0", "-5"])
def test_expires_in_non_positive_raises_systemexit_2(bad_value):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            ["encode", "--payload", "{}", "--secret", SENTINEL_SECRET, "--expires-in", bad_value]
        )
    assert excinfo.value.code == 2


def test_header_flag_without_equals_sign_raises_systemexit_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "encode",
                "--payload",
                "{}",
                "--secret",
                SENTINEL_SECRET,
                "--header",
                "no-equals-sign-here",
            ]
        )
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# --help / usage
# ---------------------------------------------------------------------------


def test_root_help_exits_0_and_mentions_both_subcommands(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "decode" in out
    assert "encode" in out


def test_decode_help_exits_0():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["decode", "--help"])
    assert excinfo.value.code == 0


def test_encode_help_exits_0():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["encode", "--help"])
    assert excinfo.value.code == 0


# ---------------------------------------------------------------------------
# --header K=V
# ---------------------------------------------------------------------------


def test_header_flag_value_reaches_the_decoded_header_as_a_string(capsys):
    code = cli.main(
        ["encode", "--payload", '{"a": 1}', "--secret", SENTINEL_SECRET, "--header", "kid=my-key-1"]
    )
    token = capsys.readouterr().out.strip()
    assert code == 0

    cli.main(["decode", token])
    data = json.loads(capsys.readouterr().out)
    assert data["header"]["kid"] == "my-key-1"


def test_header_flag_value_is_json_parsed_when_it_looks_like_json(capsys):
    code = cli.main(
        ["encode", "--payload", '{"a": 1}', "--secret", SENTINEL_SECRET, "--header", "count=5"]
    )
    token = capsys.readouterr().out.strip()
    assert code == 0

    cli.main(["decode", token])
    data = json.loads(capsys.readouterr().out)
    assert data["header"]["count"] == 5


# ---------------------------------------------------------------------------
# stdin: token/payload as "-"
# ---------------------------------------------------------------------------


def test_decode_reads_token_from_stdin_when_given_a_dash(monkeypatch, capsys):
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    monkeypatch.setattr("sys.stdin", io.StringIO(token))
    code = cli.main(["decode", "-", "--verify", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 0
    assert json.loads(captured.out)["payload"] == {"a": 1}


def test_encode_reads_payload_from_stdin_when_payload_is_a_dash(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO('{"a": 1}'))
    code = cli.main(["encode", "--payload", "-", "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out.strip().count(".") == 2


# ---------------------------------------------------------------------------
# The secret must never leak
# ---------------------------------------------------------------------------


def test_secret_never_appears_in_output_on_a_successful_encode(capsys):
    code = cli.main(["encode", "--payload", '{"a": 1}', "--secret", SENTINEL_SECRET])
    captured = capsys.readouterr()

    assert code == 0
    assert SENTINEL_SECRET not in captured.out
    assert SENTINEL_SECRET not in captured.err


def test_secret_never_appears_in_output_on_a_failing_decode(capsys):
    token = core.encode_token({"a": 1}, SENTINEL_SECRET)
    code = cli.main(["decode", token, "--verify", "--secret", WRONG_SECRET])
    captured = capsys.readouterr()

    assert code == 1
    assert SENTINEL_SECRET not in captured.out
    assert SENTINEL_SECRET not in captured.err
    assert WRONG_SECRET not in captured.out
    assert WRONG_SECRET not in captured.err
