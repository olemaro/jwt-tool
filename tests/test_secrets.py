"""Tests for jwt_tool.secrets.resolve_secret, written against CONTRACT.md section 3.

resolve_secret(args, *, required, stdin=None, isatty=None) is tested as a
plain function: `args` is a minimal namespace with the four argparse dest
attributes (secret, secret_env, secret_file, secret_stdin), and `stdin`
/`isatty` are the injectable overrides the contract's signature exposes, so
none of this needs real TTYs, real stdin, or subprocesses.
"""
from __future__ import annotations

import io

import pytest

from jwt_tool import errors
from jwt_tool import secrets as secrets_mod

from conftest import SENTINEL_SECRET, make_secret_args


# ---------------------------------------------------------------------------
# Each source works
# ---------------------------------------------------------------------------


def test_secret_flag_resolves_to_its_literal_value():
    args = make_secret_args(secret=SENTINEL_SECRET)
    result = secrets_mod.resolve_secret(args, required=True)
    assert result == SENTINEL_SECRET


def test_secret_env_flag_resolves_from_the_named_environment_variable(monkeypatch):
    monkeypatch.setenv("JWT_TOOL_TEST_SECRET_VAR", SENTINEL_SECRET)
    args = make_secret_args(secret_env="JWT_TOOL_TEST_SECRET_VAR")
    result = secrets_mod.resolve_secret(args, required=True)
    assert result == SENTINEL_SECRET


def test_secret_file_flag_resolves_from_file_contents(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_bytes(SENTINEL_SECRET.encode("utf-8") + b"\n")
    args = make_secret_args(secret_file=str(secret_file))
    result = secrets_mod.resolve_secret(args, required=True)
    assert result == SENTINEL_SECRET


def test_secret_stdin_flag_resolves_from_stdin_contents():
    args = make_secret_args(secret_stdin=True)
    stdin = io.StringIO(SENTINEL_SECRET + "\n")
    result = secrets_mod.resolve_secret(args, required=True, stdin=stdin)
    assert result == SENTINEL_SECRET


# ---------------------------------------------------------------------------
# --secret-env with an unset variable
# ---------------------------------------------------------------------------


def test_secret_env_with_unset_variable_raises_secret_error_naming_the_variable(monkeypatch):
    monkeypatch.delenv("JWT_TOOL_TEST_MISSING_VAR", raising=False)
    args = make_secret_args(secret_env="JWT_TOOL_TEST_MISSING_VAR")
    with pytest.raises(errors.SecretError, match="JWT_TOOL_TEST_MISSING_VAR"):
        secrets_mod.resolve_secret(args, required=True)


# ---------------------------------------------------------------------------
# --secret-file: missing path, newline stripping, whitespace preservation
# ---------------------------------------------------------------------------


def test_secret_file_with_missing_path_raises_secret_error(tmp_path):
    missing = tmp_path / "does-not-exist.txt"
    args = make_secret_args(secret_file=str(missing))
    with pytest.raises(errors.SecretError):
        secrets_mod.resolve_secret(args, required=True)


def test_secret_file_strips_exactly_one_trailing_newline(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_bytes(b"my-file-secret\n\n")  # two trailing newlines
    args = make_secret_args(secret_file=str(secret_file))
    result = secrets_mod.resolve_secret(args, required=True)
    # Only ONE trailing newline is stripped -- this is not a general
    # .rstrip() / .strip() call, so the second newline must survive.
    assert result == "my-file-secret\n"


def test_secret_file_with_meaningful_internal_and_trailing_whitespace_survives(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_bytes(b"  spaced out secret with trailing spaces   \n")
    args = make_secret_args(secret_file=str(secret_file))
    result = secrets_mod.resolve_secret(args, required=True)
    assert result == "  spaced out secret with trailing spaces   "


def test_secret_file_resolving_to_empty_string_when_required_raises_secret_error(tmp_path):
    secret_file = tmp_path / "empty.txt"
    secret_file.write_bytes(b"\n")  # strips down to ""
    args = make_secret_args(secret_file=str(secret_file))
    with pytest.raises(errors.SecretError):
        secrets_mod.resolve_secret(args, required=True)


def test_secret_stdin_strips_exactly_one_trailing_newline():
    args = make_secret_args(secret_stdin=True)
    stdin = io.StringIO("stdin-secret\n\n")
    result = secrets_mod.resolve_secret(args, required=True, stdin=stdin)
    assert result == "stdin-secret\n"


# ---------------------------------------------------------------------------
# No source given
# ---------------------------------------------------------------------------


def test_no_source_when_required_and_not_a_tty_raises_secret_error():
    args = make_secret_args()
    with pytest.raises(errors.SecretError):
        secrets_mod.resolve_secret(args, required=True, isatty=lambda: False)


def test_no_source_when_not_required_returns_none():
    args = make_secret_args()
    result = secrets_mod.resolve_secret(args, required=False, isatty=lambda: False)
    assert result is None


def test_no_source_when_required_and_a_tty_prompts_via_getpass(monkeypatch):
    calls = []

    def fake_getpass(prompt=""):
        calls.append(prompt)
        return SENTINEL_SECRET

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    args = make_secret_args()
    result = secrets_mod.resolve_secret(args, required=True, isatty=lambda: True)
    assert result == SENTINEL_SECRET
    assert calls, "expected getpass.getpass to be called"


# ---------------------------------------------------------------------------
# --secret warns on stderr; the other sources do not
# ---------------------------------------------------------------------------


def test_secret_flag_warns_on_stderr_without_echoing_the_value(capsys):
    args = make_secret_args(secret=SENTINEL_SECRET)
    secrets_mod.resolve_secret(args, required=True)
    captured = capsys.readouterr()
    assert captured.err.strip() != ""
    assert "warning" in captured.err.lower()
    assert SENTINEL_SECRET not in captured.err


def test_secret_env_flag_does_not_warn_on_stderr(monkeypatch, capsys):
    monkeypatch.setenv("JWT_TOOL_TEST_QUIET_VAR", SENTINEL_SECRET)
    args = make_secret_args(secret_env="JWT_TOOL_TEST_QUIET_VAR")
    secrets_mod.resolve_secret(args, required=True)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_secret_file_flag_does_not_warn_on_stderr(tmp_path, capsys):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_bytes(SENTINEL_SECRET.encode("utf-8") + b"\n")
    args = make_secret_args(secret_file=str(secret_file))
    secrets_mod.resolve_secret(args, required=True)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_secret_stdin_flag_does_not_warn_on_stderr(capsys):
    args = make_secret_args(secret_stdin=True)
    stdin = io.StringIO(SENTINEL_SECRET + "\n")
    secrets_mod.resolve_secret(args, required=True, stdin=stdin)
    captured = capsys.readouterr()
    assert captured.err == ""
