"""Secret resolution for jwt-tool.

A JWT secret must never be leaked to stdout, logged, or embedded in an error
message. This module implements the single recommended entry point,
:func:`resolve_secret`, which knows about every supported secret source and
centralises that precedence/validation so ``decode`` and ``encode`` behave
identically.

Supported sources, exactly one of which may be given (mutual exclusion is
enforced by argparse in :mod:`jwt_tool.cli`):

- ``--secret VALUE``     literal value; warns on stderr (leaks via ``ps`` /
                          shell history).
- ``--secret-env VAR``   read ``os.environ[VAR]``; ``VAR`` is always
                          explicit (see the note in :mod:`jwt_tool.cli`).
- ``--secret-file PATH`` read PATH, stripping exactly one trailing newline.
- ``--secret-stdin``     read all of stdin, stripping exactly one trailing
                          newline.
- none of the above      interactive TTY -> ``getpass``; non-interactive ->
                          ``SecretError`` (only when a secret is required).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from typing import TextIO

from jwt_tool.errors import SecretError

_INSECURE_SECRET_WARNING = (
    "warning: --secret exposes the secret in process listings (e.g. `ps`) "
    "and in shell history; prefer --secret-env, --secret-file, or "
    "--secret-stdin instead"
)

_NO_SOURCE_ERROR = (
    "no secret provided; pass --secret-env, --secret-file, --secret-stdin "
    "(or, for quick local testing only, --secret), or run interactively to "
    "be prompted"
)


def resolve_secret(
    args: argparse.Namespace,
    *,
    required: bool,
    stdin: TextIO | None = None,
    isatty: Callable[[], bool] | None = None,
) -> str | None:
    """Resolve the JWT secret from whichever source the user selected.

    ``args`` is the parsed CLI namespace; it must carry the ``secret``,
    ``secret_env``, ``secret_file`` and ``secret_stdin`` attributes produced
    by the shared secret-source parent parser in :mod:`jwt_tool.cli`. Exactly
    one of those may be set (argparse enforces this via a mutually exclusive
    group), or none at all.

    :param args: parsed CLI namespace (see above).
    :param required: whether a secret is mandatory for the calling command
        (``True`` for ``encode``; ``True`` for ``decode --verify``). When
        ``False`` and no source was given, this returns ``None`` instead of
        prompting or raising.
    :param stdin: stream to read from for ``--secret-stdin`` and for the
        interactive fallback's TTY check; defaults to ``sys.stdin``. Exposed
        as a parameter so tests can supply a fake stream.
    :param isatty: zero-argument callable reporting whether the input stream
        is an interactive terminal; defaults to ``stdin.isatty``. Kept
        separate from ``stdin`` so tests can simulate a TTY without needing
        a real one (e.g. a ``StringIO`` is never a TTY on its own).
    :returns: the secret string, or ``None`` when not required and no source
        was given.
    :raises SecretError: the selected source is missing, unreadable, or
        empty, or no source was given while a secret was required.
    """
    if stdin is None:
        stdin = sys.stdin
    if isatty is None:
        isatty = stdin.isatty

    value: str | None

    if args.secret is not None:
        print(_INSECURE_SECRET_WARNING, file=sys.stderr)
        value = args.secret
    elif args.secret_env is not None:
        value = _read_secret_env(args.secret_env)
    elif args.secret_file is not None:
        value = _read_secret_file(args.secret_file)
    elif args.secret_stdin:
        value = strip_one_trailing_newline(stdin.read())
    elif required:
        if isatty():
            value = getpass.getpass("Secret: ")
        else:
            raise SecretError(_NO_SOURCE_ERROR)
    else:
        return None

    if required and not value:
        raise SecretError("resolved secret is empty")
    return value


def _read_secret_env(var: str) -> str:
    """Read the secret from environment variable ``var``."""
    try:
        return os.environ[var]
    except KeyError:
        raise SecretError(f"environment variable {var!r} is not set") from None


def _read_secret_file(path: str) -> str:
    """Read the secret from ``path``, stripping one trailing newline."""
    try:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            raw = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise SecretError(f"cannot read secret file {path!r}: {exc}") from None
    return strip_one_trailing_newline(raw)


def strip_one_trailing_newline(value: str) -> str:
    """Strip exactly one trailing newline (``\\n`` or ``\\r\\n``), no more."""
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value
