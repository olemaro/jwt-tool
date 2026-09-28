"""Command-line interface for jwt-tool.

Design rules this module enforces (see ``docs/CONTRACT.md`` section 4):

- stdout carries ONLY the machine-readable result (the decoded JSON, or the
  bare encoded token) so it composes with tools like ``jq``. Everything else
  -- warnings, the interactive secret prompt, and error messages -- goes to
  stderr.
- :func:`main` returns an exit code; it never calls ``sys.exit`` itself.
  argparse still exits directly (code 2 for usage errors, 0 for
  ``--help``/``--version``); that is argparse's documented behaviour via
  ``parser.error()``/``parser.exit()`` and is left alone.
- Only :class:`~jwt_tool.errors.JwtToolError` is caught and turned into a
  clean ``error: <message>`` line on stderr; anything else is a bug and is
  left to propagate with its traceback.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from jwt_tool import __version__
from jwt_tool.core import (
    ALLOWED_ALGORITHMS,
    DEFAULT_ALGORITHM,
    min_secret_bytes,
    decode_token,
    encode_token,
    parse_payload,
    secret_is_weak,
)
from jwt_tool.errors import JwtToolError, SecretError
from jwt_tool.secrets import resolve_secret, strip_one_trailing_newline

_DESCRIPTION = """\
Encode and decode JSON Web Tokens (JWT).

Secret handling: avoid --secret VALUE for anything but a quick local test --
it is visible to other users on the machine (`ps`, task manager) and is
saved in your shell history. Prefer --secret-env, --secret-file or
--secret-stdin, or omit the secret flags entirely on an interactive
terminal to be prompted with getpass (input is not echoed)."""

_EPILOG = """\
examples:
  # Recommended: secret via environment variable
  export JWT_TOOL_SECRET=$(openssl rand -base64 32)
  jwt-tool encode --payload '{"sub": "alice"}' --secret-env JWT_TOOL_SECRET --expires-in 3600

  # Recommended: secret from a file, e.g. a mounted Kubernetes/Docker secret
  jwt-tool decode "$TOKEN" --verify --secret-file /run/secrets/jwt_secret

  # Recommended: secret piped in, never touching argv, env or shell history
  jwt-tool encode --payload '{"sub": "alice"}' --secret-stdin < /run/secrets/jwt

  # Convenience only (INSECURE - leaks via `ps` / shell history); fine for
  # quick local testing:
  jwt-tool decode "$TOKEN" --verify --secret 'only-for-local-testing'

Run `jwt-tool <command> --help` for the flags of a specific command."""

_DECODE_EPILOG = """\
examples:
  jwt-tool decode "$TOKEN"
  jwt-tool decode "$TOKEN" --verify --secret-env JWT_TOOL_SECRET
  echo "$TOKEN" | jwt-tool decode - --verify --secret-file ./secret.key
"""

_ENCODE_EPILOG = """\
examples:
  jwt-tool encode --payload '{"sub": "alice"}' --secret-env JWT_TOOL_SECRET
  jwt-tool encode --payload - --secret-env JWT_SIGNING_KEY < payload.json
  jwt-tool encode --payload '{"sub": "alice"}' --secret-env JWT_TOOL_SECRET --expires-in 3600 --header kid=my-key-1
"""


def _positive_int(raw: str) -> int:
    """argparse ``type=`` for ``--expires-in``: seconds, strictly positive."""
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not an integer") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer (seconds), got {value}"
        )
    return value


def _non_negative_int(raw: str) -> int:
    """argparse ``type=`` for ``--leeway``: seconds, zero or more."""
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not an integer") from None
    if value < 0:
        raise argparse.ArgumentTypeError(
            f"must be zero or a positive integer (seconds), got {value}"
        )
    return value


def _header_pair(raw: str) -> tuple[str, Any]:
    """argparse ``type=`` for ``--header K=V``.

    Splits once on ``=``; the value is JSON-decoded when possible (so
    ``--header amr='["pwd"]'`` yields a list) and kept as a plain string
    otherwise (so ``--header kid=my-key-1`` yields the string ``"my-key-1"``).
    """
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"{raw!r} is not in K=V form")
    key, _, raw_value = raw.partition("=")
    if not key:
        raise argparse.ArgumentTypeError(f"{raw!r} is missing a header name before '='")
    try:
        value: Any = json.loads(raw_value)
    except json.JSONDecodeError:
        value = raw_value
    return key, value


def _reject_stdin_conflict(*, other_uses_stdin: bool, secret_stdin: bool) -> None:
    """Refuse to read both the secret and the token/payload from stdin at once.

    ``--secret-stdin`` combined with a ``-`` token/payload would otherwise
    silently read an empty string for the second consumer of stdin.
    """
    if other_uses_stdin and secret_stdin:
        raise SecretError(
            "cannot read both the secret (--secret-stdin) and the "
            "token/payload ('-') from stdin at the same time; use "
            "--secret-env or --secret-file instead"
        )


def _print_json(data: dict[str, Any], *, compact: bool) -> None:
    """Print ``data`` to stdout as JSON; this is the only thing decode writes to stdout."""
    if compact:
        print(json.dumps(data, sort_keys=False))
    else:
        print(json.dumps(data, indent=2, sort_keys=False))


def _warn_if_weak_secret(secret: str | None, algorithm: str | None) -> None:
    """Warn on stderr if ``secret`` is shorter than RFC 7518 recommends.

    Advisory only -- ``secret_is_weak`` never blocks anything, per contract.
    core.encode_token/decode_token suppress PyJWT's own InsecureKeyLengthWarning
    so this is the single place that warning reaches the user, and it never
    prints the secret itself.
    """
    alg = algorithm or DEFAULT_ALGORITHM
    if secret and secret_is_weak(secret, alg):
        print(
            f"warning: secret is shorter than {min_secret_bytes(alg)} bytes, "
            f"the minimum RFC 7518 section 3.2 recommends for {alg}",
            file=sys.stderr,
        )


def _run_decode(args: argparse.Namespace) -> int:
    """Handle ``jwt-tool decode``. Returns the process exit code."""
    _reject_stdin_conflict(
        other_uses_stdin=(args.token == "-"), secret_stdin=args.secret_stdin
    )

    token = (
        strip_one_trailing_newline(sys.stdin.read())
        if args.token == "-"
        else args.token
    )

    secret = resolve_secret(args, required=args.verify)
    _warn_if_weak_secret(secret, args.algorithm)

    decoded = decode_token(
        token,
        secret=secret,
        algorithm=args.algorithm,
        verify=args.verify,
        leeway=args.leeway,
    )

    if not args.verify:
        print(
            "warning: signature NOT verified (decode only); "
            "pass --verify with a secret to check it",
            file=sys.stderr,
        )
        if args.algorithm is not None:
            print(
                "warning: --algorithm only constrains --verify and was "
                "ignored; the token's own 'alg' header is never trusted",
                file=sys.stderr,
            )

    result = {
        "header": decoded.header,
        "payload": decoded.payload,
        "signature_verified": decoded.signature_verified,
        # Spelled out so a script can tell what was actually validated.
        # "signature_verified": true does NOT mean "valid for my service":
        # aud and iss are never checked. See README's Security notes.
        "claims_checked": list(decoded.claims_checked),
    }
    _print_json(result, compact=args.compact)
    return 0


def _run_encode(args: argparse.Namespace) -> int:
    """Handle ``jwt-tool encode``. Returns the process exit code."""
    _reject_stdin_conflict(
        other_uses_stdin=(args.payload == "-"), secret_stdin=args.secret_stdin
    )

    raw_payload = sys.stdin.read() if args.payload == "-" else args.payload
    payload = parse_payload(raw_payload)

    secret = resolve_secret(args, required=True)
    _warn_if_weak_secret(secret, args.algorithm)

    extra_headers = dict(args.header) if args.header else None

    token = encode_token(
        payload,
        secret,
        algorithm=args.algorithm,
        extra_headers=extra_headers,
        expires_in=args.expires_in,
    )
    print(token)
    return 0


def _build_secret_parent() -> argparse.ArgumentParser:
    """Shared, mutually-exclusive secret-source flags for decode and encode.

    Defined once here and inherited via ``parents=[...]`` on both
    subparsers so the flag definitions live in exactly one place and cannot
    drift apart between ``decode`` and ``encode``.
    """
    parent = argparse.ArgumentParser(add_help=False)
    group = parent.add_argument_group("secret source (choose at most one)")
    mutex = group.add_mutually_exclusive_group()
    mutex.add_argument(
        "--secret",
        metavar="VALUE",
        help=(
            "secret as a literal value. INSECURE: visible via `ps`/task "
            "manager and saved in shell history; use only for quick local "
            "testing"
        ),
    )
    mutex.add_argument(
        "--secret-env",
        default=None,
        metavar="VAR",
        help=(
            "read the secret from environment variable VAR, e.g. "
            "--secret-env JWT_TOOL_SECRET. Recommended. VAR is always "
            "explicit: an implicit default would both swallow the token "
            "argument and risk silently picking up an application's real "
            "signing key"
        ),
    )
    mutex.add_argument(
        "--secret-file",
        metavar="PATH",
        help="read the secret from PATH, e.g. a mounted secret file. Recommended.",
    )
    mutex.add_argument(
        "--secret-stdin",
        action="store_true",
        help=(
            "read the secret from stdin. Recommended. Cannot be combined "
            "with reading the token/payload from stdin via '-'."
        ),
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    """Build the ``jwt-tool`` argument parser (``decode`` and ``encode`` subcommands)."""
    secret_parent = _build_secret_parent()

    parser = argparse.ArgumentParser(
        prog="jwt-tool",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        required=True,
        metavar="{decode,encode}",
    )

    decode_parser = subparsers.add_parser(
        "decode",
        parents=[secret_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="decode a JWT and print its header/payload as JSON",
        description=(
            "Decode a JWT and print {header, payload, signature_verified} "
            "as JSON on stdout."
        ),
        epilog=_DECODE_EPILOG,
    )
    decode_parser.add_argument(
        "token", help="the JWT to decode, or '-' to read it from stdin"
    )
    decode_parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "verify the signature (requires a secret source above); "
            "without this flag the token is parsed but NOT cryptographically "
            "checked"
        ),
    )
    decode_parser.add_argument(
        "--algorithm",
        choices=ALLOWED_ALGORITHMS,
        default=None,
        metavar="ALG",
        help=(
            f"restrict --verify to this algorithm ({', '.join(ALLOWED_ALGORITHMS)}); "
            "default: accept any allowlisted algorithm. The token's own "
            "header 'alg' is never trusted"
        ),
    )
    decode_parser.add_argument(
        "--leeway",
        type=_non_negative_int,
        default=0,
        metavar="SECONDS",
        help=(
            "clock-skew tolerance for exp/nbf/iat when verifying "
            "(default: 0). Useful when the signing and verifying machines "
            "disagree slightly about the time"
        ),
    )
    decode_parser.add_argument(
        "--compact",
        action="store_true",
        help="print the result JSON on one line instead of indented",
    )
    decode_parser.set_defaults(func=_run_decode)

    encode_parser = subparsers.add_parser(
        "encode",
        parents=[secret_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="sign a JSON payload into a JWT",
        description="Sign a JSON object payload into a JWT and print the token on stdout.",
        epilog=_ENCODE_EPILOG,
    )
    encode_parser.add_argument(
        "--payload",
        required=True,
        metavar="JSON",
        help="the payload as a JSON object, or '-' to read it from stdin",
    )
    encode_parser.add_argument(
        "--algorithm",
        choices=ALLOWED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        metavar="ALG",
        help=(
            f"signing algorithm ({', '.join(ALLOWED_ALGORITHMS)}); "
            f"default: {DEFAULT_ALGORITHM}"
        ),
    )
    encode_parser.add_argument(
        "--expires-in",
        type=_positive_int,
        default=None,
        metavar="SECONDS",
        help=(
            "add 'exp' (and 'iat') claims SECONDS from now; must be a "
            "positive integer. Omitted: exp/iat are left untouched"
        ),
    )
    encode_parser.add_argument(
        "--header",
        action="append",
        type=_header_pair,
        default=None,
        metavar="K=V",
        help=(
            "extra JOSE header field, repeatable; V is JSON-decoded when "
            "possible, else kept as a string. Cannot be used to change 'alg'"
        ),
    )
    encode_parser.add_argument(
        "--compact",
        action="store_true",
        help=(
            "accepted for symmetry with 'decode'; the token is always "
            "printed bare on one line regardless"
        ),
    )
    encode_parser.set_defaults(func=_run_encode)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse ``argv``, run the selected command, return an exit code.

    Only :class:`~jwt_tool.errors.JwtToolError` is caught here (printed as
    ``error: <message>`` on stderr, exit code 1). argparse handles its own
    usage errors and ``--help``/``--version`` by exiting directly (code 2,
    or 0 respectively) -- that ``SystemExit`` is intentionally left to
    propagate rather than being caught here.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except JwtToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
