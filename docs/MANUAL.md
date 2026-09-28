# jwt-tool manual

A command-line tool for inspecting, creating and verifying JSON Web Tokens
signed with HMAC.

- [Synopsis](#synopsis)
- [Installation](#installation)
- [`decode`](#decode)
- [`encode`](#encode)
- [Supplying the secret](#supplying-the-secret)
- [Output format](#output-format)
- [Exit codes](#exit-codes)
- [What verification does and does not cover](#what-verification-does-and-does-not-cover)
- [Algorithms and key length](#algorithms-and-key-length)
- [Troubleshooting](#troubleshooting)
- [Running the test suites](#running-the-test-suites)

## Synopsis

```text
jwt-tool [--version] [--help] {decode,encode} ...

jwt-tool decode <token|-> [--verify] [--algorithm ALG] [--leeway SECONDS]
                          [--compact] [<secret source>]

jwt-tool encode --payload <json|-> [--algorithm ALG] [--expires-in SECONDS]
                                   [--header K=V ...] [--compact]
                                   [<secret source>]

<secret source> := --secret-env VAR | --secret-file PATH | --secret-stdin
                 | --secret VALUE        (discouraged; see below)
                 | (omitted — prompts on an interactive terminal)
```

Two rules hold everywhere and are worth knowing up front:

1. **stdout carries only the result.** `decode` writes one JSON object;
   `encode` writes the bare token. Warnings, prompts and errors go to stderr.
   This is what makes `jwt-tool decode … | jq` safe.
2. **The algorithm is never taken from the token.** Verification always uses an
   allowlist the tool controls, so a token cannot nominate its own algorithm.

## Installation

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .
```

That puts a `jwt-tool` executable on `PATH`. Without installing, the module
form works from a checkout:

```bash
PYTHONPATH=src python -m jwt_tool --help
```

Every example below writes `jwt-tool`; substitute the module form if you
prefer not to install.

## `decode`

Reads a token and prints its header and claims. **By default it does not check
the signature** — it parses and displays, nothing more.

```bash
jwt-tool decode "$token"
```

Because that is a genuinely dangerous default to forget, each unverified
decode prints a warning to stderr and reports `"signature_verified": false` in
the JSON, so a script can detect it without reading stderr.

Pass `-` instead of a token to read it from stdin:

```bash
echo "$token" | jwt-tool decode -
```

### Verifying

```bash
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET
```

`--verify` requires a secret and exits non-zero if the signature, `exp`, `nbf`
or `iat` fails. Read
[What verification does and does not cover](#what-verification-does-and-does-not-cover)
before relying on a success.

| Option | Effect |
| --- | --- |
| `--verify` | Check the signature and the time-based claims. Requires a secret. |
| `--algorithm ALG` | Restrict verification to one of `HS256`, `HS384`, `HS512`. Without it, any of the three is accepted. Only meaningful with `--verify`; the tool warns if you pass it alone. |
| `--leeway SECONDS` | Clock-skew tolerance for `exp`/`nbf`/`iat`. Default `0`. |
| `--compact` | Print the JSON on one line instead of indented. |

## `encode`

Signs a JSON object into a token and prints it, bare, on stdout.

```bash
jwt-tool encode --payload '{"sub":"alice","role":"admin"}' \
                --secret-env JWT_TOOL_SECRET
```

The payload must be a JSON **object**. An array, string, number or `null` is
rejected, because JWT claims sets are objects. `--payload -` reads the JSON
from stdin.

| Option | Effect |
| --- | --- |
| `--payload JSON` | Required. The claims as a JSON object, or `-` for stdin. |
| `--algorithm ALG` | `HS256` (default), `HS384` or `HS512`. |
| `--expires-in SECONDS` | Add `exp` (now + SECONDS) **and** `iat`. Must be a positive integer. |
| `--header K=V` | Add a JOSE header field; repeatable. `V` is parsed as JSON when it parses, otherwise kept as a string. |
| `--compact` | Accepted for symmetry with `decode`; the token is always one line, so this does nothing. |

Two deliberate behaviours:

- **Nothing is added that you did not ask for.** Without `--expires-in`, no
  `exp`, `iat`, `nbf` or `jti` appears. An `exp` you put in the payload
  yourself is left untouched.
- **`--header` cannot change `alg`.** `--header alg=none` is discarded. This
  matters because the underlying library prefers a header's `alg` over the
  requested algorithm, so forwarding headers naively would be an allowlist
  bypass.

## Supplying the secret

Listed by convenience, with the trade-offs spelled out rather than implied.

| Source | Notes |
| --- | --- |
| `--secret-env VAR` | Read from environment variable `VAR`. `VAR` is mandatory — there is no default, so the tool cannot quietly pick up an application's real key (often named `JWT_SECRET`). |
| `--secret-file PATH` | Read from a file; exactly one trailing newline is stripped. The tool does **not** check the file's permissions. |
| `--secret-stdin` | Read from stdin. Cannot be combined with `-` for the token or payload; the tool refuses rather than silently reading an empty string. |
| *(omitted)* | On an interactive terminal you are prompted via `getpass`, so nothing is echoed. Non-interactively this is an error, never a silent empty secret. |
| `--secret VALUE` | **Discouraged.** Visible to other local users through `ps`/Task Manager for the process's lifetime, and saved in shell history. The tool prints a warning on stderr every time it is used. |

Caveats that the ordering alone does not convey:

- `--secret-env` has the widest blast radius of the scriptable options: the
  value is inherited by every child process for the rest of the shell session,
  and the `export` that set it is in your history just as surely as `--secret`
  would be.
- `--secret-stdin` is the safest scriptable option — no argv, no environment,
  no disk — but only if its producer is safe too. `echo 'secret' | jwt-tool
  --secret-stdin` leaks through `echo`'s own argv and history.
- Whatever the source, the secret is an ordinary Python string for the life of
  the process. It cannot be zeroed or pinned, so a crash dump or swapped
  memory can capture it. That is inherent to pure Python.

The secret never appears on stdout, in an error message, or in a warning.

## Output format

`decode` prints one JSON object:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "alice",
    "role": "admin"
  },
  "signature_verified": true,
  "claims_checked": [
    "signature",
    "exp",
    "nbf",
    "iat"
  ]
}
```

`claims_checked` is `[]` after a decode without `--verify`. It exists so that
what was actually validated is machine-readable rather than something you have
to infer from a boolean — see the next section.

`encode` prints the token alone, followed by a newline.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | An expected failure: malformed token, failed signature, expired or not-yet-valid token, bad payload, missing or unreadable secret, disallowed algorithm. Printed as `error: <message>` on stderr, never a traceback. |
| `2` | Usage error from argument parsing: unknown flag, missing required option, non-positive `--expires-in`, negative `--leeway`, two secret sources at once. |

All expected failures share exit code `1`; distinguish them by the message on
stderr, not by the code.

## What verification does and does not cover

`"signature_verified": true` means the HMAC signature verified and the
time-based claims (`exp`, `nbf`, `iat`) passed.

It does **not** mean the token is valid for your service. `aud` and `iss` are
returned but not checked. A token minted for a different service that happens
to share the same HMAC secret still reports `true`. That is why every decode
reports `claims_checked` explicitly.

To check an audience, compare it yourself:

```bash
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET \
  | jq -e '.payload.aud == "my-api"'
```

What the design does close off:

- **`alg: none`** cannot be signed (it is not in the allowlist) and is rejected
  on verification with a clear `AlgorithmError` rather than a misleading
  signature failure.
- **Algorithm confusion** (the RS256↔HS256 class) is structurally unreachable:
  the tool never holds an asymmetric public key, and the secret always comes
  from you out-of-band, so the attack has no foothold.
- **Signature reuse with modified claims** — tampering with the payload while
  keeping a previously valid signature — fails, as it must.

## Algorithms and key length

`HS256`, `HS384` and `HS512` only, by design. Asymmetric algorithms and
`alg: none` are refused on both encoding and verification.

Short secrets get a non-blocking advisory on stderr. The minimum follows the
digest size, per [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2):

| Algorithm | Minimum recommended secret |
| --- | --- |
| `HS256` | 32 bytes |
| `HS384` | 48 bytes |
| `HS512` | 64 bytes |

A 32-byte secret is therefore fine for `HS256` and flagged as short for
`HS512`. The advisory never blocks the operation.

## Troubleshooting

**`error: Not enough segments`** — the input is not a three-part JWT. Check for
a truncated copy-paste.

**`error: Invalid crypto padding` on a token that looks right** — there is
almost certainly trailing whitespace or a newline. Whitespace is rejected
rather than trimmed, deliberately: guessing at malformed input is worse than
refusing it. `jwt-tool decode -` strips exactly one trailing newline, so
`echo "$token" | jwt-tool decode -` works.

**`error: token is not yet valid` on a token you just created** — the signing
and verifying clocks disagree. Add `--leeway 60`.

**`error: signature verification failed`** — the secret does not match, or the
token was altered after signing.

**`error: The specified alg value is not allowed`** — the token uses an
algorithm outside `HS256`/`HS384`/`HS512`, possibly `none`.

**`warning: --algorithm only constrains --verify and was ignored`** — you
restricted the algorithm without asking for verification. Add `--verify`.

**No output and exit code 2** — a usage error; the message is on stderr.

## Running the test suites

```bash
pip install -e ".[dev]"
pytest                      # unit and integration suite
python scripts/smoke.py     # end-to-end smoke test against the real CLI
```

`pytest` needs no install step from a checkout: `pyproject.toml` sets
`pythonpath = ["src"]`. `scripts/smoke.py` adds `src` to `PYTHONPATH` itself,
prints one PASS/FAIL line per check, and exits non-zero if any fails.

The two suites overlap on purpose. The unit suite exercises the API in-process;
the smoke test types commands at the CLI the way a person would, covering
argument parsing, exit codes and the stdout/stderr split. Each has caught
defects the other missed.

See [SCENARIOS.md](SCENARIOS.md) for worked end-to-end scenarios with expected
output.
