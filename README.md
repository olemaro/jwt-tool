# jwt-tool

A small command-line tool for decoding, encoding, and HMAC-signing JSON Web
Tokens (JWTs).

## Install

```bash
python -m venv .venv
```

Activate it — PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

POSIX (macOS/Linux):

```bash
source .venv/bin/activate
```

Then, from the repo root:

```bash
pip install -e .
```

This installs the `jwt-tool` command on your `PATH`. If you haven't activated
the venv, you can also run it as `python -m jwt_tool ...`.

## Usage

Every flag is documented in `jwt-tool --help`; `jwt-tool --version` prints
the installed package version.

### Encode, then decode with verification (round trip)

PowerShell:

```powershell
$env:JWT_TOOL_SECRET = "9f1c9e6b7a3d4c8e9b2a5f6d7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e"
$token = jwt-tool encode --payload '{"sub":"alice","role":"admin"}' --secret-env JWT_TOOL_SECRET
jwt-tool decode $token --verify --secret-env JWT_TOOL_SECRET
```

POSIX:

```bash
export JWT_TOOL_SECRET="9f1c9e6b7a3d4c8e9b2a5f6d7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e"
token=$(jwt-tool encode --payload '{"sub":"alice","role":"admin"}' --secret-env JWT_TOOL_SECRET)
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET
```

`decode --verify` fails closed: it needs a secret, checks the signature
against an explicit algorithm allowlist, and exits non-zero (see
[Exit codes](#exit-codes)) if the check fails.

### Decode without verifying

```bash
jwt-tool decode "$token"
```

This never needs a secret. It prints the header and payload as-is and sets
`"signature_verified": false` in the JSON — see
[Security notes](#security-notes).

### Piping into `jq`

stdout carries only the result, so it's safe to pipe:

```bash
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET | jq '.payload.role'
# "admin"
```

`--compact` collapses the JSON to one line if you'd rather not pretty-print
before piping:

```bash
jwt-tool decode "$token" --compact | jq '.payload'
```

### Reading a token from stdin (`-`)

```bash
echo "$token" | jwt-tool decode - --verify --secret-env JWT_TOOL_SECRET
```

`encode` supports the same convention for its payload:

```bash
echo '{"sub":"alice"}' | jwt-tool encode --payload - --secret-env JWT_TOOL_SECRET
```

### A few more flags

```bash
# Pin the algorithm explicitly instead of accepting the default (HS256) or, on
# verify, the full allowlist.
jwt-tool encode --payload '{"sub":"alice"}' --secret-env JWT_TOOL_SECRET --algorithm HS512

# Add exp/iat (seconds from now).
jwt-tool encode --payload '{"sub":"alice"}' --secret-env JWT_TOOL_SECRET --expires-in 300

# Tolerate clock skew between the signing and verifying host when verifying.
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET --leeway 60

# Add extra JOSE header fields (K=V, repeatable; value parsed as JSON if
# possible, else kept as a string). Headers can never override "alg".
jwt-tool encode --payload '{"sub":"alice"}' --secret-env JWT_TOOL_SECRET --header kid=my-key-1
```

## Secret handling

In order of preference:

1. `--secret-env VAR` — read the secret from environment variable `VAR`.
   `VAR` is always explicit: there is deliberately no default, both so the
   flag cannot swallow the token argument and so `jwt-tool` can never pick up
   an application's real signing key (commonly `JWT_SECRET`) by accident.
2. `--secret-file PATH` — read it from a file (one trailing newline is
   stripped).
3. `--secret-stdin` — pipe it in on stdin.
4. Omit all secret flags on an interactive terminal — `jwt-tool` prompts with
   `getpass`, so the value is never echoed and never becomes a shell
   argument.

The ranking above is by convenience-with-safety, not strictly by exposure.
Two caveats worth knowing:

- `--secret-env` has the widest blast radius of the three scriptable options:
  the value is inherited by *every* child process for the rest of the shell
  session, and the `export`/`$env:` command that sets it lands in shell
  history just as surely as `--secret` would. It is safer than `--secret` only
  in that it stays out of this process's argument list.
- `--secret-stdin` is the safest scriptable option — no argv, no environment,
  no disk — but only if the upstream producer is also safe:
  `echo 'secret' | jwt-tool --secret-stdin` leaks via `echo`'s own argv and
  history, defeating the point. Read from a file or a secrets manager instead.
- `--secret-file` is safe only if the file's permissions are. `jwt-tool` does
  not check them.

Regardless of the source, the secret lives as an ordinary Python string for
the life of the process; it cannot be zeroed or pinned, so a crash dump or
swapped memory can capture it. That is inherent to pure Python, not something
this tool can fix.

`--secret VALUE` *(literal, on the command line)* also exists, but is
**discouraged**: anything passed as a CLI argument is visible to other users
on the same machine via `ps`/Task Manager for as long as the process runs,
and it lands permanently in your shell history file. `jwt-tool` prints a
warning to stderr every time `--secret` is used, precisely because of this:

```bash
jwt-tool encode --payload '{"sub":"alice"}' --secret 'do-not-do-this-in-real-life'  # discouraged — see above
```

## Security notes

- `decode` never verifies a signature unless you pass `--verify`, and it says
  so: every unverified decode prints
  `warning: signature NOT verified (decode only); pass --verify with a secret to check it`
  to stderr, and the JSON on stdout carries `"signature_verified": false` so
  a script can check this without parsing stderr.
- Verification always checks the signature against an **explicit algorithm
  allowlist** that `jwt-tool` controls (`--algorithm`, or the full
  `HS256`/`HS384`/`HS512` set if omitted) — it never trusts the `alg` named
  in the token's own header. That's what makes the classic `alg:none` bypass
  and RS/HS algorithm-confusion attacks structurally unreachable here. See
  [docs/LIBRARY-EVALUATION.md](docs/LIBRARY-EVALUATION.md) for the measured
  PyJWT behavior this design defends against.
- **`signature_verified: true` does not mean "this token is valid for my
  service."** It means the HMAC signature and the time-based claims (`exp`,
  `nbf`, `iat`) checked out. `aud` and `iss` are **not** verified — a token
  minted for a different service that happens to share the same secret still
  reports `true`. To make that unambiguous rather than buried in prose, every
  decode reports exactly what ran:

  ```json
  "claims_checked": ["signature", "exp", "nbf", "iat"]
  ```

  and `[]` for an unverified decode. If you need an audience or issuer check,
  compare `payload.aud` / `payload.iss` yourself — for example
  `jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET | jq -e '.payload.aud == "my-api"'`.
- HMAC-only by design: `HS256`/`HS384`/`HS512` are the only algorithms
  `jwt-tool` will ever encode or verify with.
- Short secrets get an advisory (non-blocking) warning on stderr. The floor is
  the digest size, per
  [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2): 32 bytes
  for HS256, 48 for HS384, 64 for HS512.
- Time-based claims are checked with no clock-skew tolerance by default. Use
  `--leeway SECONDS` when the signing and verifying machines disagree slightly
  about the time, otherwise a freshly-minted token can be rejected as "not yet
  valid".
- **Decoded payloads are printed verbatim, including any PII the token
  carries** (email, name, `sub`, roles). Treat `jwt-tool decode` output the
  same way you would treat the token itself: it ends up in shell history, CI
  job logs and terminal scrollback.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A `JwtToolError` (bad token, failed/rejected signature, bad payload, bad or missing secret, disallowed algorithm) — printed as `error: <message>` on stderr, no traceback |
| 2 | Argument-parsing error (unknown flag, missing required flag, bad `--expires-in`, negative `--leeway`) |

## Running the tests

```bash
pip install -e ".[dev]"

python scripts/run-tests.py     # both suites + artifacts, one command
```

Or run them separately:

```bash
pytest                          # unit + integration (182 tests)
python scripts/smoke.py         # end-to-end against the real CLI (72 checks)
```

`scripts/run-tests.py` runs both — a pytest failure does not skip the smoke
test, since "does the CLI still work at all" is exactly what you want to know
when the unit tests are red — and writes `artifacts/`:

| File | Contents |
| --- | --- |
| `summary.md`, `summary.json` | Totals, coverage, pass/fail |
| `pytest-junit.xml`, `smoke-junit.xml` | JUnit reports, for CI |
| `smoke.log` | Full transcript: every command, its exit code, its output |
| `smoke-results.json` | One structured record per smoke check |
| `smoke-tokens.json`, `smoke-tokens.txt` | Every JWT the run touched, with its decoded header and payload |
| `coverage.xml`, `coverage-html/` | Coverage report |

The smoke run narrates itself. Each check prints the command it invoked, the
exit code, stdout and stderr, and what it observed — so a failure is readable
without a debugger, and a pass can be audited instead of trusted:

```text
  $ jwt-tool decode a.b.c.d
    exit=1  (456 ms)
    stdout: <empty>
    stderr: error: Invalid header padding
  PASS  malformed (four segments): non-zero exit, no traceback, empty stdout
```

The secret is masked before anything is printed or written, so no artifact
carries it. `--quiet` drops the transcript for CI; `--no-artifacts` writes
nothing.

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/MANUAL.md](docs/MANUAL.md) | Full reference: every command and flag, secret handling, exit codes, troubleshooting. |
| [docs/SCENARIOS.md](docs/SCENARIOS.md) | Worked end-to-end scenarios with expected output, including the attack cases. |
| [docs/LIBRARY-EVALUATION.md](docs/LIBRARY-EVALUATION.md) | Why PyJWT, measured against `python-jwt` and `jwt-decode`. |
| [docs/CONTRACT.md](docs/CONTRACT.md) | The interface contract the implementation was built against. |

## License

MIT — see [LICENSE](LICENSE).
