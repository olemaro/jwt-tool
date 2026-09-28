# jwt-tool — implementation contract

Frozen interface agreed before implementation. Modules are built against *this*
document, not against each other, so the pieces can be written in parallel.

- Language: Python 3.11+ (dev env: 3.13.15)
- JWT library: **PyJWT >= 2.8** (see `LIBRARY-EVALUATION.md` for why not `python-jwt`)
- Layout: `src/` layout, package `jwt_tool`, console script `jwt-tool`
- Tests: `pytest`

## 1. `jwt_tool/errors.py`

```python
class JwtToolError(Exception):          """Base for all expected failures; exit code 1."""
class InvalidTokenError(JwtToolError):  """Malformed / unparseable token."""
class SignatureError(JwtToolError):     """Signature verification failed or claim rejected."""
class PayloadError(JwtToolError):       """--payload is not a JSON object."""
class SecretError(JwtToolError):        """Secret missing, empty or unreadable."""
class AlgorithmError(JwtToolError):     """Algorithm not in the allowlist."""
```

Every message must be actionable and must NEVER echo the secret.

## 2. `jwt_tool/core.py`

```python
ALLOWED_ALGORITHMS: tuple[str, ...] = ("HS256", "HS384", "HS512")
DEFAULT_ALGORITHM: str = "HS256"
MIN_SECRET_BYTES_BY_ALGORITHM = {"HS256": 32, "HS384": 48, "HS512": 64}
MIN_SECRET_BYTES: int = 32          # RFC 7518 3.2 floor for the default alg

@dataclass(frozen=True)
class DecodedToken:
    header: dict[str, Any]
    payload: dict[str, Any]
    signature_verified: bool
    claims_checked: tuple[str, ...] = ()

def parse_payload(raw: str) -> dict[str, Any]
def encode_token(payload, secret, *, algorithm=DEFAULT_ALGORITHM,
                 extra_headers=None, expires_in=None) -> str
def decode_token(token, *, secret=None, algorithm=None, verify=False,
                 leeway=0) -> DecodedToken
def secret_is_weak(secret: str, algorithm: str = DEFAULT_ALGORITHM) -> bool
def min_secret_bytes(algorithm: str = DEFAULT_ALGORITHM) -> int
```

### `parse_payload(raw)`
- `json.loads`; on `JSONDecodeError` -> `PayloadError` including the position.
- Result MUST be a `dict`. A JSON array/string/number/null -> `PayloadError`
  ("payload must be a JSON object").

### `encode_token(...)`
- `algorithm` not in `ALLOWED_ALGORITHMS` -> `AlgorithmError`. This is what blocks
  `alg: none`; there is no opt-out.
- Empty/blank `secret` -> `SecretError`.
- `expires_in` (seconds, int > 0) adds `exp = now + expires_in` **and** `iat = now`,
  both integer UTC epoch seconds. `expires_in=None` adds nothing: we do not silently
  inject claims the caller did not ask for.
- An `exp` already present in the payload is NOT overwritten unless `expires_in` is given.
- `extra_headers` merged into the JOSE header; it must not be able to change `alg`.
- Returns `str` (PyJWT >= 2 already returns `str`; do not call `.decode()` on it).

### `decode_token(...)`
- Default `verify=False`: decode only, no key needed -> `signature_verified=False`.
  Use `jwt.get_unverified_header()` + `jwt.decode(..., options={"verify_signature": False})`.
- `verify=True`: `secret` is required (else `SecretError`) and the algorithm allowlist
  is passed explicitly to `jwt.decode(algorithms=[...])`. NEVER read `alg` out of the
  token header and trust it (alg-confusion / `alg:none` attack).
  - `algorithm=None` + `verify=True` -> allow the full `ALLOWED_ALGORITHMS` list.
  - `algorithm="HS256"` -> allowlist is exactly `["HS256"]`.
- **Every claim check is pinned explicitly** via `options=`, never inherited from
  PyJWT's defaults. This is not cosmetic: PyJWT defaults to `verify_aud: True`,
  and a token carrying an `aud` claim then fails with `InvalidAudienceError`
  unless `audience=` is also passed. Because that exception is an
  `InvalidTokenError` subclass, the first implementation reported it as a
  *malformed token* — meaning the tool could not verify a token it had just
  signed, and misdescribed why. Checks performed: `signature`, `exp`, `nbf`,
  `iat`. Checks pinned off: `aud`, `iss`, `sub`, `jti`.
- `claims_checked` reports what actually ran, so `signature_verified: true`
  cannot be misread as "valid for my service". `aud`/`iss` comparison is the
  caller's job and is documented as such in the README.
- `leeway` (seconds, default 0) sets clock-skew tolerance for the time-based
  claims. PyJWT's default of 0 rejects a token whose `iat` is even slightly in
  the future, which is routine when tokens move between hosts.
- Even with `verify=False`, a token whose header declares `alg: none` (or no `alg`)
  still decodes — but `signature_verified` stays `False`. With `verify=True` it must
  raise `AlgorithmError`.
- Exception mapping (PyJWT -> ours):
  - `jwt.InvalidSignatureError` -> `SignatureError("signature verification failed")`
  - `jwt.ExpiredSignatureError` -> `SignatureError("token has expired")`
  - `jwt.ImmatureSignatureError` -> `SignatureError(...)`
  - `jwt.InvalidAlgorithmError` -> `AlgorithmError`
  - `jwt.DecodeError` / `jwt.InvalidTokenError` -> `InvalidTokenError`
  Order matters: catch the specific subclasses before `InvalidTokenError`.
- Must reject with `InvalidTokenError` (not a traceback): empty string, `"abc"`,
  `"a.b"`, `"a.b.c.d"`, non-base64 segments, base64 that is not JSON, a payload
  segment that is valid JSON but not an object, and leading/trailing whitespace.

### `secret_is_weak(secret)`
- `True` when the secret is shorter than `min_secret_bytes(algorithm)`. The floor
  is the digest size (32/48/64), not a flat 32: RFC 7518 §3.2 ties the minimum key
  size to the hash output, so a flat floor under-warns for HS384/HS512. Advisory only —
  callers warn, nothing blocks. PyJWT 2.15 raises its own
  `InsecureKeyLengthWarning`; suppress it inside core so we own the message.

## 3. `jwt_tool/secrets.py`

```python
def resolve_secret(args, *, required: bool, stdin=None, isatty=None) -> str | None
```
Exactly one source may be given (argparse enforces mutual exclusion):

| flag | behaviour |
|---|---|
| `--secret VALUE`   | literal. **Warn on stderr**: visible in `ps` output and shell history. |
| `--secret-env VAR` | read `os.environ[VAR]`; missing -> `SecretError` naming the var. `VAR` is mandatory: an optional-argument form would swallow the positional token, and a `JWT_SECRET` default risks picking up an application's real signing key. |
| `--secret-file PATH` | read file, strip ONE trailing newline; missing/unreadable -> `SecretError`. |
| `--secret-stdin`   | read all of stdin, strip one trailing newline. |
| none               | if `required`: interactive TTY -> `getpass.getpass("Secret: ")`; non-TTY -> `SecretError` listing the options. If not `required` -> `None`. |

Empty result when a secret was required -> `SecretError`. Never log the value.

## 4. `jwt_tool/cli.py`

```python
def build_parser() -> argparse.ArgumentParser
def main(argv: list[str] | None = None) -> int
```
`main` returns an exit code and must not call `sys.exit` itself.
`__main__.py` does `raise SystemExit(main())`.

```
jwt-tool decode <token> [--verify] [<secret source>] [--algorithm ALG] [--compact]
jwt-tool encode --payload JSON [<secret source>] [--algorithm ALG] [--expires-in N]
                [--header K=V ...] [--compact]
```
- `decode` also accepts the token as `-` to read it from stdin.
- `encode --payload -` reads the JSON payload from stdin.
- `--header K=V` repeatable; value parsed as JSON if possible, else kept as string.

### stdout / stderr split
- **stdout carries only the result**, so it pipes into `jq`:
  - `decode` -> `{"header": {...}, "payload": {...}, "signature_verified": bool}`
  - `encode` -> the token, bare, with a trailing newline
- Pretty-printed with `indent=2` and `sort_keys=False` by default; `--compact` gives
  one line. Warnings, prompts and errors go to **stderr** only.
- `decode` without `--verify` prints to stderr:
  `warning: signature NOT verified (decode only); pass --verify with a secret to check it`

### exit codes
| code | when |
|---|---|
| 0 | success |
| 1 | any `JwtToolError` — printed as `error: <message>` on stderr, no traceback |
| 2 | argparse usage error (unknown flag, missing required, bad `--expires-in`) |

`--help` must list every flag with a one-line description, and `--version` prints the
package version. Unexpected exceptions are NOT swallowed — only `JwtToolError` is.

## 5. Round-trip guarantee (the requirement "must be decodable by your tool")

`decode_token(encode_token(p, s), secret=s, verify=True).payload == p` for any
JSON-object payload `p` and non-empty `s`, when `expires_in` is not used.
