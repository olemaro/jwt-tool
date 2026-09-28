# Library evaluation: JWT handling for `jwt-tool`

`jwt-tool` needs a library that can do four distinct things: **decode** a token
without a key (read header/claims only), **encode** a payload into a JOSE
structure, **sign** that structure, and **verify** a signature against an
explicit algorithm. Three candidates were in scope: `PyJWT`, `python-jwt`, and
the npm package `jwt-decode`.

Everything below is either a fact **measured in this repo's venv**
(`C:\abccloudz\.venv`, Python 3.13.15, `PyJWT 2.15.0`, `python-jwt 4.1.0`,
checked 2026-09-28) or a statement **quoted from upstream** (PyPI project
pages, advisories, or the library's own docs). Each bullet says which. Nothing
here is inferred or assumed.

## Capability matrix

| Library | Decoding (no key) | Encoding | Signing | Signature verification |
|---|---|---|---|---|
| **PyJWT 2.15.0** | Yes — `get_unverified_header()`, `decode(options={"verify_signature": False})` | Yes — `encode()` | Yes — `encode()` (same call) | Yes — `decode(key, algorithms=[...])` |
| **python-jwt 4.1.0** | Yes — `process_jwt()` | Yes — `generate_jwt()` | Yes — `generate_jwt()` (same call; HMAC via a `jwcrypto` JWK) | Yes — `verify_jwt()`, but see caveats below (requires `exp`, requires a JWK object) |
| **jwt-decode (npm)** | Yes — its only function | No | No | No — upstream docs say explicitly not to use it for validation |

## PyJWT 2.15.0 — selected

Measured in this venv:

- `jwt.encode(payload, key, algorithm="HS256")` signs and returns a `str` in
  one call. Encoding and signing are the same operation here: **yes** to both.
- `jwt.decode(token, key, algorithms=["HS256"])` verifies the signature and
  returns the claims: **signature verification: yes**.
- `jwt.get_unverified_header(token)` returns the JOSE header with no key
  involved.
- `jwt.decode(token, options={"verify_signature": False})` returns the claims
  with no key involved. Between these two calls, **decode-only: yes** — PyJWT
  supports reading a token without ever needing a secret.
- A wrong key raises `jwt.exceptions.InvalidSignatureError`, one member of a
  deep, specific exception hierarchy: `DecodeError`, `ExpiredSignatureError`,
  `ImmatureSignatureError`, `InvalidAlgorithmError`, `InvalidAudienceError`,
  `InvalidIssuedAtError`, `InvalidIssuerError`, `InvalidKeyError`,
  `InvalidSignatureError`, `InvalidTokenError`, `MissingRequiredClaimError`,
  and more. This maps cleanly onto `jwt-tool`'s own error taxonomy
  (`jwt_tool/errors.py` in `docs/CONTRACT.md` §1).
- **`alg: none`, measured precisely.** The two halves behave differently, and
  the distinction matters:
  - *Signing* an unsecured token is possible. `jwt.encode({"a": 1}, None,
    algorithm="none")` produced `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhIjoxfQ.`
    (note the empty third segment). PyJWT will produce `alg: none` if a caller
    names it.
  - *Verifying* one is not. `jwt.decode(token, algorithms=["none"])` raises
    `InvalidSignatureError: Signature verification failed` — and so does
    passing `key=""` or widening the list to `["none", "HS256"]`. The only way
    to read such a token's claims is to opt out of verification entirely with
    `options={"verify_signature": False}`. PyJWT is therefore **stricter** on
    the verify path than "whitelist `none` and it passes".

  `jwt-tool` does not rely on that, for two reasons: it still needs to refuse
  to *sign* `alg: none`, and it wants a clear `AlgorithmError` ("not in the
  allowlist") rather than a misleading "signature verification failed". So the
  guarantee comes from *our* allowlist (`core.ALLOWED_ALGORITHMS` =
  `HS256`/`HS384`/`HS512`), which is checked before PyJWT is called on the
  encode path and passed explicitly as `algorithms=[...]` on the verify path.
  The token's own `alg` header is never read to choose an algorithm.
- **Measured gotcha that caused a real bug here:** `jwt.encode()` **prefers
  `headers["alg"]` over the `algorithm=` keyword**. Concretely,
  `jwt.encode({"a": 1}, secret, algorithm="HS256", headers={"alg": "none"})`
  returns a token whose header says `alg: none` with an empty signature — the
  validated `algorithm=` argument is silently overridden. Any wrapper that
  forwards user-supplied headers straight through therefore has an allowlist
  bypass. `core.encode_token` strips `alg` from `extra_headers` before the call
  for exactly this reason.
- **Measured gotcha that caused a second real bug here:** PyJWT's default
  options include `verify_aud: True`, and a token carrying an `aud` claim then
  fails with `InvalidAudienceError` unless the caller also passes `audience=`.
  Since `InvalidAudienceError` is an `InvalidTokenError` subclass, a naive
  mapping reports it as a *malformed token*. The effect was that `jwt-tool`
  could not verify a token it had just signed itself whenever the payload
  contained `aud` — which most real OIDC/OAuth2 tokens do. `core.py` now pins
  every claim check explicitly (`_VERIFY_OPTIONS`) instead of inheriting those
  defaults, and reports what it actually checked via `claims_checked`.
- PyJWT 2.15.0 raises `InsecureKeyLengthWarning` for short HMAC keys, citing
  RFC 7518 §3.2. The threshold is **per algorithm, not a flat 32**: it is the
  digest size, i.e. 32 bytes for HS256, 48 for HS384, 64 for HS512 (read from
  `HMACAlgorithm.check_key_length` in the installed source). `jwt-tool`
  suppresses the warning inside `core.py` and re-emits its own advisory on
  stderr via `secret_is_weak(secret, algorithm)`, so the wording and the
  channel stay ours to control.
- PyJWT can also turn that advisory into a hard failure via
  `options={"enforce_minimum_key_length": True}` — but **only on `decode`**.
  `encode()` accepts no `options` argument at all (`TypeError: PyJWT.encode()
  got an unexpected keyword argument 'options'`), so the option cannot cover
  the signing path. That asymmetry is why `jwt-tool` uses its own advisory for
  both directions rather than PyJWT's enforcement for one of them.
- **Minimum usable version: PyJWT 2.11.0.** `InsecureKeyLengthWarning` was
  added in 2.11.0 (per the upstream `CHANGELOG.rst`), and `core.py` imports it
  by name, so `pyproject.toml` pins `PyJWT>=2.11`. An earlier draft declared
  `>=2.8`, which would have failed at import time on 2.8–2.10.

## python-jwt 4.1.0 — rejected

Quoted from upstream (not our claim):

- The PyPI project page states, verbatim: **"All versions of python-jwt are
  now DEPRECATED. I don't have the time to maintain this module."**
- The same page records that versions 3.3.4+ fix **CVE-2022-39227**
  (advisory [GHSA-5p8v-58qm-c7fp](https://github.com/davedoesdev/python-jwt/security/advisories/GHSA-5p8v-58qm-c7fp)):
  *"lets an attacker with a valid token re-use its signature with modified
  claims."* Details cross-checked against the advisory itself and
  [OSV](https://osv.dev/vulnerability/GHSA-5p8v-58qm-c7fp):
  - **Severity: CVSS v3.1 9.1 (Critical)**; OSV additionally lists CVSS v4.0
    9.3 (Critical).
  - **Affected: 0.1.0 through 3.3.3. Fixed in 3.3.4.**
  - Root cause, quoted from the advisory: *"an inconsistency between the JWT
    parsers used by python-jwt and its dependency jwcrypto. By mixing compact
    and JSON [JWS] representations, an attacker can trick jwcrypto into
    parsing different claims than those over which the signature is
    validated."* So it is a serialization-confusion bug between two libraries,
    not a duplicate-key bug — worth stating precisely, because the same
    permissive `jwcrypto` parsing is still what sits under this library.
- An earlier note on the same page records that 1.0.0+ fixed a separate
  `alg:none` verification vulnerability — this library has shipped two distinct
  classes of forgery bug across its history.

Measured in this venv:

- Importing it prints `DeprecationWarning: The python_jwt module is
  deprecated`.
- Its API is `generate_jwt` / `verify_jwt` / `process_jwt` (`process_jwt` is
  the decode-without-verification call).
- It **requires** a `jwcrypto.jwk.JWK` object as the key. Passing a plain
  `str`/`bytes` secret is rejected outright: `ValueError: key is not a JWK
  object`. `jwt-tool`'s contract takes a plain string secret from
  `--secret`/`--secret-env`/`--secret-file`/`--secret-stdin`
  (`docs/CONTRACT.md` §3) — python-jwt cannot consume that shape without
  extra key-wrapping code we'd have to write and maintain ourselves.
- `generate_jwt` silently injects `iat`, `jti`, and `nbf` into the payload,
  and `exp` when a `lifetime` is passed. Observed output of
  `generate_jwt({"sub": "bob"}, key, "HS256", lifetime=<5 min>)`:
  ```
  {'exp': ..., 'iat': ..., 'jti': 'ECQLOmX8GnzX0oWyHOfL6Q', 'nbf': ..., 'sub': 'bob'}
  ```
  This directly conflicts with the contract's requirement that
  `encode_token` add nothing the caller didn't ask for (`docs/CONTRACT.md`
  §2).
- `verify_jwt` **requires** an `exp` claim to be present: verifying a token
  that `generate_jwt` had produced *without* a `lifetime` argument raised
  `_JWTError: exp claim not present`. The library's own generate/verify pair
  is therefore not symmetric by default — a token it happily creates, it then
  refuses to verify. That's a real footgun for a general-purpose encode/decode
  tool.
- It pulls in `jwcrypto` 1.6.1 and `cryptography` 50.0.1 — a materially
  heavier dependency tree than PyJWT (which has zero required dependencies)
  for a tool that only ever needs HMAC.
- It still calls the deprecated `datetime.utcnow()` internally, which emits
  `DeprecationWarning`s on Python 3.13.

## jwt-decode (npm) — not applicable

- Current version **4.0.0**, taken from the npm registry API
  (`https://registry.npmjs.org/jwt-decode/latest`), described there as
  *"Decode JWT tokens, mostly useful for browser applications."* The version is
  quoted from upstream metadata, not measured here — the package was never
  installed in this environment.
- Its README states verbatim, under an "IMPORTANT" callout: *"This library
  doesn't validate the token, any well-formed JWT can be decoded"*, and points
  readers at server-side libraries (`express-jwt`, `koa-jwt`) for validation.
- Its entire public API is two symbols: `jwtDecode(token, options?)` and an
  `InvalidTokenError` class thrown only for malformed input — not for signature
  or expiry failures. There is **no** encode, no sign, and no verify.
- Because `jwt-tool` must implement `encode` as well as `decode`/verify
  (`docs/CONTRACT.md` §4), `jwt-decode` alone could not cover even half the
  contract — the encode/sign half is entirely out of scope for it by design.
- Independently moot on this machine: `node` and `npm` are both absent from
  `PATH` (verified by running `node --version` and `npm --version`; both
  report "command not found"), so the JavaScript ecosystem wasn't reachable
  here at all, regardless of the library's feature gap.

## Decision

**PyJWT 2.15.0.** It is the only candidate that measurably covers all four
capabilities — decoding, encoding, signing, and signature verification —
through one small API. It takes a plain string secret (matching the
contract's `--secret*` flags with no extra wrapping), injects nothing into
the payload behind the caller's back, is actively maintained, and exposes a
granular exception hierarchy that maps cleanly onto `jwt-tool`'s own
`JwtToolError` subclasses. `python-jwt` is upstream-deprecated, has a
documented signature-reuse CVE, demands a `jwcrypto` key object instead of a
plain secret, and its own generate/verify pair isn't symmetric by default.
`jwt-decode` covers none of encode/sign/verify by design, and the runtime it
needs isn't even installed on this machine.

**Alternative considered and deferred: [`joserfc`](https://jose.authlib.org/).**
It is actively maintained and implements the JOSE family (JWS/JWE/JWK/JWA/JWT)
more completely than PyJWT, with a more modern typed API and a published
["Migrating from PyJWT" guide](https://jose.authlib.org/en/migrations/pyjwt/).
If this tool ever grows RS/ES algorithms, JWK handling or JWE, `joserfc` would
scale better without a rewrite. For an HMAC-only CLI today that breadth buys
nothing, and PyJWT is the more widely deployed and audited option, so the
choice is PyJWT with `joserfc` noted as the migration target if scope grows.
Using `jwcrypto` directly was rejected outright: its permissive
compact-vs-JSON parsing is the ingredient that made CVE-2022-39227 possible,
so wrapping it by hand reintroduces that risk class. Hand-rolling on stdlib
`hmac` was also rejected — base64url padding, constant-time comparison and
segment validation are exactly the adversarially-tested parts worth inheriting.

One deliberate design point worth stating explicitly: `jwt-tool` restricts
verification to an HMAC allowlist (`HS256`/`HS384`/`HS512`) and never trusts
the token's own `alg` header, so both the `alg:none` bypass and RS/HS
algorithm-confusion attacks are structurally unreachable in this tool — not
because PyJWT blocks them (measured above: it doesn't, if asked by name), but
because `jwt-tool` never lets the token pick its own algorithm.
