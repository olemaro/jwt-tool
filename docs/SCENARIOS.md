# jwt-tool scenarios

Worked end-to-end scenarios with the commands to run and what you should see.
Every one of these is also asserted automatically by `scripts/smoke.py`, so if
a scenario here stops matching reality, that script fails.

Examples use POSIX shell. PowerShell equivalents are given where the
difference matters. Set up a secret first:

```bash
export JWT_TOOL_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

```powershell
$env:JWT_TOOL_SECRET = (python -c 'import secrets; print(secrets.token_urlsafe(48))')
```

48 bytes of entropy gives a 64-character secret, which clears the recommended
minimum for all three algorithms, so no short-secret advisory appears in the
output below. Scenario 13 exercises that advisory deliberately.

- [1. Round trip: sign, then verify](#1-round-trip-sign-then-verify)
- [2. Inspect a token you do not have the key for](#2-inspect-a-token-you-do-not-have-the-key-for)
- [3. A wrong secret is rejected](#3-a-wrong-secret-is-rejected)
- [4. Tampering with the payload is rejected](#4-tampering-with-the-payload-is-rejected)
- [5. An `alg: none` token cannot sneak through](#5-an-alg-none-token-cannot-sneak-through)
- [6. Expiry](#6-expiry)
- [7. Clock skew between two machines](#7-clock-skew-between-two-machines)
- [8. Tokens with `aud`: what verification does not tell you](#8-tokens-with-aud-what-verification-does-not-tell-you)
- [9. Malformed input fails cleanly](#9-malformed-input-fails-cleanly)
- [10. Keeping the secret out of argv and history](#10-keeping-the-secret-out-of-argv-and-history)
- [11. Scripting: piping into jq](#11-scripting-piping-into-jq)
- [12. Exit codes in a script](#12-exit-codes-in-a-script)
- [13. Algorithm and header control](#13-algorithm-and-header-control)

## 1. Round trip: sign, then verify

The core requirement: a token this tool produces, this tool can read back.

```bash
token=$(jwt-tool encode --payload '{"sub":"alice","role":"admin"}' \
                        --secret-env JWT_TOOL_SECRET)
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET
```

Expected — exit `0`, and:

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

Note the payload contains exactly what you supplied. No `iat`, `nbf` or `jti`
was invented on your behalf.

## 2. Inspect a token you do not have the key for

Decoding needs no secret. This is the everyday debugging case.

```bash
jwt-tool decode "$token"
```

Expected — exit `0`, the same `header` and `payload`, and:

```json
  "signature_verified": false,
  "claims_checked": []
```

On **stderr**:

```text
warning: signature NOT verified (decode only); pass --verify with a secret to check it
```

The warning is on stderr, so `jwt-tool decode "$token" | jq .payload` still
works. The `false` in the JSON is the signal a script should test.

## 3. A wrong secret is rejected

```bash
jwt-tool decode "$token" --verify --secret 'not-the-right-secret'; echo "exit=$?"
```

Expected — `exit=1`, nothing on stdout, and on stderr:

```text
warning: --secret exposes the secret in process listings (e.g. `ps`) and in shell history; …
error: signature verification failed
```

Two things to notice: no claims are printed when verification fails, and
`--secret` warned about itself.

## 4. Tampering with the payload is rejected

Take a valid token, swap in an escalated payload, keep the original signature.
This is the shape of the vulnerability that was found in `python-jwt`
(CVE-2022-39227), so it is worth seeing fail.

```bash
forged=$(python - "$token" <<'EOF'
import base64, json, sys
head, _payload, sig = sys.argv[1].split(".")
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
print(f'{head}.{b(json.dumps({"sub": "alice", "role": "superadmin"}).encode())}.{sig}')
EOF
)
jwt-tool decode "$forged" --verify --secret-env JWT_TOOL_SECRET; echo "exit=$?"
```

Expected — `exit=1`, `error: signature verification failed`, no payload on
stdout.

Decoding it *without* `--verify` does show `role: superadmin` — correctly, since
that is what the token says. That is exactly why `signature_verified` exists.

## 5. An `alg: none` token cannot sneak through

```bash
none_token=$(python - <<'EOF'
import base64, json
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
print(f'{b(json.dumps({"alg":"none","typ":"JWT"}).encode())}.'
      f'{b(json.dumps({"sub":"attacker","role":"admin"}).encode())}.')
EOF
)
jwt-tool decode "$none_token" --verify --secret-env JWT_TOOL_SECRET; echo "exit=$?"
```

Expected — `exit=1` and `error: The specified alg value is not allowed`.

The error names the real reason. It is not reported as a signature failure and
not reported as a malformed token.

You also cannot produce such a token:

```bash
jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET --algorithm none
```

Expected — `exit=2`; `none` is not among the accepted `--algorithm` values.
And `--header alg=none` is discarded rather than honoured:

```bash
t=$(jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET --header alg=none)
jwt-tool decode "$t" | jq -r .header.alg
```

Expected — `HS256`. The `alg` you tried to inject was dropped.

## 6. Expiry

```bash
short=$(jwt-tool encode --payload '{"sub":"alice"}' \
                        --secret-env JWT_TOOL_SECRET --expires-in 1)
jwt-tool decode "$short" --verify --secret-env JWT_TOOL_SECRET   # succeeds now
sleep 2
jwt-tool decode "$short" --verify --secret-env JWT_TOOL_SECRET; echo "exit=$?"
```

Expected — the first call exits `0`; after the pause, `exit=1` with
`error: token has expired`.

`--expires-in` adds `exp` **and** `iat`, both integer epoch seconds. Verify it:

```bash
jwt-tool decode "$short" --compact | python -m json.tool | grep -E 'exp|iat'
```

## 7. Clock skew between two machines

A token whose `iat` is slightly in the future — the signing host's clock runs
fast — is rejected by default, because the tolerance is zero.

```bash
skewed=$(python - <<'EOF'
import json, subprocess, time
payload = json.dumps({"sub": "alice", "iat": int(time.time()) + 30})
print(subprocess.run(["jwt-tool", "encode", "--payload", payload,
                      "--secret-env", "JWT_TOOL_SECRET"],
                     capture_output=True, text=True).stdout.strip())
EOF
)
jwt-tool decode "$skewed" --verify --secret-env JWT_TOOL_SECRET; echo "exit=$?"
jwt-tool decode "$skewed" --verify --secret-env JWT_TOOL_SECRET --leeway 60; echo "exit=$?"
```

Expected — first `exit=1` with `error: token is not yet valid`, then `exit=0`.

`--leeway` does not resurrect a long-expired token; it only widens the boundary.

## 8. Tokens with `aud`: what verification does not tell you

```bash
aud_token=$(jwt-tool encode --payload '{"sub":"alice","aud":"billing-api"}' \
                            --secret-env JWT_TOOL_SECRET)
jwt-tool decode "$aud_token" --verify --secret-env JWT_TOOL_SECRET
```

Expected — `exit=0`, `"signature_verified": true`, and `claims_checked` listing
`signature`, `exp`, `nbf`, `iat` — **not** `aud`.

That is the point of this scenario. The token says it is for `billing-api`, and
verification succeeded, but nothing checked whether `billing-api` is *you*. If
the same secret is shared between services, a token for one verifies against
another. Check it yourself:

```bash
jwt-tool decode "$aud_token" --verify --secret-env JWT_TOOL_SECRET \
  | jq -e '.payload.aud == "my-api"' > /dev/null \
  && echo "audience ok" || echo "WRONG AUDIENCE"
```

Expected — `WRONG AUDIENCE`, because the token is for `billing-api`.

## 9. Malformed input fails cleanly

Every one of these exits non-zero, prints `error: …` on stderr, writes nothing
to stdout, and never shows a traceback.

```bash
for bad in "" "abc" "a.b" "a.b.c.d" "!!!.!!!.!!!"; do
  jwt-tool decode "$bad" >/dev/null 2>&1
  echo "input=${bad:-<empty>} exit=$?"
done
```

Expected — `exit=1` for each.

A payload segment that is valid base64 and valid JSON but *not an object* is
also refused, because a JWT claims set must be an object:

```bash
jwt-tool decode "$(python -c "
import base64,json
b=lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
print(f\"{b(json.dumps({'alg':'HS256'}).encode())}.{b(json.dumps([1,2]).encode())}.x\")")"
echo "exit=$?"
```

Expected — `exit=1`, `error: Invalid payload string: must be a json object`.

The same applies on the encode side:

```bash
jwt-tool encode --payload '[1,2]'    --secret-env JWT_TOOL_SECRET; echo "exit=$?"
jwt-tool encode --payload '{not json' --secret-env JWT_TOOL_SECRET; echo "exit=$?"
```

Expected — `exit=1` for both, with `payload must be a JSON object` and a JSON
parse error including the position.

## 10. Keeping the secret out of argv and history

All three of these produce the **same** token, because each reads the identical
secret through a different channel.

```bash
# From the environment
jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET

# From a file (one trailing newline is stripped)
printf '%s\n' "$JWT_TOOL_SECRET" > /tmp/jwt.key && chmod 600 /tmp/jwt.key
jwt-tool encode --payload '{"a":1}' --secret-file /tmp/jwt.key

# From stdin, reading the file rather than echoing the value
jwt-tool encode --payload '{"a":1}' --secret-stdin < /tmp/jwt.key
```

Expected — three identical tokens, and **no warning** on stderr for any of
them. Compare with `--secret`:

```bash
jwt-tool encode --payload '{"a":1}' --secret "$JWT_TOOL_SECRET" 2>&1 >/dev/null
```

Expected — a warning naming `ps` and shell history.

Failure modes are explicit rather than silent:

```bash
jwt-tool encode --payload '{"a":1}' --secret-env NO_SUCH_VAR; echo "exit=$?"
jwt-tool encode --payload '{"a":1}' < /dev/null; echo "exit=$?"
echo "$token" | jwt-tool decode - --verify --secret-stdin; echo "exit=$?"
```

Expected — `exit=1` naming `NO_SUCH_VAR`; `exit=1` listing the secret options
(rather than prompting, since stdin is not a terminal); and `exit=1` refusing
to read both the token and the secret from stdin.

Omit the secret flags on a real terminal and you are prompted instead, with no
echo:

```bash
jwt-tool encode --payload '{"a":1}'
# Secret:
```

## 11. Scripting: piping into jq

stdout is only ever the result, so it pipes cleanly.

```bash
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET | jq -r '.payload.role'
```

Expected — `admin`, with the process's warnings (if any) still visible on your
terminal via stderr but absent from the pipe.

Guard on verification rather than trusting the exit code alone:

```bash
jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET \
  | jq -e '.signature_verified and (.claims_checked | index("signature"))' >/dev/null \
  && echo "trusted"
```

`--compact` gives one line per token, convenient for logs or `while read`:

```bash
jwt-tool decode "$token" --compact
```

## 12. Exit codes in a script

```bash
if jwt-tool decode "$token" --verify --secret-env JWT_TOOL_SECRET >/dev/null 2>&1; then
  echo "valid"
else
  case $? in
    1) echo "rejected: bad token, bad signature, or expired" ;;
    2) echo "I called jwt-tool wrong" ;;
  esac
fi
```

`1` is every expected runtime failure; `2` is always your own usage mistake.
Confirm the split:

```bash
jwt-tool decode "garbage"          >/dev/null 2>&1; echo "malformed token -> $?"   # 1
jwt-tool decode "$token" --nope    >/dev/null 2>&1; echo "unknown flag    -> $?"   # 2
jwt-tool encode --secret-env JWT_TOOL_SECRET >/dev/null 2>&1; echo "no --payload -> $?"  # 2
jwt-tool encode --payload '{}' --secret-env JWT_TOOL_SECRET --expires-in 0 \
                                   >/dev/null 2>&1; echo "--expires-in 0  -> $?"   # 2
```

## 13. Algorithm and header control

Each algorithm round-trips, and pinning a different one on verification fails —
the token does not get to choose.

```bash
for alg in HS256 HS384 HS512; do
  t=$(jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET --algorithm "$alg")
  jwt-tool decode "$t" --verify --secret-env JWT_TOOL_SECRET --algorithm "$alg" >/dev/null \
    && echo "$alg round trip ok"
done

t384=$(jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET --algorithm HS384)
jwt-tool decode "$t384" --verify --secret-env JWT_TOOL_SECRET --algorithm HS256; echo "exit=$?"
```

Expected — three `round trip ok` lines, then `exit=1` for the mismatch.

`--algorithm` without `--verify` constrains nothing, and says so:

```bash
jwt-tool decode "$token" --algorithm HS256 2>&1 >/dev/null
```

Expected — `warning: --algorithm only constrains --verify and was ignored; …`.

Extra header fields, with `V` parsed as JSON when it can be:

```bash
t=$(jwt-tool encode --payload '{"a":1}' --secret-env JWT_TOOL_SECRET \
                    --header kid=key-1 --header amr='["pwd","mfa"]')
jwt-tool decode "$t" | jq .header
```

Expected:

```json
{
  "alg": "HS256",
  "amr": [
    "pwd",
    "mfa"
  ],
  "kid": "key-1",
  "typ": "JWT"
}
```

`kid` stayed a string; `amr` was parsed as a JSON array.

The secret-length advisory is per algorithm, following the digest size:

```bash
short=$(python -c 'print("y"*32)')
jwt-tool encode --payload '{}' --secret "$short" --algorithm HS256 2>&1 >/dev/null
jwt-tool encode --payload '{}' --secret "$short" --algorithm HS512 2>&1 >/dev/null
```

Expected — for `HS256`, only the `--secret` warning; for `HS512`, an additional
advisory that the secret is shorter than 64 bytes. Neither blocks the operation,
and neither prints the secret.
