"""End-to-end smoke test for jwt-tool.

    python scripts/smoke.py

Exits 0 when every check passes and 1 otherwise, printing one PASS/FAIL line
per check so a failure states what broke without needing a debugger.

This is deliberately not a pytest suite, and deliberately not written from
docs/CONTRACT.md. It was written from the original requirements and drives the
real CLI in a separate process -- the same commands a person would type. That
makes it an independent check: it catches drift between "what was asked for"
and "what was built", and it covers argument parsing, exit codes and the
stdout/stderr split, which in-process unit tests barely touch.

tests/ holds the unit and integration suite (run with `pytest`). The two
overlap on purpose: each has caught defects the other missed.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
SECRET = "acceptance-sentinel-secret-do-not-leak-0123456789"
PAYLOAD = '{"sub":"1234567890","name":"John Doe","admin":false,"n":42}'

results: list[tuple[bool, str, str]] = []


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(header: dict, payload: object, sig: str = "x") -> str:
    h = b64u(json.dumps(header).encode())
    p = b64u(json.dumps(payload).encode())
    return f"{h}.{p}.{sig}"


def run(args: list[str], *, stdin: str | None = None, env: dict | None = None):
    environ = {**os.environ, **(env or {})}
    # Also work from a bare checkout, not just an installed package: mirrors the
    # `pythonpath = ["src"]` that pyproject.toml already gives pytest.
    src_dir = str(REPO_ROOT / "src")
    prior = environ.get("PYTHONPATH")
    environ["PYTHONPATH"] = f"{src_dir}{os.pathsep}{prior}" if prior else src_dir
    return subprocess.run(
        [PY, "-m", "jwt_tool", *args],
        capture_output=True, text=True, input=stdin, cwd=REPO_ROOT, env=environ,
    )


def check(name: str, cond: object, detail: str = "") -> bool:
    ok = bool(cond)
    results.append((ok, name, detail))
    print(("PASS  " if ok else "FAIL  ") + name)
    if not ok and detail:
        print(f"        {detail}")
    return ok


def section(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


section("1. Task statement verbatim: encode --payload '<json>' --secret '<secret>'")
r = run(["encode", "--payload", PAYLOAD, "--secret", SECRET])
check("encode with literal --payload/--secret exits 0", r.returncode == 0,
      f"rc={r.returncode} stderr={r.stderr[:400]}")
token = r.stdout.strip()
check("encode prints a bare 3-segment JWT on stdout",
      token.count(".") == 2 and " " not in token, f"stdout={r.stdout!r}")
check("encode keeps warnings out of stdout", "warn" not in r.stdout.lower(), f"stdout={r.stdout!r}")
check("--secret warns about insecurity on stderr", "warn" in r.stderr.lower(), f"stderr={r.stderr!r}")
check("secret never appears in stdout", SECRET not in r.stdout)
check("secret never appears in stderr", SECRET not in r.stderr, f"stderr={r.stderr!r}")

section("2. Task statement verbatim: decode <token>")
r = run(["decode", token])
check("decode exits 0", r.returncode == 0, f"rc={r.returncode} stderr={r.stderr[:400]}")
out: dict = {}
try:
    out = json.loads(r.stdout)
    check("decode stdout is valid JSON on its own (pipeable to jq)", True)
except Exception as exc:  # noqa: BLE001
    check("decode stdout is valid JSON on its own (pipeable to jq)", False, f"{exc}: {r.stdout[:300]}")
check("decode shows the header",
      isinstance(out.get("header"), dict) and out.get("header", {}).get("alg") == "HS256", str(out)[:300])
check("decode shows the payload", out.get("payload", {}).get("name") == "John Doe", str(out)[:300])
check("ROUND TRIP: decoded payload == original payload",
      out.get("payload") == json.loads(PAYLOAD), f"got {out.get('payload')}")
check("plain decode reports signature NOT verified", out.get("signature_verified") is False, str(out)[:300])
check("plain decode warns on stderr that it did not verify", "verif" in r.stderr.lower(), f"stderr={r.stderr!r}")

section("3. Signature verification actually verifies")
r = run(["decode", token, "--verify", "--secret-env", "JWT_SECRET"], env={"JWT_SECRET": SECRET})
check("--verify with correct secret exits 0", r.returncode == 0, f"rc={r.returncode} stderr={r.stderr[:300]}")
if r.returncode == 0:
    check("--verify reports signature_verified=true",
          json.loads(r.stdout).get("signature_verified") is True, r.stdout[:200])

r = run(["decode", token, "--verify", "--secret-env", "JWT_SECRET"], env={"JWT_SECRET": "the-wrong-secret"})
check("--verify with WRONG secret exits non-zero", r.returncode != 0, f"rc={r.returncode}")
check("--verify with wrong secret leaks no payload on stdout", r.stdout.strip() == "", f"stdout={r.stdout!r}")

header_b64, _, sig = token.split(".")
escalated = b64u(json.dumps({**json.loads(PAYLOAD), "admin": True}).encode())
forged = f"{header_b64}.{escalated}.{sig}"
r = run(["decode", forged, "--verify", "--secret-env", "JWT_SECRET"], env={"JWT_SECRET": SECRET})
check("forged payload reusing a valid signature is REJECTED (CVE-2022-39227 class)",
      r.returncode != 0, f"rc={r.returncode} stdout={r.stdout[:200]}")

none_token = make_token({"alg": "none", "typ": "JWT"}, {"admin": True}, sig="")
r = run(["decode", none_token, "--verify", "--secret-env", "JWT_SECRET"], env={"JWT_SECRET": SECRET})
check("alg:none token is REJECTED under --verify", r.returncode != 0,
      f"rc={r.returncode} stdout={r.stdout[:200]}")

section("4. Malformed tokens -> graceful, non-zero exit")
malformed = [
    ("", "empty string"),
    ("abc", "not a JWT"),
    ("a.b", "two segments"),
    ("a.b.c.d", "four segments"),
    ("!!!.!!!.!!!", "non-base64 segments"),
    (make_token({"alg": "HS256"}, [1, 2]), "payload is a JSON array"),
    (f'{b64u(b"{}")}.{b64u(b"not-json")}.x', "payload is not JSON"),
]
for bad, label in malformed:
    r = run(["decode", bad])
    check(f"malformed ({label}): non-zero exit, no traceback, empty stdout",
          r.returncode != 0 and "Traceback" not in r.stderr and r.stdout.strip() == "",
          f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr[:200]}")

section("5. Secure secret sources")
r_env = run(["encode", "--payload", '{"a":1}', "--secret-env", "JWT_SECRET"], env={"JWT_SECRET": SECRET})
check("--secret-env encodes", r_env.returncode == 0 and r_env.stdout.strip().count(".") == 2,
      f"rc={r_env.returncode} {r_env.stderr[:200]}")
check("--secret-env does NOT warn about leaking", "warn" not in r_env.stderr.lower(), f"stderr={r_env.stderr!r}")

r_stdin = run(["encode", "--payload", '{"a":1}', "--secret-stdin"], stdin=SECRET + "\n")
check("--secret-stdin encodes", r_stdin.returncode == 0 and r_stdin.stdout.strip().count(".") == 2,
      f"rc={r_stdin.returncode} {r_stdin.stderr[:200]}")
check("--secret-stdin agrees with --secret-env (one trailing newline stripped)",
      r_stdin.stdout.strip() == r_env.stdout.strip(),
      f"{r_stdin.stdout.strip()[:60]} vs {r_env.stdout.strip()[:60]}")

secret_file = os.path.join(tempfile.mkdtemp(prefix="jwt-tool-smoke-"), "secret.txt")
with open(secret_file, "w", encoding="utf-8") as fh:
    fh.write(SECRET + "\n")
r_file = run(["encode", "--payload", '{"a":1}', "--secret-file", secret_file])
check("--secret-file encodes and agrees with the others",
      r_file.returncode == 0 and r_file.stdout.strip() == r_env.stdout.strip(),
      f"rc={r_file.returncode} {r_file.stderr[:200]}")

r = run(["encode", "--payload", '{"a":1}', "--secret-env", "NO_SUCH_VAR_XYZ"])
check("missing env var -> non-zero exit naming the variable",
      r.returncode != 0 and "NO_SUCH_VAR_XYZ" in r.stderr, f"rc={r.returncode} stderr={r.stderr[:200]}")
r = run(["encode", "--payload", '{"a":1}', "--secret-file", os.path.join(tempfile.gettempdir(), "no-such-file-xyz")])
check("missing secret file -> non-zero exit", r.returncode != 0, f"rc={r.returncode}")
r = run(["encode", "--payload", '{"a":1}'], stdin="")
check("no secret + non-TTY -> non-zero exit with guidance", r.returncode != 0, f"rc={r.returncode}")

section("6. Bad payloads and usage errors")
env = {"JWT_SECRET": SECRET}
r = run(["encode", "--payload", "{not json", "--secret-env", "JWT_SECRET"], env=env)
check("invalid JSON payload -> non-zero, no traceback",
      r.returncode != 0 and "Traceback" not in r.stderr, f"rc={r.returncode} stderr={r.stderr[:200]}")
r = run(["encode", "--payload", "[1,2]", "--secret-env", "JWT_SECRET"], env=env)
check("JSON array payload -> non-zero (claims must be an object)", r.returncode != 0, f"rc={r.returncode}")
r = run(["encode", "--payload", '{"a":1}', "--secret-env", "JWT_SECRET", "--algorithm", "none"], env=env)
check("--algorithm none is refused", r.returncode != 0, f"rc={r.returncode} stdout={r.stdout[:120]}")
r = run(["encode", "--payload", '{"a":1}', "--secret-env", "JWT_SECRET", "--algorithm", "RS256"], env=env)
check("--algorithm RS256 is refused (HMAC-only by design)", r.returncode != 0, f"rc={r.returncode}")
r = run(["decode", token, "--bogus-flag"])
check("unknown flag -> exit code 2", r.returncode == 2, f"rc={r.returncode}")
r = run(["encode", "--secret-env", "JWT_SECRET"], env=env)
check("missing --payload -> exit code 2", r.returncode == 2, f"rc={r.returncode}")
r = run(["encode", "--payload", '{"a":1}', "--secret-env", "JWT_SECRET", "--expires-in", "0"], env=env)
check("--expires-in 0 -> exit code 2", r.returncode == 2, f"rc={r.returncode}")

section("7. --help is useful")
r = run(["--help"])
check("--help exits 0", r.returncode == 0, f"rc={r.returncode} {r.stderr[:200]}")
check("--help lists both subcommands", "decode" in r.stdout and "encode" in r.stdout, r.stdout[:300])
for sub in ("decode", "encode"):
    rs = run([sub, "--help"])
    check(f"{sub} --help exits 0 and documents the secret flags",
          rs.returncode == 0 and "--secret-env" in rs.stdout, f"rc={rs.returncode} {rs.stdout[:300]}")

section("8. End-to-end through the CLI only")
rich = ('{"sub":"abc","roles":["a","b"],"nested":{"k":[1,2,{"deep":true}]},'
        '"unicode":"\u00dcn\u00efc\u00f8d\u00e9 \u2713","f":1.5,"nil":null}')
r = run(["encode", "--payload", rich, "--secret-file", secret_file, "--expires-in", "3600"])
check("encode with --expires-in exits 0", r.returncode == 0, f"rc={r.returncode} {r.stderr[:300]}")
if r.returncode == 0:
    r = run(["decode", r.stdout.strip(), "--verify", "--secret-file", secret_file])
    check("generated token is decodable AND verifiable by our own tool",
          r.returncode == 0, f"rc={r.returncode} {r.stderr[:300]}")
    if r.returncode == 0:
        got = json.loads(r.stdout)["payload"]
        check("all original claims survive the round trip",
              {k: v for k, v in got.items() if k not in ("exp", "iat")} == json.loads(rich), f"got {got}")
        check("--expires-in added integer exp and iat",
              isinstance(got.get("exp"), int) and isinstance(got.get("iat"), int), f"got {got}")

r = run(["encode", "--payload", '{"only":"this"}', "--secret-file", secret_file])
if r.returncode == 0:
    r = run(["decode", r.stdout.strip()])
    got = json.loads(r.stdout)["payload"] if r.returncode == 0 else {}
    check("without --expires-in NO claims are injected (unlike python-jwt)",
          got == {"only": "this"}, f"got {got}")

r = run(["decode", token, "--compact"])
check("--compact gives single-line JSON",
      r.returncode == 0 and r.stdout.strip().count("\n") == 0, f"stdout={r.stdout[:200]!r}")
r = run(["decode", "-"], stdin=token)
check("decode reads the token from stdin with '-'", r.returncode == 0, f"rc={r.returncode} {r.stderr[:200]}")

for alg in ("HS256", "HS384", "HS512"):
    r = run(["encode", "--payload", '{"a":1}', "--secret-file", secret_file, "--algorithm", alg])
    if check(f"{alg} encodes", r.returncode == 0, f"rc={r.returncode} {r.stderr[:200]}"):
        rv = run(["decode", r.stdout.strip(), "--verify", "--secret-file", secret_file, "--algorithm", alg])
        check(f"{alg} verifies", rv.returncode == 0, f"rc={rv.returncode} {rv.stderr[:200]}")

section("9. Regressions for defects found in review")
# Real-world OIDC tokens carry aud. PyJWT verifies aud BY DEFAULT and fails with
# InvalidAudienceError when no audience= is passed -- so before the fix, our own
# tool could not verify a token it had just signed.
oidc = '{"sub":"alice","aud":"my-api","iss":"https://auth.example.com"}'
r = run(["encode", "--payload", oidc, "--secret-file", secret_file])
check("encode a token carrying aud + iss", r.returncode == 0, f"rc={r.returncode} {r.stderr[:200]}")
if r.returncode == 0:
    aud_token = r.stdout.strip()
    r = run(["decode", aud_token, "--verify", "--secret-file", secret_file])
    check("REGRESSION: our own aud-bearing token verifies with our own tool",
          r.returncode == 0, f"rc={r.returncode} stderr={r.stderr[:250]}")
    if r.returncode == 0:
        out = json.loads(r.stdout)
        check("aud and iss survive verification intact",
              out["payload"].get("aud") == "my-api"
              and out["payload"].get("iss") == "https://auth.example.com", str(out)[:250])
        check("claims_checked reports exactly what was validated",
              out.get("claims_checked") == ["signature", "exp", "nbf", "iat"],
              f"got {out.get('claims_checked')!r}")
        check("aud/iss are NOT claimed as checked (they are not)",
              "aud" not in out.get("claims_checked", []) and "iss" not in out.get("claims_checked", []),
              f"got {out.get('claims_checked')!r}")

r = run(["decode", token])
if r.returncode == 0:
    check("claims_checked is empty for an unverified decode",
          json.loads(r.stdout).get("claims_checked") == [], r.stdout[:200])

# clock skew: a token whose iat is slightly in the future must be rescuable via --leeway
future = run(["encode", "--payload", '{"sub":"a","iat":' + str(int(__import__("time").time()) + 30) + '}',
              "--secret-file", secret_file])
if future.returncode == 0:
    ft = future.stdout.strip()
    r = run(["decode", ft, "--verify", "--secret-file", secret_file])
    check("iat 30s in the future is rejected with leeway 0 (default)", r.returncode != 0, f"rc={r.returncode}")
    r = run(["decode", ft, "--verify", "--secret-file", secret_file, "--leeway", "60"])
    check("--leeway 60 tolerates that clock skew", r.returncode == 0, f"rc={r.returncode} {r.stderr[:200]}")
    r = run(["decode", ft, "--verify", "--secret-file", secret_file, "--leeway", "-1"])
    check("--leeway -1 is a usage error (exit 2)", r.returncode == 2, f"rc={r.returncode}")

# --secret-env must require an explicit variable name, so it cannot eat the token
r = run(["decode", token, "--verify", "--secret-env"])
check("bare --secret-env is a usage error, not a token-swallowing surprise",
      r.returncode == 2, f"rc={r.returncode} stderr={r.stderr[:200]}")

# --algorithm without --verify does nothing and must say so
r = run(["decode", token, "--algorithm", "HS256"])
check("--algorithm without --verify warns that it was ignored",
      r.returncode == 0 and "ignored" in r.stderr.lower(), f"rc={r.returncode} stderr={r.stderr[:250]}")

# per-algorithm weak-secret advisory: 32 bytes is fine for HS256 but short for HS512
short32 = "y" * 32
r = run(["encode", "--payload", '{"a":1}', "--secret", short32, "--algorithm", "HS256"])
check("32-byte secret raises no length advisory for HS256",
      r.returncode == 0 and "shorter than" not in r.stderr, f"stderr={r.stderr!r}")
r = run(["encode", "--payload", '{"a":1}', "--secret", short32, "--algorithm", "HS512"])
check("same 32-byte secret DOES warn for HS512 (needs 64)",
      r.returncode == 0 and "64 bytes" in r.stderr, f"stderr={r.stderr!r}")
r = run(["encode", "--payload", '{"a":1}', "--secret", "tiny", "--algorithm", "HS256"])
check("short secret warns for HS256 too, without printing the secret",
      r.returncode == 0 and "32 bytes" in r.stderr and "tiny" not in r.stderr, f"stderr={r.stderr!r}")

if os.path.exists(secret_file):
    os.remove(secret_file)

failed = [(n, d) for ok, n, d in results if not ok]
print("\n" + "=" * 72)
print(f"RESULT: {len(results) - len(failed)}/{len(results)} passed, {len(failed)} failed")
if failed:
    print("\nFAILURES:")
    for name, detail in failed:
        print(f"  - {name}\n      {detail}")
print("=" * 72)
sys.exit(1 if failed else 0)
