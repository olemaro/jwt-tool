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

import argparse
import base64
import datetime
import json
import os
import pathlib
import platform
import shlex
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

# This suite prints tokens, payloads and error messages verbatim, and one of the
# payloads is deliberately non-ASCII. A Windows console defaults to cp1252, where
# print() would raise UnicodeEncodeError and abort the run, so force UTF-8 and
# degrade gracefully if the stream cannot be reconfigured (e.g. when piped by a
# harness that replaced it).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable
SECRET = "smoke-sentinel-secret-do-not-leak-0123456789678"
PAYLOAD = '{"sub":"1234567890","name":"John Doe","admin":false,"n":42}'

parser = argparse.ArgumentParser(
    description="End-to-end smoke test for jwt-tool.",
    epilog="Artifacts: smoke.log (transcript), smoke-results.json, smoke-junit.xml",
)
parser.add_argument("--out", metavar="DIR", default=str(REPO_ROOT / "artifacts"),
                    help="directory for artifacts (default: ./artifacts)")
parser.add_argument("--no-artifacts", action="store_true",
                    help="print the transcript but write no files")
parser.add_argument("-q", "--quiet", action="store_true",
                    help="only PASS/FAIL lines and the summary, no command transcript")
ARGS = parser.parse_args()

#: Every line printed, kept verbatim for smoke.log.
TRANSCRIPT: list[str] = []
#: (ok, name, detail) per check -- the summary reads this.
results: list[tuple[bool, str, str]] = []
#: One record per check, for smoke-results.json and the JUnit report.
RECORDS: list[dict] = []
CURRENT_SECTION = "0. setup"
STARTED = time.time()


def mask(text: str) -> str:
    """Never let the secret reach the transcript, a log file or a CI console."""
    return text.replace(SECRET, "<SECRET:" + str(len(SECRET)) + "-chars-redacted>")


def say(line: str = "", *, quiet_ok: bool = True) -> None:
    """Print a line and record it. quiet_ok=False means --quiet suppresses it."""
    line = mask(line)
    TRANSCRIPT.append(line)
    if quiet_ok or not ARGS.quiet:
        print(line)


def trace(line: str = "") -> None:
    """Transcript detail -- suppressed by --quiet, still written to smoke.log."""
    line = mask(line)
    TRANSCRIPT.append(line)
    if not ARGS.quiet:
        print(line)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(header: dict, payload: object, sig: str = "x") -> str:
    h = b64u(json.dumps(header).encode())
    p = b64u(json.dumps(payload).encode())
    return f"{h}.{p}.{sig}"


def _abbrev(value: str, limit: int = 220) -> str:
    value = value.replace("\r\n", "\n").strip()
    if not value:
        return "<empty>"
    single = " \u23ce ".join(value.splitlines())
    return single if len(single) <= limit else single[:limit] + " \u2026"


def run(args: list[str], *, stdin: str | None = None, env: dict | None = None):
    """Invoke the CLI in a separate process and narrate exactly what happened."""
    environ = {**os.environ, **(env or {})}
    # Also work from a bare checkout, not just an installed package: mirrors the
    # `pythonpath = ["src"]` that pyproject.toml already gives pytest.
    src_dir = str(REPO_ROOT / "src")
    prior = environ.get("PYTHONPATH")
    environ["PYTHONPATH"] = f"{src_dir}{os.pathsep}{prior}" if prior else src_dir

    shown = "jwt-tool " + " ".join(shlex.quote(a) for a in args)
    extras = []
    if env:
        extras.append("env " + " ".join(f"{k}={mask(v)}" for k, v in env.items()))
    if stdin is not None:
        extras.append(f"stdin={_abbrev(stdin, 60)!r}")
    trace("  $ " + shown + (("   [" + "; ".join(extras) + "]") if extras else ""))

    started = time.time()
    proc = subprocess.run(
        [PY, "-m", "jwt_tool", *args],
        capture_output=True, text=True, input=stdin, cwd=REPO_ROOT, env=environ,
    )
    trace(f"    exit={proc.returncode}  ({(time.time() - started) * 1000:.0f} ms)")
    trace(f"    stdout: {_abbrev(proc.stdout)}")
    trace(f"    stderr: {_abbrev(proc.stderr)}")
    return proc


def check(name: str, cond: object, detail: str = "") -> bool:
    """Record one assertion. Detail is shown on pass as well as on failure.

    Showing it on a pass is the point: the transcript then states what was
    actually observed, so a reader can audit the claim instead of trusting a
    bare PASS.
    """
    ok = bool(cond)
    results.append((ok, name, detail))
    RECORDS.append({"section": CURRENT_SECTION, "name": name,
                    "ok": ok, "detail": mask(detail)})
    say(("  PASS  " if ok else "  FAIL  ") + name)
    if detail:
        if ok:
            trace("          observed: " + _abbrev(detail))
        else:
            say("          observed: " + _abbrev(detail, 400))
    return ok


#: What each section proves, and why it is worth proving. Printed under the
#: heading so the transcript explains itself to someone who has never read the
#: source.
WHY = {
    "1.": "The task documents this exact invocation, so it must work verbatim -- and\n"
          "   using --secret on the command line must warn about argv/history exposure.",
    "2.": "Plain `decode` needs no key. It must print parseable JSON on stdout, keep the\n"
          "   warning on stderr so `| jq` still works, and admit it verified nothing.",
    "3.": "Verification must actually reject: wrong key, a payload tampered with while\n"
          "   reusing a valid signature (the CVE-2022-39227 shape), and alg:none.",
    "4.": "Malformed input is the normal case for a CLI. Every shape must fail with a\n"
          "   clean message and a non-zero exit -- never a traceback, never partial output.",
    "5.": "The secret must be suppliable without putting it in argv. All four sources must\n"
          "   agree on the same secret, and a missing source must fail loudly, not silently.",
    "6.": "Bad payloads and bad usage are different failures: exit 1 for the former,\n"
          "   exit 2 for the latter, so a script can tell 'the token was bad' from 'I\n"
          "   called this wrong'.",
    "7.": "`--help` is part of the deliverable. It must list both subcommands and document\n"
          "   the secure secret flags.",
    "8.": "The requirement 'the generated token should be decodable by your tool', proven\n"
          "   through the CLI only, for every supported algorithm and payload shape.",
    "9.": "One check per defect found during review. Each of these passed the original\n"
          "   test suite and still shipped a bug, so they are pinned here permanently.",
}


def section(title: str) -> None:
    global CURRENT_SECTION
    CURRENT_SECTION = title
    say()
    say("=" * 74)
    say(title)
    why = WHY.get(title.split()[0])
    if why:
        say("   " + why)
    say("=" * 74)


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


def finish() -> int:
    failed = [(n, d) for ok, n, d in results if not ok]
    passed = len(results) - len(failed)
    elapsed = time.time() - STARTED

    say()
    say("=" * 74)
    say(f"RESULT: {passed}/{len(results)} checks passed, {len(failed)} failed "
        f"in {elapsed:.1f}s")
    by_section: dict[str, list[bool]] = {}
    for rec in RECORDS:
        by_section.setdefault(rec["section"], []).append(rec["ok"])
    for name, oks in by_section.items():
        mark = "ok  " if all(oks) else "FAIL"
        say(f"  [{mark}] {sum(oks)}/{len(oks)}  {name}")
    if failed:
        say()
        say("FAILURES:")
        for name, detail in failed:
            say(f"  - {name}")
            say(f"      {_abbrev(detail, 400)}")
    say("=" * 74)

    if not ARGS.no_artifacts:
        out = pathlib.Path(ARGS.out)
        out.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

        (out / "smoke.log").write_text("\n".join(TRANSCRIPT) + "\n", encoding="utf-8")

        (out / "smoke-results.json").write_text(json.dumps({
            "suite": "jwt-tool smoke",
            "started_utc": stamp,
            "duration_seconds": round(elapsed, 3),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "interpreter": PY,
            "totals": {"checks": len(results), "passed": passed, "failed": len(failed)},
            "checks": RECORDS,
        }, indent=2) + "\n", encoding="utf-8")

        suite = ET.Element("testsuite", name="jwt-tool.smoke",
                           tests=str(len(results)), failures=str(len(failed)),
                           errors="0", skipped="0", time=f"{elapsed:.3f}",
                           timestamp=stamp)
        for rec in RECORDS:
            case = ET.SubElement(suite, "testcase",
                                 classname="smoke." + rec["section"].split(".")[0],
                                 name=rec["name"])
            if not rec["ok"]:
                ET.SubElement(case, "failure",
                              message=rec["detail"] or "check failed").text = rec["detail"]
        tree = ET.ElementTree(ET.Element("testsuites"))
        tree.getroot().append(suite)
        ET.indent(tree, space="  ")
        tree.write(out / "smoke-junit.xml", encoding="utf-8", xml_declaration=True)

        say()
        say("Artifacts written to " + str(out) + ":")
        for fname in ("smoke.log", "smoke-results.json", "smoke-junit.xml"):
            say(f"  {(out / fname).stat().st_size:>8} B  {fname}")

    return 1 if failed else 0


sys.exit(finish())
