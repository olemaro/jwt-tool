"""Run both test suites and collect artifacts in one command.

    python scripts/run-tests.py [--out DIR] [--no-coverage]

Runs, in order:

1. pytest              -> artifacts/pytest-junit.xml, coverage.xml, coverage-html/
2. scripts/smoke.py    -> artifacts/smoke.log, smoke-results.json, smoke-junit.xml

Then writes artifacts/summary.md and artifacts/summary.json, and exits non-zero
if either suite failed. Both suites always run: a pytest failure does not skip
the smoke test, because knowing whether the CLI still works end to end is
exactly what you want when the unit tests are red.

Cross-platform: uses the interpreter running this script, so it picks up the
active virtualenv without needing a shell activation.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass


def banner(text: str) -> None:
    print("\n" + "#" * 74)
    print("# " + text)
    print("#" * 74, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", metavar="DIR", default=str(REPO_ROOT / "artifacts"),
                        help="artifact directory (default: ./artifacts)")
    parser.add_argument("--no-coverage", action="store_true",
                        help="skip coverage measurement (useful if pytest-cov is absent)")
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()

    pytest_cmd = [
        sys.executable, "-m", "pytest", "tests", "-q",
        f"--junitxml={out / 'pytest-junit.xml'}",
    ]
    if not args.no_coverage:
        pytest_cmd += [
            "--cov=jwt_tool", "--cov-report=term-missing",
            f"--cov-report=xml:{out / 'coverage.xml'}",
            f"--cov-report=html:{out / 'coverage-html'}",
        ]

    banner("1/2  pytest  (unit + integration)")
    unit = subprocess.run(pytest_cmd, cwd=REPO_ROOT)

    banner("2/2  smoke  (end-to-end against the real CLI)")
    smoke = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "smoke.py"), "--out", str(out)],
        cwd=REPO_ROOT,
    )

    elapsed = time.time() - started

    # Pull the real numbers out of the artifacts rather than re-deriving them.
    totals: dict[str, object] = {}
    junit = out / "pytest-junit.xml"
    if junit.exists():
        import xml.etree.ElementTree as ET

        suite = ET.parse(junit).getroot()
        suite = suite if suite.tag == "testsuite" else suite[0]
        totals["pytest"] = {
            "tests": int(suite.get("tests", 0)),
            "failures": int(suite.get("failures", 0)),
            "errors": int(suite.get("errors", 0)),
            "skipped": int(suite.get("skipped", 0)),
        }
    results_json = out / "smoke-results.json"
    if results_json.exists():
        totals["smoke"] = json.loads(results_json.read_text(encoding="utf-8"))["totals"]

    coverage_pct = None
    cov_xml = out / "coverage.xml"
    if cov_xml.exists():
        import xml.etree.ElementTree as ET

        rate = ET.parse(cov_xml).getroot().get("line-rate")
        if rate is not None:
            coverage_pct = round(float(rate) * 100, 1)

    ok = unit.returncode == 0 and smoke.returncode == 0
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    (out / "summary.json").write_text(json.dumps({
        "ok": ok,
        "finished_utc": stamp,
        "duration_seconds": round(elapsed, 3),
        "python": sys.version.split()[0],
        "exit_codes": {"pytest": unit.returncode, "smoke": smoke.returncode},
        "totals": totals,
        "line_coverage_percent": coverage_pct,
    }, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# jwt-tool test run",
        "",
        f"- Finished: {stamp}",
        f"- Python: {sys.version.split()[0]}",
        f"- Duration: {elapsed:.1f}s",
        f"- Result: **{'PASS' if ok else 'FAIL'}**",
        "",
        "| Suite | Result | Detail |",
        "| --- | --- | --- |",
    ]
    if "pytest" in totals:
        t = totals["pytest"]
        bad = t["failures"] + t["errors"]
        lines.append(f"| pytest | {'pass' if bad == 0 else 'FAIL'} | "
                     f"{t['tests'] - bad}/{t['tests']} passed |")
    if "smoke" in totals:
        t = totals["smoke"]
        lines.append(f"| smoke | {'pass' if t['failed'] == 0 else 'FAIL'} | "
                     f"{t['passed']}/{t['checks']} checks passed |")
    if coverage_pct is not None:
        lines += ["", f"Line coverage: **{coverage_pct}%**"]
    lines += [
        "",
        "## Artifacts",
        "",
        "| File | Contents |",
        "| --- | --- |",
        "| `pytest-junit.xml` | JUnit report for the unit suite |",
        "| `smoke-junit.xml` | JUnit report for the smoke checks |",
        "| `smoke.log` | Full transcript: every command run, its exit code and output |",
        "| `smoke-results.json` | One structured record per smoke check |",
        "| `smoke-tokens.json`, `smoke-tokens.txt` | Every JWT the run touched, decoded |",
        "| `coverage.xml`, `coverage-html/` | Coverage, for a badge or a browsable report |",
        "| `summary.md`, `summary.json` | This summary |",
        "",
        "Secrets are redacted from every artifact; the smoke harness masks its "
        "sentinel value before anything is printed or written.",
    ]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    banner("summary")
    print(f"pytest exit={unit.returncode}   smoke exit={smoke.returncode}")
    for name, t in totals.items():
        print(f"  {name}: {t}")
    if coverage_pct is not None:
        print(f"  line coverage: {coverage_pct}%")
    print(f"\nArtifacts in {out}:")
    for path in sorted(out.iterdir()):
        size = f"{path.stat().st_size:>9} B" if path.is_file() else "      dir"
        print(f"  {size}  {path.name}")
    print(f"\nOverall: {'PASS' if ok else 'FAIL'} in {elapsed:.1f}s")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
