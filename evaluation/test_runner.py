#!/usr/bin/env python3
"""
VibeGuard Phase 5 — Evaluation test runner.

Creates GitHub PRs from test branches, waits for VibeGuard comments,
parses results, and computes Precision / Recall / F1 / FPR metrics.

Usage:
    python evaluation/test_runner.py \\
        --repo <owner/repo-name> \\
        --token <github-pat> \\
        [--cases S1,A1,E1]   # run specific cases (default: all)
        [--timeout 180]       # seconds to wait per PR (default: 180)
        [--output results/]   # output directory (default: evaluation/results/)
        [--close-prs]         # close PRs after evaluation

Requirements:
    pip install requests

Output files written to --output:
    results.json     — full per-case results
    metrics.json     — Precision, Recall, F1, FPR per category + overall
    report.md        — human-readable markdown report
    latency.csv      — per-case latency measurements
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
MANIFEST_PATH = SCRIPT_DIR / "manifest.json"
DEFAULT_OUTPUT = SCRIPT_DIR / "results"

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COMMENT_MARKER_RE = re.compile(r"<!-- vibe-guard:pr-\d+ -->")

# Risk score / level patterns
RISK_SCORE_RE = re.compile(r"Risk.*?(CRITICAL|HIGH|MEDIUM|LOW)[^\d]*(\d+)\s*/\s*100", re.IGNORECASE)
RISK_LEVEL_RE = re.compile(r"Risk.*?(CRITICAL|HIGH|MEDIUM|LOW)", re.IGNORECASE)
FINDING_SEVERITY_RE = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]", re.IGNORECASE)
NO_ISSUES_RE = re.compile(r"보안 이슈 없음|No security issues|no_findings|findings_count.*:\s*0", re.IGNORECASE)
LOW_RISK_RE = re.compile(r"보안 관련성이 낮습니다|low.?risk|relevance.*LOW", re.IGNORECASE)
SKIP_RE = re.compile(r"SkipAnalysis|relevance.*SKIP", re.IGNORECASE)


# ---------------------------------------------------------------------------
# GitHub API wrapper
# ---------------------------------------------------------------------------

class GitHub:
    def __init__(self, token: str) -> None:
        self._token = token

    def _req(self, method: str, path: str, body: dict | None = None) -> dict | list:
        url = f"https://api.github.com{path}"
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"token {self._token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
            },
            method=method,
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    def get(self, path: str) -> dict | list:
        return self._req("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self._req("POST", path, body)

    def patch(self, path: str, body: dict) -> dict:
        return self._req("PATCH", path, body)

    def create_pr(self, repo: str, title: str, head: str, base: str, body: str = "") -> dict:
        return self.post(f"/repos/{repo}/pulls", {
            "title": title,
            "head": head,
            "base": base,
            "body": body,
        })

    def close_pr(self, repo: str, pr_number: int) -> None:
        self.patch(f"/repos/{repo}/pulls/{pr_number}", {"state": "closed"})

    def list_comments(self, repo: str, pr_number: int) -> list:
        return self.get(f"/repos/{repo}/issues/{pr_number}/comments")

    def get_commit_sha(self, repo: str, branch: str) -> str:
        ref = self.get(f"/repos/{repo}/git/ref/heads/{branch}")
        return ref["object"]["sha"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    id: str
    branch: str
    description: str
    category: str
    expected: dict


@dataclass
class ParsedResult:
    has_findings: bool = False
    risk_level: str = "NONE"
    risk_score: int = 0
    finding_severities: list[str] = field(default_factory=list)
    is_low_risk: bool = False
    is_skipped: bool = False
    comment_body: str = ""


@dataclass
class CaseResult:
    case: TestCase
    pr_number: int | None
    verdict: str  # TP / FP / TN / FN / ERROR / TIMEOUT
    parsed: ParsedResult | None
    latency_seconds: float
    error: str = ""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_vibeguard_comment(body: str) -> ParsedResult:
    result = ParsedResult(comment_body=body)

    if SKIP_RE.search(body):
        result.is_skipped = True
        return result

    if LOW_RISK_RE.search(body):
        result.is_low_risk = True
        return result

    if NO_ISSUES_RE.search(body):
        return result

    score_match = RISK_SCORE_RE.search(body)
    if score_match:
        result.risk_score = int(score_match.group(2))

    level_match = RISK_LEVEL_RE.search(body)
    if level_match:
        result.risk_level = level_match.group(1).upper()

    severities = [s.upper() for s in FINDING_SEVERITY_RE.findall(body)]
    result.finding_severities = severities
    result.has_findings = bool(severities) or result.risk_score > 0

    return result


def is_vibeguard_comment(body: str) -> bool:
    return (
        COMMENT_MARKER_RE.search(body) is not None
        or "<!-- vibeguard-security-review -->" in body
        or "VibeGuard" in body and ("Risk" in body or "보안" in body)
    )


# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------

def evaluate(case: TestCase, parsed: ParsedResult) -> str:
    expected = case.expected
    should_find = expected.get("should_find", False)

    # Determine if VibeGuard reported a finding
    actually_found = False
    if parsed.has_findings:
        actually_found = True
        min_sev = expected.get("min_severity")
        if min_sev:
            max_actual = max(
                (SEVERITY_ORDER.index(s) for s in parsed.finding_severities
                 if s in SEVERITY_ORDER),
                default=-1,
            )
            required = SEVERITY_ORDER.index(min_sev)
            if max_actual < required:
                # Found something but below required severity
                return "FN"

    if should_find:
        return "TP" if actually_found else "FN"
    else:
        return "TN" if not actually_found else "FP"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(results: list[CaseResult]) -> dict:
    categories = {}
    all_verdicts: list[str] = []

    for r in results:
        if r.verdict in ("ERROR", "TIMEOUT"):
            continue
        cat = r.case.category
        if cat not in categories:
            categories[cat] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        categories[cat][r.verdict] += 1
        all_verdicts.append(r.verdict)

    def calc(counts: dict) -> dict:
        tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall else None)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None
        return {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "fpr": round(fpr, 3) if fpr is not None else None,
        }

    overall_counts: dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for v in all_verdicts:
        overall_counts[v] += 1

    return {
        "overall": calc(overall_counts),
        "by_category": {cat: calc(counts) for cat, counts in categories.items()},
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def render_report(results: list[CaseResult], metrics: dict, run_at: str) -> str:
    lines: list[str] = [
        "# VibeGuard Phase 5 — Evaluation Report",
        "",
        f"**Run at:** {run_at}",
        f"**Total cases:** {len(results)}",
        "",
    ]

    overall = metrics["overall"]
    lines += [
        "## Overall Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Precision | {overall.get('precision') or 'N/A'} |",
        f"| Recall    | {overall.get('recall') or 'N/A'} |",
        f"| F1 Score  | {overall.get('f1') or 'N/A'} |",
        f"| False Positive Rate | {overall.get('fpr') or 'N/A'} |",
        f"| TP / FP / TN / FN | {overall['TP']} / {overall['FP']} / {overall['TN']} / {overall['FN']} |",
        "",
    ]

    lines += ["## By Category", ""]
    for cat, m in metrics.get("by_category", {}).items():
        lines += [
            f"### {cat.capitalize()}",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Precision | {m.get('precision') or 'N/A'} |",
            f"| Recall    | {m.get('recall') or 'N/A'} |",
            f"| F1        | {m.get('f1') or 'N/A'} |",
            f"| TP / FP / TN / FN | {m['TP']} / {m['FP']} / {m['TN']} / {m['FN']} |",
            "",
        ]

    lines += ["## Per-Case Results", ""]
    lines += ["| ID | Branch | Expected | Verdict | Risk | Score | Latency |",
              "|----|--------|----------|---------|------|-------|---------|"]

    for r in results:
        parsed = r.parsed
        risk = parsed.risk_level if parsed else "-"
        score = parsed.risk_score if parsed else "-"
        expected_label = "FIND" if r.case.expected.get("should_find") else "SAFE"
        latency = f"{r.latency_seconds:.0f}s" if r.latency_seconds else "-"
        icon = {"TP": "✅", "FP": "❌", "TN": "✅", "FN": "❌"}.get(r.verdict, "⚠️")
        lines.append(
            f"| {r.case.id} | `{r.case.branch}` | {expected_label} "
            f"| {icon} {r.verdict} | {risk} | {score} | {latency} |"
        )

    latencies = [r.latency_seconds for r in results if r.latency_seconds and r.verdict not in ("ERROR", "TIMEOUT")]
    if latencies:
        avg = sum(latencies) / len(latencies)
        lines += [
            "",
            "## Latency",
            "",
            f"| Metric | Value |",
            "|--------|-------|",
            f"| Average | {avg:.1f}s |",
            f"| Min | {min(latencies):.1f}s |",
            f"| Max | {max(latencies):.1f}s |",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def load_manifest(case_filter: list[str] | None) -> list[TestCase]:
    with open(MANIFEST_PATH) as f:
        data = json.load(f)
    cases = [TestCase(**tc) for tc in data["test_cases"]]
    if case_filter:
        ids = {c.upper() for c in case_filter}
        cases = [c for c in cases if c.id.upper() in ids]
    return cases


def wait_for_comment(gh: GitHub, repo: str, pr_number: int, timeout: int) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            comments = gh.list_comments(repo, pr_number)
            for c in comments:
                body = c.get("body") or ""
                if is_vibeguard_comment(body):
                    return body
        except Exception as e:
            print(f"    Warning: error polling comments: {e}")
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(10)
    return None


def run_case(
    case: TestCase,
    gh: GitHub,
    repo: str,
    timeout: int,
    close_prs: bool,
) -> CaseResult:
    pr_number: int | None = None
    start = time.time()

    try:
        pr = gh.create_pr(
            repo=repo,
            title=f"[VibeGuard Test] {case.id} — {case.description}",
            head=case.branch,
            base="main",
            body=f"Automated test case `{case.id}` for VibeGuard evaluation.\n\nExpected: `{json.dumps(case.expected)}`",
        )
        pr_number = pr["number"]
        print(f"  PR #{pr_number} created for {case.id} ({case.branch})")

        comment_body = wait_for_comment(gh, repo, pr_number, timeout)
        latency = time.time() - start

        if comment_body is None:
            return CaseResult(
                case=case,
                pr_number=pr_number,
                verdict="TIMEOUT",
                parsed=None,
                latency_seconds=latency,
                error=f"No VibeGuard comment within {timeout}s",
            )

        parsed = parse_vibeguard_comment(comment_body)
        verdict = evaluate(case, parsed)

        return CaseResult(
            case=case,
            pr_number=pr_number,
            verdict=verdict,
            parsed=parsed,
            latency_seconds=latency,
        )

    except Exception as e:
        latency = time.time() - start
        return CaseResult(
            case=case,
            pr_number=pr_number,
            verdict="ERROR",
            parsed=None,
            latency_seconds=latency,
            error=str(e),
        )
    finally:
        if close_prs and pr_number:
            try:
                gh.close_pr(repo, pr_number)
            except Exception:
                pass


def write_outputs(results: list[CaseResult], metrics: dict, output_dir: Path, run_at: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # results.json
    results_data = []
    for r in results:
        p = r.parsed
        results_data.append({
            "id": r.case.id,
            "branch": r.case.branch,
            "description": r.case.description,
            "category": r.case.category,
            "pr_number": r.pr_number,
            "verdict": r.verdict,
            "expected": r.case.expected,
            "actual": {
                "has_findings": p.has_findings if p else None,
                "risk_level": p.risk_level if p else None,
                "risk_score": p.risk_score if p else None,
                "finding_severities": p.finding_severities if p else [],
                "is_low_risk": p.is_low_risk if p else None,
            },
            "latency_seconds": round(r.latency_seconds, 1),
            "error": r.error,
        })
    (output_dir / "results.json").write_text(
        json.dumps({"run_at": run_at, "results": results_data}, indent=2, ensure_ascii=False)
    )

    # metrics.json
    (output_dir / "metrics.json").write_text(
        json.dumps({"run_at": run_at, **metrics}, indent=2, ensure_ascii=False)
    )

    # report.md
    (output_dir / "report.md").write_text(render_report(results, metrics, run_at))

    # latency.csv
    with (output_dir / "latency.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "branch", "category", "verdict", "latency_seconds"])
        for r in results:
            writer.writerow([r.case.id, r.case.branch, r.case.category, r.verdict,
                             round(r.latency_seconds, 1)])


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeGuard evaluation test runner")
    parser.add_argument("--repo", required=True, help="GitHub repo in owner/name format")
    parser.add_argument("--token", required=True, help="GitHub personal access token")
    parser.add_argument("--cases", default="", help="Comma-separated case IDs to run (default: all)")
    parser.add_argument("--timeout", type=int, default=180, help="Seconds to wait per PR (default: 180)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output directory")
    parser.add_argument("--close-prs", action="store_true", help="Close PRs after evaluation")
    args = parser.parse_args()

    if "/" not in args.repo:
        sys.exit("--repo must be in owner/repo-name format")

    case_filter = [c.strip() for c in args.cases.split(",") if c.strip()] or None

    print(f"▶ Loading manifest from {MANIFEST_PATH}")
    cases = load_manifest(case_filter)
    print(f"  {len(cases)} test cases loaded")

    gh = GitHub(args.token)
    output_dir = Path(args.output)
    run_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    results: list[CaseResult] = []

    print(f"\n▶ Running {len(cases)} test cases (timeout={args.timeout}s each)")
    for i, case in enumerate(cases, 1):
        print(f"\n[{i}/{len(cases)}] {case.id} — {case.description}")
        result = run_case(case, gh, args.repo, args.timeout, args.close_prs)
        results.append(result)

        icon = {"TP": "✅", "FP": "❌", "TN": "✅", "FN": "❌"}.get(result.verdict, "⚠️")
        print(f"  {icon} {result.verdict} "
              f"(latency={result.latency_seconds:.0f}s"
              f"{', error=' + result.error if result.error else ''})")

    print("\n▶ Computing metrics...")
    metrics = compute_metrics(results)

    print("\n▶ Writing outputs...")
    write_outputs(results, metrics, output_dir, run_at)

    # Print summary
    overall = metrics["overall"]
    print(f"\n{'='*50}")
    print("EVALUATION SUMMARY")
    print(f"{'='*50}")
    print(f"Cases run:   {len(results)}")
    print(f"TP / FP / TN / FN: {overall['TP']} / {overall['FP']} / {overall['TN']} / {overall['FN']}")
    print(f"Precision:   {overall.get('precision') or 'N/A'}")
    print(f"Recall:      {overall.get('recall') or 'N/A'}")
    print(f"F1 Score:    {overall.get('f1') or 'N/A'}")
    print(f"FPR:         {overall.get('fpr') or 'N/A'}")
    print(f"\nOutputs → {output_dir}/")
    print(f"  results.json  metrics.json  report.md  latency.csv")


if __name__ == "__main__":
    main()
