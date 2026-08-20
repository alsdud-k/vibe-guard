import json
import os
import time

import boto3
import jwt
import requests

secrets_client = boto3.client('secretsmanager')

SECRET_NAME = os.environ.get('SECRET_NAME', 'vibe-guard/github-app')
COMMENT_MARKER = '<!-- vibeguard-security-review -->'

GITHUB_API = 'https://api.github.com'

_secret_cache: dict | None = None


def get_secrets() -> dict:
    global _secret_cache
    if _secret_cache is None:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        _secret_cache = json.loads(response['SecretString'])
    return _secret_cache


def generate_github_jwt(app_id: str, private_key: str) -> str:
    private_key = private_key.replace('\\n', '\n')
    now = int(time.time())
    payload = {'iat': now - 60, 'exp': now + 600, 'iss': str(app_id)}
    return jwt.encode(payload, private_key, algorithm='RS256')


def generate_installation_token(installation_id: str, app_id: str, private_key: str) -> str:
    jwt_token = generate_github_jwt(app_id, private_key)
    response = requests.post(
        f'{GITHUB_API}/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json',
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()['token']


def find_existing_comment(repo_full_name: str, pr_number: int, headers: dict) -> int | None:
    url = f'{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments'
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()

    for comment in response.json():
        if COMMENT_MARKER in (comment.get('body') or ''):
            return comment['id']
    return None


def create_comment(repo_full_name: str, pr_number: int, body: str, headers: dict) -> dict:
    url = f'{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments'
    response = requests.post(url, json={'body': body}, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


def update_comment(repo_full_name: str, comment_id: int, body: str, headers: dict) -> dict:
    url = f'{GITHUB_API}/repos/{repo_full_name}/issues/comments/{comment_id}'
    response = requests.patch(url, json={'body': body}, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


SEVERITY_ICON = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}


def _format_findings_section(findings: list) -> str:
    if not findings:
        return ''

    # Summary table
    rows = []
    for f in findings:
        icon = SEVERITY_ICON.get(f.get('severity', ''), '⚪')
        file_ref = f.get('affected_file', '')
        line = f.get('affected_line')
        if line:
            file_ref = f"{file_ref}:{line}"
        rows.append(f"| {icon} **{f.get('severity', '?')}** | {f.get('title', '')} | `{file_ref}` |")

    table = "| 심각도 | 제목 | 파일 |\n|---|---|---|\n" + '\n'.join(rows)

    # Detail blocks
    details_parts = []
    for f in findings:
        icon = SEVERITY_ICON.get(f.get('severity', ''), '⚪')
        detail = f"### {icon} [{f.get('severity', '?')}] {f.get('title', '')}\n\n"
        detail += f"**문제:** {f.get('issue', '')}\n\n"
        if f.get('repository_evidence'):
            detail += "**근거:**\n" + '\n'.join(f"- {e}" for e in f['repository_evidence']) + "\n\n"
        detail += f"**권고사항:** {f.get('recommendation', '')}\n"
        details_parts.append(detail)

    details = '\n'.join(details_parts)

    return f"\n## Findings ({len(findings)}개)\n\n{table}\n\n<details>\n<summary>상세 내용 보기</summary>\n\n{details}\n</details>\n"


def _format_dismissed_section(dismissed: list) -> str:
    if not dismissed:
        return ''
    items = '\n'.join(f"- **{d.get('candidate_type', '?')}**: {d.get('reason', '')}" for d in dismissed)
    return f"\n<details>\n<summary>기각된 후보 ({len(dismissed)}개)</summary>\n\n{items}\n\n</details>\n"


def build_analysis_comment(pr: dict, diff: dict, relevance: dict | None, repository_context: dict | None, bedrock_review: dict | None = None) -> str:
    commit_short = pr['head_sha'][:7]
    files_changed = diff.get('total_files_changed', 0)
    additions = diff.get('total_additions', 0)
    deletions = diff.get('total_deletions', 0)
    truncated = diff.get('truncated', False)
    relevance_level = relevance.get('level', 'UNKNOWN') if relevance else 'UNKNOWN'
    security_files = relevance.get('security_files', []) if relevance else []

    truncated_note = f"\n> ⚠️ PR이 커서 상위 {len(diff.get('files', []))}개 파일만 분석했습니다.\n" if truncated else ""

    if bedrock_review and bedrock_review.get('findings') is not None:
        findings = bedrock_review.get('findings', [])
        dismissed = bedrock_review.get('dismissed_candidates', [])
        summary_text = bedrock_review.get('summary', '')
        model_note = bedrock_review.get('model_used', '').replace('anthropic.', '').split('-20')[0]

        if findings:
            critical_high = [f for f in findings if f.get('severity') in ('CRITICAL', 'HIGH')]
            status_line = f"🔴 **보안 이슈 {len(findings)}개 발견** ({len(critical_high)}개 HIGH+)" if critical_high else f"🟡 **보안 이슈 {len(findings)}개 발견**"
        else:
            status_line = "✅ **보안 이슈 없음** — Bedrock 분석 완료"

        findings_section = _format_findings_section(findings)
        dismissed_section = _format_dismissed_section(dismissed)
        summary_section = f"\n**요약:** {summary_text}\n" if summary_text else ""

        return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

{status_line}
{summary_section}
| | |
|---|---|
| **PR** | #{pr['number']} {pr['title']} |
| **Commit** | `{commit_short}` |
| **Files Changed** | {files_changed} (+{additions} / -{deletions}) |
| **보안 관련 파일** | {len(security_files)}개 |
| **Relevance** | {relevance_level} |
{truncated_note}{findings_section}{dismissed_section}
---
<sub>VibeGuard v0.3 • {model_note} • Relevance: {relevance_level}</sub>
"""

    # Bedrock not yet run or failed — show context-only status
    context_lines = []
    if repository_context and repository_context.get('evidence_files'):
        for ef in repository_context['evidence_files'][:5]:
            terms = ', '.join(ef.get('matched_terms', []))
            context_lines.append(f"- `{ef['file']}` ({ef['domain']}): {terms}")

    context_section = ""
    if context_lines:
        context_section = "\n**수집된 보안 컨텍스트:**\n" + "\n".join(context_lines) + "\n"
    elif repository_context is not None:
        context_section = "\n**보안 컨텍스트:** 관련 파일 없음\n"

    return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

⏳ 분석 중

| | |
|---|---|
| **PR** | #{pr['number']} {pr['title']} |
| **Commit** | `{commit_short}` |
| **Files Changed** | {files_changed} (+{additions} / -{deletions}) |
| **보안 관련 파일** | {len(security_files)}개 |
| **Relevance** | {relevance_level} |
{truncated_note}{context_section}
---
<sub>VibeGuard v0.3 • Relevance: {relevance_level}</sub>
"""


def build_low_risk_comment(pr: dict, diff: dict, relevance: dict | None) -> str:
    files_changed = diff.get('total_files_changed', 0)
    relevance_level = relevance.get('level', 'LOW') if relevance else 'LOW'

    return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

✅ **보안 이슈 없음**

이 PR의 변경 사항은 보안과 관련성이 낮습니다.

| | |
|---|---|
| **변경 파일** | {files_changed}개 |
| **보안 관련 파일** | 0개 |

---
<sub>VibeGuard v0.2 • Relevance: {relevance_level}</sub>
"""


def build_skip_comment(pr: dict, diff: dict) -> str:
    files_changed = diff.get('total_files_changed', 0)

    return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

⏭️ **분석 건너뜀**

이 PR의 변경 파일은 보안 분석 대상이 아닙니다 (이미지, lock 파일 등).

| | |
|---|---|
| **변경 파일** | {files_changed}개 |

---
<sub>VibeGuard v0.2 • Relevance: SKIP</sub>
"""


def build_error_comment(pr: dict) -> str:
    return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

⚠️ **분석 중 오류가 발생했습니다**

분석 파이프라인에서 오류가 발생했습니다. 잠시 후 커밋을 다시 푸시하거나 문제가 지속되면 관리자에게 문의하세요.

---
<sub>VibeGuard v0.2</sub>
"""


def lambda_handler(event, context):
    # Step Functions may wrap the event with a mode parameter
    mode = event.get('mode', 'analysis')
    inner = event.get('input', event) if mode in ('low_risk', 'error', 'skip') else event

    repo = inner['repository']
    pr = inner['pull_request']
    installation_id = inner['installation_id']
    diff = inner.get('diff', {})
    relevance = inner.get('relevance')
    repository_context = inner.get('repository_context')
    bedrock_review = inner.get('bedrock_review')

    secrets = get_secrets()
    token = generate_installation_token(
        installation_id,
        secrets['app_id'],
        secrets['private_key'],
    )
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }

    if mode == 'low_risk':
        comment_body = build_low_risk_comment(pr, diff, relevance)
    elif mode == 'skip':
        comment_body = build_skip_comment(pr, diff)
    elif mode == 'error':
        comment_body = build_error_comment(pr)
    else:
        comment_body = build_analysis_comment(pr, diff, relevance, repository_context, bedrock_review)

    existing_comment_id = find_existing_comment(repo['full_name'], pr['number'], headers)

    if existing_comment_id:
        update_comment(repo['full_name'], existing_comment_id, comment_body, headers)
        print(f"Updated comment {existing_comment_id} on PR #{pr['number']} (mode={mode})")
    else:
        result = create_comment(repo['full_name'], pr['number'], comment_body, headers)
        print(f"Created comment {result.get('id')} on PR #{pr['number']} (mode={mode})")

    return {**inner, 'comment_posted': True}
