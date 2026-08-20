import decimal
import json
import logging
import os
import time
from datetime import datetime

import boto3
import jwt
import requests

secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')

SECRET_NAME = os.environ.get('SECRET_NAME', 'vibe-guard/github-app')
ANALYSIS_TABLE = 'vibe-guard-analysis-results'
LOCK_TABLE = 'vibe-guard-execution-lock'
LEGACY_COMMENT_MARKER = '<!-- vibeguard-security-review -->'

GITHUB_API = 'https://api.github.com'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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


def find_existing_comment(repo_full_name: str, pr_number: int, markers: list[str], headers: dict) -> int | None:
    url = f'{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments'
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    for comment in response.json():
        body = comment.get('body') or ''
        if any(m in body for m in markers):
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


def create_review(repo_full_name: str, pr_number: int, commit_sha: str, action: str, message: str, headers: dict):
    url = f'{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}/reviews'
    try:
        requests.post(url, headers=headers, timeout=10, json={
            'commit_id': commit_sha,
            'event': action,
            'body': f'🛡️ VibeGuard: {message}',
        })
    except Exception as e:
        logger.warning(f"create_review failed (non-fatal): {e}")


def _to_decimal(obj):
    if isinstance(obj, float):
        return decimal.Decimal(str(round(obj, 4)))
    elif isinstance(obj, dict):
        return {k: _to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_to_decimal(i) for i in obj]
    return obj


def save_to_dynamodb(event, final_result):
    try:
        table = dynamodb.Table(ANALYSIS_TABLE)
        repo = event['repository']
        pr = event['pull_request']
        bedrock_review = event.get('bedrock_review') or {}

        simplified_findings = [
            {
                'title': f.get('title', ''),
                'severity': f.get('severity', ''),
                'category': f.get('category', ''),
                'affected_file': f.get('affected_file', ''),
                'affected_line': f.get('affected_line'),
                'final_confidence': f.get('final_confidence', 0),
            }
            for f in final_result.get('findings', [])
        ]

        item = {
            'repository': repo['full_name'],
            'pr_commit': f"PR#{pr['number']}#SHA#{pr['head_sha']}",
            'analysis_status': 'COMPLETED',
            'analysis_mode': final_result.get('analysis_mode', 'unknown'),
            'security_relevance': (event.get('relevance') or {}).get('level', 'UNKNOWN'),
            'risk_score': final_result.get('risk_score', 0),
            'risk_level': final_result.get('risk_level', 'UNKNOWN'),
            'review_action': (final_result.get('review_action') or {}).get('action', 'COMMENT'),
            'findings_count': len(final_result.get('findings', [])),
            'findings': simplified_findings,
            'dismissed_count': len(final_result.get('dismissed_candidates', [])),
            'bedrock_input_tokens': bedrock_review.get('input_tokens', 0),
            'bedrock_output_tokens': bedrock_review.get('output_tokens', 0),
            'bedrock_model': bedrock_review.get('model_used', 'none'),
            'pr_title': pr.get('title', ''),
            'pr_branch': pr.get('head_branch', ''),
            'files_changed': (event.get('diff') or {}).get('total_files_changed', 0),
            'config_source': (event.get('vibeguard_config') or {}).get('source', 'unknown'),
            'created_at': datetime.utcnow().isoformat(),
            'ttl': int(time.time()) + 90 * 24 * 60 * 60,
        }

        table.put_item(Item=_to_decimal(item))
        logger.info(json.dumps({'message': 'Saved to DynamoDB', 'repository': repo['full_name'], 'pr_number': pr['number']}))
    except Exception as e:
        logger.error(f"save_to_dynamodb failed (non-fatal): {e}")


def release_execution_lock(repo_full_name: str, pr_number: int):
    try:
        table = dynamodb.Table(LOCK_TABLE)
        table.delete_item(Key={'pr_key': f"{repo_full_name}:{pr_number}"})
    except Exception as e:
        logger.warning(f"release_execution_lock failed (non-fatal): {e}")


def build_low_risk_comment(pr: dict, diff: dict, relevance: dict | None) -> str:
    files_changed = diff.get('total_files_changed', 0)
    relevance_level = relevance.get('level', 'LOW') if relevance else 'LOW'

    return f"""{LEGACY_COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

✅ **보안 이슈 없음**

이 PR의 변경 사항은 보안과 관련성이 낮습니다.

| | |
|---|---|
| **변경 파일** | {files_changed}개 |
| **보안 관련 파일** | 0개 |

---
<sub>VibeGuard v0.4 • Relevance: {relevance_level}</sub>
"""


def build_error_comment(pr: dict) -> str:
    return f"""{LEGACY_COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

⚠️ **분석 중 오류가 발생했습니다**

분석 파이프라인에서 오류가 발생했습니다. 잠시 후 커밋을 다시 푸시하거나 문제가 지속되면 관리자에게 문의하세요.

---
<sub>VibeGuard v0.4</sub>
"""


def handle_full_result(event, headers):
    repo = event['repository']
    pr = event['pull_request']
    final_result = event.get('final_result')

    if not final_result:
        logger.error('handle_full_result called without final_result in event')
        comment_body = build_error_comment(pr)
        markers = [LEGACY_COMMENT_MARKER]
    else:
        comment_body = final_result['comment_body']
        markers = [final_result['comment_marker'], LEGACY_COMMENT_MARKER]

    existing_id = find_existing_comment(repo['full_name'], pr['number'], markers, headers)

    if existing_id:
        update_comment(repo['full_name'], existing_id, comment_body, headers)
        logger.info(f"Updated comment {existing_id} on PR #{pr['number']}")
    else:
        result = create_comment(repo['full_name'], pr['number'], comment_body, headers)
        logger.info(f"Created comment {result.get('id')} on PR #{pr['number']}")

    if final_result:
        review_action = final_result.get('review_action', {})
        if review_action.get('action') == 'REQUEST_CHANGES':
            create_review(
                repo['full_name'],
                pr['number'],
                pr['head_sha'],
                'REQUEST_CHANGES',
                review_action.get('message', ''),
                headers,
            )

        save_to_dynamodb(event, final_result)
        release_execution_lock(repo['full_name'], pr['number'])

    return {
        'status': 'completed',
        'risk_score': (final_result or {}).get('risk_score', 0),
        'risk_level': (final_result or {}).get('risk_level', 'UNKNOWN'),
        'findings_count': len((final_result or {}).get('findings', [])),
    }


def lambda_handler(event, context):
    mode = event.get('mode', 'analysis')
    inner = event.get('input', event) if mode in ('low_risk', 'error', 'skip') else event

    repo = inner['repository']
    pr = inner['pull_request']
    installation_id = inner['installation_id']

    secrets = get_secrets()
    token = generate_installation_token(installation_id, secrets['app_id'], secrets['private_key'])
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }

    if mode == 'analysis':
        return handle_full_result(inner, headers)

    diff = inner.get('diff', {})
    relevance = inner.get('relevance')

    if mode == 'low_risk':
        comment_body = build_low_risk_comment(pr, diff, relevance)
    elif mode == 'error':
        comment_body = build_error_comment(pr)
    else:
        return {'status': 'skipped'}

    existing_id = find_existing_comment(repo['full_name'], pr['number'], [LEGACY_COMMENT_MARKER], headers)
    if existing_id:
        update_comment(repo['full_name'], existing_id, comment_body, headers)
        logger.info(f"Updated comment {existing_id} on PR #{pr['number']} (mode={mode})")
    else:
        result = create_comment(repo['full_name'], pr['number'], comment_body, headers)
        logger.info(f"Created comment {result.get('id')} on PR #{pr['number']} (mode={mode})")

    return {'status': mode, 'comment_posted': True}
