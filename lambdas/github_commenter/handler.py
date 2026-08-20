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


def build_comment_body(pr: dict, diff: dict) -> str:
    commit_short = pr['head_sha'][:7]
    files_changed = diff.get('total_files_changed', 0)
    additions = diff.get('total_additions', 0)
    deletions = diff.get('total_deletions', 0)

    return f"""{COMMENT_MARKER}
## 🛡️ VibeGuard Security Review

⏳ 분석이 완료되었습니다.

| | |
|---|---|
| **PR** | #{pr['number']} {pr['title']} |
| **Commit** | `{commit_short}` |
| **Files Changed** | {files_changed} (+{additions} / -{deletions}) |

> Phase 2에서 실제 보안 분석 결과가 여기에 표시됩니다.

---
<sub>VibeGuard v0.1</sub>
"""


def lambda_handler(event, context):
    repo = event['repository']
    pr = event['pull_request']
    installation_id = event['installation_id']
    diff = event.get('diff', {})

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

    comment_body = build_comment_body(pr, diff)
    existing_comment_id = find_existing_comment(repo['full_name'], pr['number'], headers)

    if existing_comment_id:
        update_comment(repo['full_name'], existing_comment_id, comment_body, headers)
        print(f"Updated comment {existing_comment_id} on PR #{pr['number']}")
    else:
        result = create_comment(repo['full_name'], pr['number'], comment_body, headers)
        print(f"Created comment {result.get('id')} on PR #{pr['number']}")

    return {**event, 'comment_posted': True}
