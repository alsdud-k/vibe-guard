import base64
import json
import os
import time

import boto3
import jwt
import requests
import yaml

secrets_client = boto3.client('secretsmanager')

SECRET_NAME = os.environ.get('SECRET_NAME', 'vibe-guard/github-app')
MAX_FILES = 30
MAX_PATCH_CHARS = 3000

_secret_cache: dict | None = None

GITHUB_API = 'https://api.github.com'


def get_secrets() -> dict:
    global _secret_cache
    if _secret_cache is None:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        _secret_cache = json.loads(response['SecretString'])
    return _secret_cache


def generate_github_jwt(app_id: str, private_key: str) -> str:
    # Secrets Manager stores literal \n; convert to real newlines
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


def fetch_vibeguard_config(repo_full_name: str, branch: str, headers: dict) -> dict:
    url = f'{GITHUB_API}/repos/{repo_full_name}/contents/.vibeguard.yml?ref={branch}'
    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code == 200:
        try:
            raw = base64.b64decode(response.json()['content']).decode('utf-8')
            config = yaml.safe_load(raw)
            if config:
                return {'source': 'repository', 'config': config}
        except Exception as e:
            print(f"Failed to parse .vibeguard.yml: {e}")

    return {'source': 'default', 'config': get_default_profile()}


def get_default_profile() -> dict:
    return {
        'framework': 'auto_detect',
        'language': 'auto_detect',
        'authentication': 'unknown',
        'auth_patterns': {'admin': None, 'user': None},
        'protected_paths': [
            {'path': '/admin', 'required_auth': 'unknown'},
            {'path': '/internal', 'required_auth': 'unknown'},
        ],
        'scan_paths': ['.'],
        'exclude_paths': ['tests/', 'node_modules/', '.git/', '__pycache__/'],
        'behavior': {
            'regression_detection': 'pattern_discovery',
            'context_collection': 'broad',
            'confidence_penalty': 0.7,
        },
    }


def lambda_handler(event, context):
    repo = event['repository']
    pr = event['pull_request']
    installation_id = event['installation_id']

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

    # Fetch changed files
    files_url = f"{GITHUB_API}/repos/{repo['full_name']}/pulls/{pr['number']}/files"
    files_response = requests.get(files_url, headers=headers, timeout=15)
    files_response.raise_for_status()
    changed_files = files_response.json()

    # Fetch optional .vibeguard.yml from base branch
    config = fetch_vibeguard_config(repo['full_name'], pr['base_branch'], headers)

    print(f"Collected {len(changed_files)} changed files for PR #{pr['number']}")
    print(f"Config source: {config['source']}")

    return {
        **event,
        'diff': {
            'total_files_changed': len(changed_files),
            'total_additions': sum(f.get('additions', 0) for f in changed_files),
            'total_deletions': sum(f.get('deletions', 0) for f in changed_files),
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f.get('additions', 0),
                    'deletions': f.get('deletions', 0),
                    'patch': (f.get('patch') or '')[:MAX_PATCH_CHARS],
                }
                for f in changed_files[:MAX_FILES]
            ],
        },
        'vibeguard_config': config,
    }
