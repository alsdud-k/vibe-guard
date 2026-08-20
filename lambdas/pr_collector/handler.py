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
MAX_DIFF_LINES = 5000

SECURITY_PATH_KEYWORDS = [
    "/routes/", "/api/", "/views/", "/endpoints/",
    "/middleware/", "/auth/", "/security/", "/permissions/"
]

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


def parse_vibeguard_config(raw_config: dict | None) -> dict:
    if raw_config is None or not isinstance(raw_config, dict):
        return get_default_profile()

    config = raw_config.copy()

    # Normalize auth_patterns
    if 'auth_patterns' in config and isinstance(config['auth_patterns'], dict):
        for key, pattern in config['auth_patterns'].items():
            if pattern is not None and not isinstance(pattern, str):
                config['auth_patterns'][key] = None

    # Normalize protected_paths to list of dicts
    if 'protected_paths' in config:
        normalized = []
        for item in config['protected_paths']:
            if isinstance(item, str):
                normalized.append({'path': item, 'required_auth': 'unknown'})
            elif isinstance(item, dict):
                normalized.append(item)
        config['protected_paths'] = normalized

    config.setdefault('scan_paths', ['.'])
    config.setdefault('exclude_paths', ['tests/', 'node_modules/'])
    config.setdefault('suppressions', [])
    config.setdefault('behavior', {})

    return config


def fetch_vibeguard_config(repo_full_name: str, branch: str, headers: dict) -> dict:
    url = f'{GITHUB_API}/repos/{repo_full_name}/contents/.vibeguard.yml?ref={branch}'
    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code == 200:
        try:
            raw = base64.b64decode(response.json()['content']).decode('utf-8')
            raw_config = yaml.safe_load(raw)
            if raw_config:
                config = parse_vibeguard_config(raw_config)
                return {'source': 'repository', 'config': config}
            print(".vibeguard.yml is empty — using default profile")
        except Exception as e:
            print(f"Failed to parse .vibeguard.yml: {e} — falling back to default")

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
        'suppressions': [],
        'behavior': {
            'regression_detection': 'pattern_discovery',
            'context_collection': 'broad',
            'confidence_penalty': 0.7,
        },
    }


def sort_by_security_relevance(files: list) -> list:
    def security_score(f):
        filename = f.get('filename', '')
        return 1 if any(kw in filename for kw in SECURITY_PATH_KEYWORDS) else 0
    return sorted(files, key=security_score, reverse=True)


def truncate_large_patches(files: list, max_lines: int) -> list:
    total = 0
    result = []
    for f in files:
        file_lines = f.get('additions', 0) + f.get('deletions', 0)
        if total + file_lines <= max_lines:
            total += file_lines
            result.append(f)
        else:
            remaining = max_lines - total
            if remaining > 0:
                patch = f.get('patch', '')
                if patch:
                    patch_lines = patch.split('\n')
                    truncated_patch = '\n'.join(patch_lines[:remaining]) + '\n... [truncated]'
                    result.append({**f, 'patch': truncated_patch})
                else:
                    result.append(f)
            break
    return result


def apply_limits(changed_files: list) -> tuple[list, bool]:
    truncated = False

    if len(changed_files) > MAX_FILES:
        changed_files = sort_by_security_relevance(changed_files)[:MAX_FILES]
        truncated = True

    total_lines = sum(f.get('additions', 0) + f.get('deletions', 0) for f in changed_files)
    if total_lines > MAX_DIFF_LINES:
        changed_files = truncate_large_patches(changed_files, MAX_DIFF_LINES)
        truncated = True

    return changed_files, truncated


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

    files_url = f"{GITHUB_API}/repos/{repo['full_name']}/pulls/{pr['number']}/files"
    files_response = requests.get(files_url, headers=headers, timeout=15)
    files_response.raise_for_status()
    changed_files = files_response.json()

    limited_files, truncated = apply_limits(changed_files)

    vibeguard_config = fetch_vibeguard_config(repo['full_name'], pr['base_branch'], headers)

    print(f"Collected {len(changed_files)} files for PR #{pr['number']} (using {len(limited_files)}, truncated={truncated})")
    print(f"Config source: {vibeguard_config['source']}")

    return {
        **event,
        'diff': {
            'total_files_changed': len(changed_files),
            'total_additions': sum(f.get('additions', 0) for f in changed_files),
            'total_deletions': sum(f.get('deletions', 0) for f in changed_files),
            'truncated': truncated,
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f.get('additions', 0),
                    'deletions': f.get('deletions', 0),
                    'patch': (f.get('patch') or '')[:MAX_PATCH_CHARS],
                }
                for f in limited_files
            ],
        },
        'vibeguard_config': vibeguard_config,
    }
