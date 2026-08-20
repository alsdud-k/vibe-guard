import base64
import json
import os
import time

import boto3
import jwt
import requests

secrets_client = boto3.client("secretsmanager")

SECRET_NAME = os.environ.get("SECRET_NAME", "vibe-guard/github-app")
GITHUB_API = "https://api.github.com"
MAX_TOTAL_TOKENS = 4000

_secret_cache = None


def get_secrets():
    global _secret_cache
    if _secret_cache is None:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        _secret_cache = json.loads(response["SecretString"])
    return _secret_cache


def generate_github_jwt(app_id, private_key):
    private_key = private_key.replace("\\n", "\n")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
    return jwt.encode(payload, private_key, algorithm="RS256")


def generate_installation_token(installation_id, app_id, private_key):
    jwt_token = generate_github_jwt(app_id, private_key)
    response = requests.post(
        f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json",
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["token"]


def list_directory_recursive(repo_full_name, path, branch, headers, depth=0):
    if depth > 2:
        return []
    url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{path.rstrip('/')}?ref={branch}"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        return []

    items = response.json()
    if not isinstance(items, list):
        return []

    files = []
    for item in items:
        if item["type"] == "file":
            files.append(item["path"])
        elif item["type"] == "dir":
            files.extend(
                list_directory_recursive(repo_full_name, item["path"], branch, headers, depth + 1)
            )
    return files


def get_file_content(repo_full_name, filepath, branch, headers):
    url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{filepath}?ref={branch}"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        return None
    try:
        return base64.b64decode(response.json()["content"]).decode("utf-8")
    except Exception:
        return None


def find_relevant_lines(content, search_terms):
    """Return lines matching any search term, plus 2 lines of surrounding context."""
    lines = content.split("\n")
    matched_indices = set()

    for i, line in enumerate(lines):
        for term in search_terms:
            if term in line:
                for j in range(max(0, i - 2), min(len(lines), i + 3)):
                    matched_indices.add(j)
                break

    return [{"line": i + 1, "content": lines[i]} for i in sorted(matched_indices)]


def get_matched_terms(relevant_lines, search_terms):
    matched = set()
    for entry in relevant_lines:
        for term in search_terms:
            if term in entry["content"]:
                matched.add(term)
    return sorted(matched)


def estimate_tokens(lines):
    total_chars = sum(len(l["content"]) for l in lines)
    return total_chars // 4


def lambda_handler(event, context):
    repo = event["repository"]
    search_plan = event["relevance"]["context_search_plan"]
    config = event["vibeguard_config"]["config"]
    installation_id = event["installation_id"]
    base_branch = event["pull_request"]["base_branch"]

    if not search_plan:
        print("Empty search plan — skipping context collection")
        return {
            **event,
            "repository_context": {
                "evidence_files": [],
                "pattern_statistics": {},
                "total_tokens_estimated": 0,
                "search_completed": True
            }
        }

    secrets = get_secrets()
    token = generate_installation_token(installation_id, secrets["app_id"], secrets["private_key"])
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    total_tokens = 0
    evidence_files = []
    pattern_statistics = {}

    for domain, plan in search_plan.items():
        if total_tokens >= MAX_TOTAL_TOKENS:
            break

        # Collect candidate Python files from each search path
        target_files = []
        for search_path in plan["search_paths"]:
            files = list_directory_recursive(repo["full_name"], search_path, base_branch, headers)
            target_files.extend(f for f in files if f.endswith(".py"))

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for f in target_files:
            if f not in seen:
                seen.add(f)
                deduped.append(f)

        for filepath in deduped[:plan.get("max_files", 10)]:
            if total_tokens >= MAX_TOTAL_TOKENS:
                break

            content = get_file_content(repo["full_name"], filepath, base_branch, headers)
            if not content:
                continue

            relevant_lines = find_relevant_lines(content, plan["search_terms"])

            if relevant_lines:
                tokens = estimate_tokens(relevant_lines)
                if total_tokens + tokens > MAX_TOTAL_TOKENS:
                    break
                total_tokens += tokens
                evidence_files.append({
                    "file": filepath,
                    "relevant_lines": relevant_lines,
                    "domain": domain,
                    "matched_terms": get_matched_terms(relevant_lines, plan["search_terms"])
                })

            # Collect pattern frequency statistics across all visited files
            for term in plan["search_terms"]:
                count = content.count(term)
                if count > 0:
                    if term not in pattern_statistics:
                        pattern_statistics[term] = {"occurrences": 0, "files": []}
                    pattern_statistics[term]["occurrences"] += count
                    if filepath not in pattern_statistics[term]["files"]:
                        pattern_statistics[term]["files"].append(filepath)

    print(f"Context collected: {len(evidence_files)} evidence files, ~{total_tokens} tokens")

    return {
        **event,
        "repository_context": {
            "evidence_files": evidence_files,
            "pattern_statistics": pattern_statistics,
            "total_tokens_estimated": total_tokens,
            "search_completed": total_tokens < MAX_TOTAL_TOKENS
        }
    }
