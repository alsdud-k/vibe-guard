import json
import os
import re

RELEVANCE_RULES = {
    "HIGH": {
        "file_path_contains": [
            "/routes/", "/api/", "/views/", "/endpoints/",
            "/middleware/", "/auth/", "/security/", "/permissions/"
        ],
        "code_patterns_new": [
            r"@router\.", r"@app\.", r"APIRouter",
            r"def\s+\w+.*endpoint", r"@api_view"
        ],
        "code_patterns_removed": [
            r"Depends$", r"require_", r"authenticate",
            r"authorize", r"permission", r"@login_required"
        ],
        "sensitive_keywords_new": [
            "secret", "password", "api_key", "token",
            "private_key", "credential", "AWS_"
        ],
    },
    "MEDIUM": {
        "file_path_contains": [
            "/config/", "/settings/", "/database/", "/db/"
        ],
        "code_patterns_new": [
            r"query$", r"execute$", r"cursor\.",
            r"raw_sql", r"text$",
            r"subprocess", r"eval$", r"exec$",
            r"os\.system", r"pickle\.loads",
            r"yaml\.load$", r"shell=True"
        ]
    },
    "LOW": {
        "file_extensions": [".md", ".txt", ".rst", ".yml", ".yaml"],
        "file_path_contains": ["/tests/", "/docs/", "/migrations/"],
    },
    "SKIP": {
        "file_extensions": [
            ".png", ".jpg", ".svg", ".ico", ".gif",
            ".lock", ".sum", ".map", ".min.js", ".min.css"
        ]
    }
}

RELEVANCE_ORDER = ["SKIP", "LOW", "MEDIUM", "HIGH"]


def max_relevance(a, b):
    ia = RELEVANCE_ORDER.index(a) if a in RELEVANCE_ORDER else 0
    ib = RELEVANCE_ORDER.index(b) if b in RELEVANCE_ORDER else 0
    return RELEVANCE_ORDER[max(ia, ib)]


def get_extension(filename):
    parts = filename.rsplit(".", 1)
    return f".{parts[1]}" if len(parts) > 1 else ""


def extract_added_lines(patch):
    if not patch:
        return ""
    return "\n".join(
        line[1:] for line in patch.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    )


def extract_removed_lines(patch):
    if not patch:
        return ""
    return "\n".join(
        line[1:] for line in patch.split("\n")
        if line.startswith("-") and not line.startswith("---")
    )


def matches_exclude_paths(filename, exclude_paths):
    for path in exclude_paths:
        normalized = path.rstrip("/")
        if normalized and normalized in filename:
            return True
    return False


def is_skip_file(filename):
    ext = get_extension(filename)
    return ext in RELEVANCE_RULES["SKIP"]["file_extensions"]


def detect_domain_from_path(path_pattern):
    if path_pattern in ("/auth/", "/security/", "/permissions/"):
        return "authentication"
    return "authorization"


def detect_domain_from_pattern(pattern):
    injection_patterns = {
        r"query$", r"execute$", r"cursor\.", "raw_sql", r"text$",
        "subprocess", r"eval$", r"exec$", r"os\.system",
        r"pickle\.loads", r"yaml\.load$", "shell=True"
    }
    return "injection" if pattern in injection_patterns else "authorization"


def extract_searchable_terms(pattern_str):
    terms = re.findall(r'[\w_]+', pattern_str)
    return [t for t in terms if len(t) > 3]


def classify_file(file, config):
    reasons = []
    domains = set()
    level = "LOW"

    filename = file["filename"]
    patch = file.get("patch", "")
    added_lines = extract_added_lines(patch)
    removed_lines = extract_removed_lines(patch)

    ext = get_extension(filename)

    # LOW by extension
    if ext in RELEVANCE_RULES["LOW"]["file_extensions"]:
        reasons.append(f"low_risk_extension: {ext}")
        level = "LOW"

    # LOW by path
    for path_pattern in RELEVANCE_RULES["LOW"]["file_path_contains"]:
        if path_pattern in filename:
            reasons.append(f"low_risk_path: {path_pattern}")
            level = "LOW"

    # HIGH: file path
    for path_pattern in RELEVANCE_RULES["HIGH"]["file_path_contains"]:
        if path_pattern in filename:
            reasons.append(f"file_in_security_path: {path_pattern}")
            level = "HIGH"
            domains.add(detect_domain_from_path(path_pattern))

    # HIGH: new code patterns
    for pattern in RELEVANCE_RULES["HIGH"]["code_patterns_new"]:
        if re.search(pattern, added_lines, re.MULTILINE):
            reasons.append(f"new_code_pattern: {pattern}")
            level = "HIGH"
            domains.add("authorization")

    # HIGH: removed security patterns (regression signal)
    for pattern in RELEVANCE_RULES["HIGH"]["code_patterns_removed"]:
        if re.search(pattern, removed_lines, re.MULTILINE):
            reasons.append(f"removed_security_pattern: {pattern}")
            level = "HIGH"
            domains.add("authorization")

    # HIGH: sensitive keywords in new code
    for keyword in RELEVANCE_RULES["HIGH"]["sensitive_keywords_new"]:
        if keyword in added_lines:
            reasons.append(f"sensitive_keyword: {keyword}")
            level = "HIGH"
            domains.add("secret")

    # HIGH: protected_paths referenced in diff
    if level != "HIGH":
        for protected in config.get("protected_paths", []):
            path = protected.get("path", "") if isinstance(protected, dict) else protected
            if path and path in added_lines:
                reasons.append(f"protected_path_reference: {path}")
                level = "HIGH"
                domains.add("authorization")

    # MEDIUM: file path
    if level not in ("HIGH",):
        for path_pattern in RELEVANCE_RULES["MEDIUM"]["file_path_contains"]:
            if path_pattern in filename:
                reasons.append(f"medium_risk_path: {path_pattern}")
                level = max_relevance(level, "MEDIUM")
                domains.add("configuration")

        # MEDIUM: code patterns
        for pattern in RELEVANCE_RULES["MEDIUM"]["code_patterns_new"]:
            if re.search(pattern, added_lines, re.MULTILINE):
                reasons.append(f"medium_risk_pattern: {pattern}")
                level = max_relevance(level, "MEDIUM")
                domains.add(detect_domain_from_pattern(pattern))

    if level in ("HIGH", "MEDIUM") and not domains:
        domains.add("authorization")

    return level, reasons, domains


def build_search_plan(domains, config):
    plan = {}

    if "authorization" in domains:
        auth_patterns = config.get("auth_patterns", {})
        terms = []
        for name, pattern in auth_patterns.items():
            if pattern and isinstance(pattern, str):
                terms.extend(extract_searchable_terms(pattern))
        plan["authorization"] = {
            "search_terms": terms or ["require_", "permission", "authorize", "Depends"],
            "search_paths": config.get("scan_paths", ["."]),
            "max_files": 10,
            "max_tokens": 2000
        }

    if "authentication" in domains:
        plan["authentication"] = {
            "search_terms": ["login", "authenticate", "jwt", "token", "session", "verify"],
            "search_paths": config.get("scan_paths", ["."]),
            "max_files": 5,
            "max_tokens": 1000
        }

    if "secret" in domains:
        plan["secret"] = {
            "search_terms": ["os.environ", "settings.", "config.", "getenv"],
            "search_paths": config.get("scan_paths", ["."]),
            "max_files": 5,
            "max_tokens": 500
        }

    return plan


def lambda_handler(event, context):
    files = event["diff"]["files"]
    config = event["vibeguard_config"]["config"]
    exclude_paths = config.get("exclude_paths", [])

    security_files = []
    non_security_files = []
    detected_domains = set()
    max_level = "SKIP"

    for file in files:
        filename = file["filename"]

        if matches_exclude_paths(filename, exclude_paths):
            non_security_files.append(filename)
            continue

        if is_skip_file(filename):
            continue

        file_level, reasons, domains = classify_file(file, config)

        if file_level in ("HIGH", "MEDIUM"):
            security_files.append({
                "filename": filename,
                "relevance": file_level,
                "reasons": reasons,
                "domains": list(domains)
            })
            detected_domains.update(domains)
        else:
            non_security_files.append(filename)

        max_level = max_relevance(max_level, file_level)

    context_search_plan = build_search_plan(detected_domains, config)

    print(f"Relevance: {max_level}, security_files: {len(security_files)}, domains: {sorted(detected_domains)}")

    return {
        **event,
        "relevance": {
            "level": max_level,
            "security_files": security_files,
            "non_security_files": non_security_files,
            "primary_domains": sorted(detected_domains),
            "context_search_plan": context_search_plan
        }
    }
