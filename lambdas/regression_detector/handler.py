import re


# ── Helpers ──────────────────────────────────────────────────────────────────

def extract_new_endpoints(patch, filename):
    """Extract newly added API endpoints (FastAPI/Flask decorators) from a diff patch."""
    endpoints = []
    lines = patch.split('\n')
    add_line = 0

    for i, line in enumerate(lines):
        hunk_match = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
        if hunk_match:
            add_line = int(hunk_match.group(1)) - 1
            continue

        if not line.startswith('-'):
            add_line += 1

        if not line.startswith('+'):
            continue

        decorator_match = re.match(
            r'^\+\s*@(?:router|app)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            line
        )
        if not decorator_match:
            continue

        method = decorator_match.group(1).upper()
        path = decorator_match.group(2)

        func_parts = []
        for j in range(i + 1, min(i + 35, len(lines))):
            fl = lines[j]
            if fl.startswith('+') or fl.startswith(' '):
                func_parts.append(fl[1:])
            if len(func_parts) >= 30:
                break

        endpoints.append({
            'method': method,
            'path': path,
            'line': add_line,
            'code': '\n'.join(func_parts),
            'filename': filename,
        })

    return endpoints


def match_protected_path(endpoint_path, protected_paths):
    for protection in protected_paths:
        protected = protection.get('path', '')
        if protected and (endpoint_path.startswith(protected) or protected in endpoint_path):
            return protection
    return None


def extract_searchable_terms(pattern):
    """Extract meaningful identifiers from an auth pattern string."""
    terms = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]+', pattern)
    stopwords = {'Depends', 'True', 'False', 'None', 'self', 'return', 'async', 'await'}
    return [t for t in terms if len(t) > 3 and t not in stopwords]


def pattern_in_code(code, pattern):
    if not pattern:
        return False
    if pattern in code:
        return True
    terms = extract_searchable_terms(pattern)
    return any(t in code for t in terms if len(t) > 4)


def find_alternative_auth_patterns(code):
    """Detect non-standard but plausible auth/authz patterns in code."""
    alternatives = []
    patterns = [
        (r'verify.*admin', 'custom_admin_verification'),
        (r'check.*permission', 'permission_check'),
        (r'require.*role', 'role_requirement'),
        (r'\bis_admin\b', 'admin_check'),
        (r'HTTPException.*status_code=40[13]', 'manual_auth_error'),
        (r'Depends\([^)]+\)', 'depends_injection'),
    ]
    for regex, name in patterns:
        if re.search(regex, code, re.IGNORECASE):
            alternatives.append({'pattern': name, 'matched': regex})
    return alternatives


def get_pattern_stats(repo_context, required_pattern, endpoint_path):
    if not repo_context or not required_pattern:
        return {}
    stats = repo_context.get('pattern_statistics', {})
    terms = extract_searchable_terms(required_pattern)
    for term in terms:
        if term in stats:
            data = stats[term]
            total = data.get('occurrences', 0)
            files = data.get('files', [])
            ratio = min(1.0, total / 10) if total > 0 else 0
            return {'ratio': ratio, 'occurrences': total, 'examples': files[:3]}
    return {'ratio': 0, 'occurrences': 0, 'examples': []}


def calculate_confidence(pattern_stats, has_alternative, config_source):
    base = 0.5
    ratio = pattern_stats.get('ratio', 0)
    if ratio >= 0.9:
        base += 0.3
    elif ratio >= 0.7:
        base += 0.2
    elif ratio >= 0.5:
        base += 0.1

    if has_alternative:
        base -= 0.2

    if config_source == 'default':
        base *= 0.7

    return round(min(0.99, max(0.1, base)), 2)


# ── Detection logic ──────────────────────────────────────────────────────────

def detect_authorization_regression(diff, config, repo_context, config_source):
    candidates = []
    protected_paths = config.get('protected_paths', [])
    auth_patterns = config.get('auth_patterns', {})

    for file in diff.get('files', []):
        if file.get('status') not in ('added', 'modified'):
            continue

        patch = file.get('patch', '')
        if not patch:
            continue

        for endpoint in extract_new_endpoints(patch, file['filename']):
            matched_protection = match_protected_path(endpoint['path'], protected_paths)
            if not matched_protection:
                continue

            required_auth = matched_protection.get('required_auth', 'unknown')
            required_pattern = auth_patterns.get(required_auth)

            if pattern_in_code(endpoint['code'], required_pattern):
                continue

            alternative_auth = find_alternative_auth_patterns(endpoint['code'])
            pattern_stats = get_pattern_stats(repo_context, required_pattern, endpoint['path'])
            confidence = calculate_confidence(pattern_stats, bool(alternative_auth), config_source)

            candidate_type = 'authorization_missing' if not alternative_auth else 'authorization_insufficient'
            severity_hint = 'HIGH' if not alternative_auth else 'MEDIUM'

            candidates.append({
                'type': candidate_type,
                'severity_hint': severity_hint,
                'file': file['filename'],
                'line': endpoint['line'],
                'endpoint': f"{endpoint['method']} {endpoint['path']}",
                'expected_pattern': required_pattern,
                'actual_pattern': [a['pattern'] for a in alternative_auth] if alternative_auth else None,
                'evidence': {
                    'protected_path_match': matched_protection['path'],
                    'required_auth_level': required_auth,
                    'existing_pattern_ratio': pattern_stats.get('ratio', 'unknown'),
                    'similar_endpoints': pattern_stats.get('examples', []),
                },
                'confidence': confidence,
            })

    return candidates


def detect_removed_security_patterns(diff, config):
    candidates = []
    auth_patterns = config.get('auth_patterns', {})
    all_patterns = [p for p in auth_patterns.values() if p]

    for file in diff.get('files', []):
        if file.get('status') == 'added':
            continue

        patch = file.get('patch', '')
        if not patch:
            continue

        removed_lines = [l[1:] for l in patch.split('\n') if l.startswith('-')]

        for pattern in all_patterns:
            keywords = [k for k in extract_searchable_terms(pattern) if len(k) >= 5]
            for keyword in keywords:
                for line in removed_lines:
                    if keyword in line:
                        candidates.append({
                            'type': 'authorization_removed',
                            'severity_hint': 'CRITICAL',
                            'file': file['filename'],
                            'line': None,
                            'endpoint': 'unknown',
                            'expected_pattern': pattern,
                            'actual_pattern': None,
                            'evidence': {
                                'removed_code': line.strip()[:200],
                                'pattern_keyword': keyword,
                            },
                            'confidence': 0.85,
                        })
                        break  # one candidate per pattern per file

    return candidates


def apply_suppressions(candidates, suppressions):
    filtered = []
    for candidate in candidates:
        suppressed = False
        for suppression in suppressions:
            file_match = suppression.get('file', '') in candidate.get('file', '')
            rule_match = (
                suppression.get('rule') == '*' or
                suppression.get('rule') == candidate.get('type')
            )
            if file_match and rule_match:
                suppressed = True
                break
        if not suppressed:
            filtered.append(candidate)
    return filtered


# ── Lambda handler ───────────────────────────────────────────────────────────

def lambda_handler(event, context):
    diff = event['diff']
    vibeguard_config = event.get('vibeguard_config', {})
    config = vibeguard_config.get('config', {})
    config_source = vibeguard_config.get('source', 'default')
    repo_context = event.get('repository_context', {})

    candidates = []
    candidates.extend(detect_authorization_regression(diff, config, repo_context, config_source))
    candidates.extend(detect_removed_security_patterns(diff, config))
    candidates = apply_suppressions(candidates, config.get('suppressions', []))

    print(f"Regression detection complete: {len(candidates)} candidates")
    for c in candidates:
        print(f"  [{c['severity_hint']}] {c['type']} — {c.get('endpoint', c['file'])} (confidence={c['confidence']})")

    return {
        **event,
        'regression_candidates': candidates,
    }
