import json
import os
import re

import boto3
import botocore.exceptions

bedrock = boto3.client('bedrock-runtime', region_name=os.environ.get('REGION', 'us-east-1'))

HAIKU_MODEL_ID = 'us.anthropic.claude-haiku-4-5-20251001-v1:0'
SONNET_MODEL_ID = 'us.anthropic.claude-sonnet-4-5-20250929-v1:0'

SYSTEM_PROMPT = """You are a security engineer reviewing a GitHub Pull Request.
Your task is to determine if this PR introduces security regressions
by comparing it against the repository's existing security patterns.

IMPORTANT RULES:
1. Only flag issues where you have strong evidence from the repository context.
2. If an alternative security pattern is used, evaluate if it provides EQUIVALENT protection.
   Functions whose names contain keywords like 'require_admin', 'verify_admin', 'check_permission',
   'auth_required', 'admin_only', or similar authorization terms should be presumed to provide
   equivalent protection UNLESS the diff clearly shows the function body is insecure.
3. Do NOT flag style differences as security issues.
4. A Regression Candidate marked as "authorization_insufficient" means there IS some auth
   but it might not be the right LEVEL. Evaluate carefully.
5. If confidence from rule-based analysis is below 0.5, be extra careful before confirming.
6. All text fields must be in Korean.
7. Output MUST be valid JSON matching the exact schema below — no markdown, no explanation.
8. If multiple endpoints in the same PR share the same vulnerability (e.g., all lack authentication),
   assess them as a group. When 3 or more similar issues appear together, escalate the overall
   severity by one level (LOW→MEDIUM, MEDIUM→HIGH, HIGH→CRITICAL).
9. Hardcoded secrets include not only API keys and tokens but also hardcoded passwords —
   including weak or common defaults such as "admin123", "password", "123456", "secret",
   "admin", "root", "test", "changeme". These must be flagged as SECRET exposure findings.

OUTPUT SCHEMA:
{
  "findings": [
    {
      "title": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "authorization|authentication|secret|injection|configuration",
      "affected_file": "string",
      "affected_line": 0,
      "issue": "string",
      "repository_evidence": ["string"],
      "recommendation": "string",
      "reasoning": "string",
      "is_regression": true,
      "confidence_adjustment": 0.0
    }
  ],
  "dismissed_candidates": [
    {
      "candidate_type": "string",
      "reason": "string"
    }
  ],
  "additional_concerns": [
    {
      "description": "string",
      "severity": "LOW|MEDIUM",
      "affected_file": "string"
    }
  ],
  "summary": "string"
}"""

USER_PROMPT_TEMPLATE = """## Security Profile
Framework: {framework}
Authentication: {authentication}

Auth Patterns:
{auth_patterns_formatted}

Protected Paths:
{protected_paths_formatted}

---

## PR Diff (보안 관련 파일만)
```
{filtered_diff}
```

---

## Repository Security Context
{repository_context_formatted}

Pattern Statistics:
{pattern_statistics_formatted}

---

## Regression Candidates (Rule 기반 사전 분석)
{regression_candidates_formatted}

---

위 정보를 종합하여:
1. 각 Regression Candidate가 실제 보안 문제인지 판단하세요.
2. 대안 패턴이 있는 경우 동등한 보호를 제공하는지 평가하세요.
3. Rule이 놓친 추가적인 보안 우려가 있는지 확인하세요:
   - 하드코딩된 시크릿: API 키, 토큰, 비밀번호 (admin123, password, 123456 등 기본값 포함)
   - 한 PR에 동일 취약 패턴이 여러 개 있으면 그룹으로 묶어 심각도를 상향 평가하세요.
4. 확실한 근거가 없는 문제는 보고하지 마세요.
5. JSON만 출력하세요."""


def _format_auth_patterns(auth_patterns):
    if not auth_patterns:
        return '  (정의되지 않음 — 기본 Profile)'
    return '\n'.join(f'  {name}: {pattern}' for name, pattern in auth_patterns.items() if pattern)


def _format_protected_paths(protected_paths):
    if not protected_paths:
        return '  (정의되지 않음)'
    return '\n'.join(
        f"  {p['path']} → required: {p.get('required_auth', 'unknown')}"
        for p in protected_paths
    )


def _format_repository_context(repo_context):
    if not repo_context:
        return '  (컨텍스트 없음)'
    evidence_files = repo_context.get('evidence_files', [])
    if not evidence_files:
        return '  (관련 파일 없음)'
    lines = []
    for ef in evidence_files[:8]:
        lines.append(f"File: {ef['file']} (domain: {ef.get('domain', 'unknown')})")
        for matched_line in (ef.get('lines') or [])[:3]:
            lines.append(f"  {matched_line.strip()}")
    return '\n'.join(lines)


def _format_pattern_stats(stats):
    if not stats:
        return '  (통계 없음)'
    return '\n'.join(
        f"  {term}: {data.get('occurrences', 0)}회 ({len(data.get('files', []))} files)"
        for term, data in list(stats.items())[:10]
    )


def _format_candidates(candidates):
    if not candidates:
        return '  (탐지된 후보 없음)'
    parts = []
    for c in candidates:
        parts.append(f"[{c['severity_hint']}] {c['type']} — {c.get('endpoint', c['file'])}")
        parts.append(f"  File: {c['file']}, Line: {c.get('line', '?')}")
        parts.append(f"  Expected: {c.get('expected_pattern', '?')}")
        parts.append(f"  Actual: {c.get('actual_pattern', 'none')}")
        parts.append(f"  Confidence: {c.get('confidence', 0)}")
        evidence = c.get('evidence', {})
        if evidence:
            parts.append(
                f"  Evidence: ratio={evidence.get('existing_pattern_ratio', '?')}, "
                f"examples={evidence.get('similar_endpoints', [])}"
            )
        parts.append('')
    return '\n'.join(parts)


def build_user_prompt(event):
    config = event.get('vibeguard_config', {}).get('config', {})
    repo_context = event.get('repository_context', {})

    security_filenames = {f['filename'] for f in event.get('relevance', {}).get('security_files', [])}
    filtered_diff_parts = [
        f"=== {f['filename']} ({f['status']}) ===\n{f.get('patch', '')}"
        for f in event.get('diff', {}).get('files', [])
        if f['filename'] in security_filenames
    ]

    return USER_PROMPT_TEMPLATE.format(
        framework=config.get('framework', 'unknown'),
        authentication=config.get('authentication', 'unknown'),
        auth_patterns_formatted=_format_auth_patterns(config.get('auth_patterns', {})),
        protected_paths_formatted=_format_protected_paths(config.get('protected_paths', [])),
        filtered_diff='\n'.join(filtered_diff_parts)[:3000],
        repository_context_formatted=_format_repository_context(repo_context)[:2500],
        pattern_statistics_formatted=_format_pattern_stats(repo_context.get('pattern_statistics', {})),
        regression_candidates_formatted=_format_candidates(event.get('regression_candidates', [])),
    )


def invoke_bedrock(system_prompt, user_prompt, model_id):
    body = json.dumps({
        'anthropic_version': 'bedrock-2023-05-31',
        'max_tokens': 2000,
        'temperature': 0.1,
        'system': system_prompt,
        'messages': [{'role': 'user', 'content': user_prompt}],
    })
    response = bedrock.invoke_model(
        modelId=model_id,
        body=body,
        contentType='application/json',
        accept='application/json',
    )
    result = json.loads(response['body'].read())
    return {
        'model': model_id,
        'content': result['content'][0]['text'],
        'usage': result.get('usage', {}),
    }


def parse_bedrock_response(content):
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    json_match = re.search(r'```json\s*\n(.*?)\n```', content, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    brace_match = re.search(r'\{.*\}', content, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    return {
        'findings': [],
        'dismissed_candidates': [],
        'additional_concerns': [],
        'summary': 'AI 응답 파싱 실패 — Rule 기반 결과만 사용합니다.',
    }


def lambda_handler(event, context):
    user_prompt = build_user_prompt(event)
    model_used = HAIKU_MODEL_ID

    try:
        response = invoke_bedrock(SYSTEM_PROMPT, user_prompt, HAIKU_MODEL_ID)
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        # Re-raise throttling so Step Functions Retry handles it
        if error_code in ('ThrottlingException', 'ServiceUnavailableException', 'ModelTimeoutException'):
            raise
        # Other errors — try Sonnet fallback
        print(f"Haiku failed ({error_code}), falling back to Sonnet")
        try:
            response = invoke_bedrock(SYSTEM_PROMPT, user_prompt, SONNET_MODEL_ID)
            model_used = SONNET_MODEL_ID
        except Exception as fallback_err:
            print(f"Sonnet fallback failed: {fallback_err}")
            return {
                **event,
                'bedrock_review': {
                    'model_used': 'none',
                    'findings': [],
                    'dismissed_candidates': [],
                    'additional_concerns': [],
                    'summary': f'Bedrock 호출 실패: {str(fallback_err)[:200]}',
                    'input_tokens': 0,
                    'output_tokens': 0,
                },
            }

    bedrock_result = parse_bedrock_response(response['content'])
    findings = bedrock_result.get('findings', [])

    print(f"Bedrock review complete ({model_used}): {len(findings)} findings")
    for f in findings:
        print(f"  [{f.get('severity', '?')}] {f.get('title', '?')}")

    return {
        **event,
        'bedrock_review': {
            'model_used': model_used,
            'findings': findings,
            'dismissed_candidates': bedrock_result.get('dismissed_candidates', []),
            'additional_concerns': bedrock_result.get('additional_concerns', []),
            'summary': bedrock_result.get('summary', ''),
            'input_tokens': response['usage'].get('input_tokens', 0),
            'output_tokens': response['usage'].get('output_tokens', 0),
        },
    }
