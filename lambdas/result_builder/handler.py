import decimal
import json
import logging
import time
import uuid
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SEVERITY_WEIGHT = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 10, 'LOW': 3}
CATEGORY_MULTIPLIER = {
    'authorization': 1.3,
    'authentication': 1.3,
    'secret': 1.5,
    'injection': 1.2,
    'configuration': 1.0,
}
SEVERITY_EMOJI = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}


def _log(level, message, **kwargs):
    entry = {'level': level, 'message': message, 'service': 'vibe-guard-result-builder', **kwargs}
    if level == 'ERROR':
        logger.error(json.dumps(entry))
    else:
        logger.info(json.dumps(entry))


def calculate_risk_score(findings):
    if not findings:
        return 0, 'LOW'

    total = 0.0
    for finding in findings:
        base = SEVERITY_WEIGHT.get(finding.get('severity', 'LOW'), 3)
        multiplier = CATEGORY_MULTIPLIER.get(finding.get('category', 'configuration'), 1.0)
        confidence = finding.get('final_confidence', 0.5)
        total += base * multiplier * confidence

    normalized = min(100, round(total))
    if normalized >= 80:
        level = 'CRITICAL'
    elif normalized >= 60:
        level = 'HIGH'
    elif normalized >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'
    return normalized, level


def find_matching_candidate(finding, candidates):
    affected_file = finding.get('affected_file', '')
    affected_line = finding.get('affected_line') or 0

    for c in candidates:
        if c['file'] == affected_file and abs((c.get('line') or 0) - affected_line) <= 5:
            return c
    for c in candidates:
        if c['file'] == affected_file:
            return c
    return None


def get_code_at_location(diff, filename, _line):
    for f in diff.get('files', []):
        if f['filename'] == filename:
            patch = f.get('patch', '')
            added = [l[1:].strip() for l in patch.split('\n') if l.startswith('+') and not l.startswith('+++')]
            return '\n'.join(added[:3])
    return ''


def calculate_final_confidence(candidate, finding):
    base = candidate.get('confidence', 0.5) if candidate else 0.5
    adjustment = finding.get('confidence_adjustment', 0)
    return round(min(0.99, max(0.1, base + adjustment)), 2)


def build_evidence(finding, event):
    candidate = find_matching_candidate(finding, event.get('regression_candidates', []))
    final_confidence = calculate_final_confidence(candidate, finding)

    return {
        'finding_id': str(uuid.uuid4()),
        'finding_title': finding['title'],
        'changed_code': {
            'file': finding.get('affected_file', ''),
            'line': finding.get('affected_line'),
            'content': get_code_at_location(
                event.get('diff', {}),
                finding.get('affected_file', ''),
                finding.get('affected_line'),
            ),
        },
        'security_profile_evidence': {
            'config_source': event.get('vibeguard_config', {}).get('source', 'unknown'),
            'protected_path': (candidate.get('evidence', {}) or {}).get('protected_path_match') if candidate else None,
            'required_pattern': candidate.get('expected_pattern') if candidate else None,
        },
        'repository_evidence': finding.get('repository_evidence', []),
        'pattern_statistics': {
            'pattern': candidate.get('expected_pattern') if candidate else None,
            'ratio': (candidate.get('evidence', {}) or {}).get('existing_pattern_ratio') if candidate else None,
            'examples': ((candidate.get('evidence', {}) or {}).get('similar_endpoints') or []) if candidate else [],
        },
        'decision_chain': {
            'relevance_filter': event.get('relevance', {}).get('level', 'UNKNOWN'),
            'rule_based': f"{candidate['type']} (confidence: {candidate['confidence']})" if candidate else 'N/A',
            'bedrock': f"CONFIRMED (severity: {finding.get('severity', '?')})",
            'final': f"{finding.get('severity', '?')} — {finding.get('title', '')}",
        },
        'confidence': {
            'rule_based': candidate.get('confidence', 0) if candidate else 0,
            'bedrock_adjustment': finding.get('confidence_adjustment', 0),
            'final': final_confidence,
        },
    }


def determine_review_action(risk_score, risk_level):
    if risk_level == 'CRITICAL':
        return {'action': 'REQUEST_CHANGES', 'prefix': '⛔', 'message': '심각한 보안 이슈입니다. 수정이 필요합니다.'}
    elif risk_level == 'HIGH':
        return {'action': 'REQUEST_CHANGES', 'prefix': '🟠', 'message': '보안 이슈 수정 후 재검토를 권장합니다.'}
    elif risk_level == 'MEDIUM':
        return {'action': 'COMMENT', 'prefix': '⚠️', 'message': '확인을 권장합니다.'}
    else:
        return {'action': 'COMMENT', 'prefix': '✅', 'message': '경미한 권장사항입니다.'}


def render_finding(finding, evidence):
    severity = finding.get('severity', 'LOW')
    emoji = SEVERITY_EMOJI.get(severity, '⚪')

    section = f"### {emoji} [{severity}] {finding.get('title', '')}\n\n"
    section += f"📍 `{finding.get('affected_file', '?')}:{finding.get('affected_line', '?')}`\n\n"
    section += f"{finding.get('issue', '')}\n\n"

    section += "<details>\n<summary>📋 Evidence</summary>\n\n"

    prof_ev = evidence.get('security_profile_evidence', {}) or {}
    if prof_ev.get('protected_path'):
        section += "**Security Profile**\n"
        section += f"- `{prof_ev['protected_path']}` → `{prof_ev.get('required_pattern', '?')}`\n\n"

    repo_ev = finding.get('repository_evidence', [])
    if repo_ev:
        section += "**Repository Evidence**\n"
        for ev in repo_ev[:5]:
            section += f"- `{ev}`\n"
        section += "\n"

    ratio = (evidence.get('pattern_statistics') or {}).get('ratio')
    if ratio:
        section += f"**Pattern Usage:** 기존 endpoint의 {ratio}에서 해당 패턴 사용\n\n"

    confidence = (evidence.get('confidence') or {}).get('final', 0)
    section += f"**Confidence:** {int(confidence * 100)}%\n\n"

    section += "</details>\n\n"

    if finding.get('recommendation'):
        section += f"#### 💡 Recommendation\n\n{finding['recommendation']}\n\n"

    section += "---\n\n"
    return section


def render_dismissed(dismissed):
    if not dismissed:
        return ''
    section = f"\n<details>\n<summary>ℹ️ 검토 후 무시된 항목 ({len(dismissed)}개)</summary>\n\n"
    for item in dismissed:
        section += f"- **{item.get('candidate_type', '?')}** — {item.get('reason', '')}\n"
    section += "\n</details>\n\n"
    return section


def render_footer(event):
    config_source = event.get('vibeguard_config', {}).get('source', 'unknown')
    bedrock_tokens = (event.get('bedrock_review') or {}).get('input_tokens', 0)
    footer = "<sub>VibeGuard v0.4"
    footer += f" • Config: {config_source}"
    if bedrock_tokens:
        footer += f" • Tokens: {bedrock_tokens}"
    footer += " • 이 분석이 부정확한 경우 `.vibeguard.yml`의 suppressions에 추가해주세요."
    footer += "</sub>"
    return footer


def render_comment(findings, evidence, risk_score, risk_level, review_action, dismissed, summary, event):
    sections = [
        "## 🛡️ VibeGuard Security Review\n",
        f"**Risk: {review_action['prefix']} {risk_level} — {risk_score} / 100**\n",
    ]

    if summary:
        sections.append(f"> {summary}\n")

    sections.append("---\n")

    if findings:
        for i, finding in enumerate(findings):
            ev = evidence[i] if i < len(evidence) else {}
            sections.append(render_finding(finding, ev))
    else:
        sections.append("✅ 보안 이슈가 발견되지 않았습니다.\n")

    dismissed_section = render_dismissed(dismissed)
    if dismissed_section:
        sections.append(dismissed_section)

    sections.append("---\n")
    sections.append(f"{review_action['prefix']} **{review_action['action'].replace('_', ' ').title()}** — {review_action['message']}\n")
    sections.append("---\n")
    sections.append(render_footer(event))

    return "\n".join(sections)


def _make_marker(pr_number):
    return f"<!-- vibe-guard:pr-{pr_number} -->"


def build_full_result(event):
    bedrock_review = event.get('bedrock_review', {})
    findings = bedrock_review.get('findings', [])

    enriched_findings = []
    all_evidence = []
    for finding in findings:
        evidence = build_evidence(finding, event)
        finding['final_confidence'] = evidence['confidence']['final']
        enriched_findings.append(finding)
        all_evidence.append(evidence)

    risk_score, risk_level = calculate_risk_score(enriched_findings)
    review_action = determine_review_action(risk_score, risk_level)
    pr_number = event['pull_request']['number']
    marker = _make_marker(pr_number)

    comment_body = render_comment(
        findings=enriched_findings,
        evidence=all_evidence,
        risk_score=risk_score,
        risk_level=risk_level,
        review_action=review_action,
        dismissed=bedrock_review.get('dismissed_candidates', []),
        summary=bedrock_review.get('summary', ''),
        event=event,
    )

    _log('INFO', 'Result built',
        repository=event.get('repository', {}).get('full_name', ''),
        pr_number=pr_number,
        risk_score=risk_score,
        risk_level=risk_level,
        findings_count=len(enriched_findings),
        analysis_mode='full',
        bedrock_tokens=bedrock_review.get('input_tokens', 0),
    )

    return {
        **event,
        'final_result': {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'review_action': review_action,
            'findings': enriched_findings,
            'evidence': all_evidence,
            'dismissed_candidates': bedrock_review.get('dismissed_candidates', []),
            'additional_concerns': bedrock_review.get('additional_concerns', []),
            'comment_body': f"{marker}\n{comment_body}",
            'comment_marker': marker,
            'analysis_mode': 'full',
        },
    }


def build_degraded_result(event):
    candidates = event.get('regression_candidates', [])
    pr_number = event['pull_request']['number']
    marker = _make_marker(pr_number)

    findings = []
    for candidate in candidates:
        findings.append({
            'title': f"Potential {candidate['type'].replace('_', ' ').title()}",
            'severity': candidate['severity_hint'],
            'category': 'authorization',
            'affected_file': candidate['file'],
            'affected_line': candidate.get('line'),
            'issue': f"Rule 기반 분석에서 {candidate['type']}이 감지되었습니다. AI 확인이 완료되지 않아 정확도가 낮을 수 있습니다.",
            'recommendation': f"Expected pattern: {candidate.get('expected_pattern', 'unknown')}",
            'final_confidence': round(candidate['confidence'] * 0.7, 2),
            'repository_evidence': [],
            'confidence_adjustment': 0,
        })

    risk_score, risk_level = calculate_risk_score(findings)
    review_action = determine_review_action(risk_score, risk_level)

    sections = [
        "## 🛡️ VibeGuard Security Review\n",
        f"**Risk: {review_action['prefix']} {risk_level} — {risk_score} / 100**\n",
        "> ⚠️ AI 분석이 완료되지 않았습니다. Rule 기반 결과만 표시됩니다.\n",
        "---\n",
    ]

    if findings:
        for finding in findings:
            evidence = build_evidence(finding, event)
            sections.append(render_finding(finding, evidence))
    else:
        sections.append("✅ Rule 기반 분석에서 이슈가 발견되지 않았습니다.\n")

    sections.append(f"---\n{render_footer(event)}")

    _log('INFO', 'Degraded result built',
        repository=event.get('repository', {}).get('full_name', ''),
        pr_number=pr_number,
        risk_score=risk_score,
        findings_count=len(findings),
    )

    return {
        **event,
        'final_result': {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'review_action': review_action,
            'findings': findings,
            'evidence': [],
            'dismissed_candidates': [],
            'additional_concerns': [],
            'comment_body': f"{marker}\n" + "\n".join(sections),
            'comment_marker': marker,
            'analysis_mode': 'rule_only',
        },
    }


def build_minimal_result(event):
    security_files = (event.get('relevance') or {}).get('security_files', [])
    pr_number = event['pull_request']['number']
    marker = _make_marker(pr_number)

    comment = "## 🛡️ VibeGuard Security Review\n\n"
    comment += "⚠️ **분석이 부분적으로 완료되었습니다.**\n\n"
    comment += "보안 관련 변경이 감지되었으나, AI 분석과 Context 수집에 실패했습니다.\n\n"
    comment += "**감지된 보안 관련 파일:**\n"
    for f in security_files[:5]:
        reasons = ', '.join(f.get('reasons', [])[:2])
        comment += f"- `{f['filename']}` — {reasons}\n"
    comment += "\n수동 보안 검토를 권장합니다.\n"

    return {
        **event,
        'final_result': {
            'risk_score': 50,
            'risk_level': 'MEDIUM',
            'review_action': determine_review_action(50, 'MEDIUM'),
            'findings': [],
            'evidence': [],
            'dismissed_candidates': [],
            'additional_concerns': [],
            'comment_body': f"{marker}\n{comment}",
            'comment_marker': marker,
            'analysis_mode': 'minimal',
        },
    }


def lambda_handler(event, context):
    has_bedrock = 'bedrock_review' in event and 'bedrock_error' not in event

    if has_bedrock:
        return build_full_result(event)
    elif event.get('regression_candidates'):
        return build_degraded_result(event)
    else:
        return build_minimal_result(event)
