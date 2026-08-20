import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info(json.dumps({
        'message': 'Semgrep scan skipped (stub)',
        'repository': event.get('repository', {}).get('full_name', ''),
        'pr_number': event.get('pull_request', {}).get('number'),
    }))

    return {
        'semgrep_results': {
            'findings': [],
            'scan_status': 'skipped',
            'rules_applied': 0,
        }
    }
