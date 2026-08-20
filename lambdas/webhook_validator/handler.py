import base64
import hashlib
import hmac
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

secrets_client = boto3.client('secretsmanager')
sfn_client = boto3.client('stepfunctions')
dynamodb = boto3.resource('dynamodb')

WORKFLOW_ARN = os.environ['WORKFLOW_ARN']
SECRET_NAME = os.environ.get('SECRET_NAME', 'vibe-guard/github-app')
LOCK_TABLE = os.environ.get('LOCK_TABLE', 'vibe-guard-execution-lock')

_secret_cache: dict | None = None


def get_secret(key: str) -> str:
    global _secret_cache
    if _secret_cache is None:
        response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        _secret_cache = json.loads(response['SecretString'])
    return _secret_cache[key]


def verify_signature(payload_body: str, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode('utf-8'),
        payload_body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def cancel_existing_execution(repo_full_name: str, pr_number: int) -> None:
    table = dynamodb.Table(LOCK_TABLE)
    pr_key = f"{repo_full_name}#PR#{pr_number}"

    try:
        response = table.get_item(Key={'pr_key': pr_key})
        item = response.get('Item')
        if not item:
            return

        execution_arn = item.get('execution_arn', '')
        if execution_arn:
            try:
                sfn_client.stop_execution(
                    executionArn=execution_arn,
                    cause='Superseded by newer commit'
                )
                print(f"Stopped execution: {execution_arn}")
            except ClientError as e:
                # Express Workflows cannot be stopped — expected; log and continue
                print(f"Could not stop execution (expected for Express Workflow): {e}")
    except ClientError as e:
        print(f"Error reading lock table: {e}")


def register_execution_lock(
    repo_full_name: str,
    pr_number: int,
    execution_arn: str,
    commit_sha: str,
) -> None:
    table = dynamodb.Table(LOCK_TABLE)
    pr_key = f"{repo_full_name}#PR#{pr_number}"
    ttl = int(time.time()) + 600  # 10 minutes

    table.put_item(Item={
        'pr_key': pr_key,
        'execution_arn': execution_arn,
        'commit_sha': commit_sha,
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'ttl': ttl,
    })


def lambda_handler(event, context):
    # 1. Extract raw body (API Gateway may base64-encode it)
    body = event.get('body', '') or ''
    if event.get('isBase64Encoded', False):
        body = base64.b64decode(body).decode('utf-8')

    # 2. Extract signature header (GitHub sends lowercase key via API Gateway)
    headers = {k.lower(): v for k, v in (event.get('headers') or {}).items()}
    signature = headers.get('x-hub-signature-256', '')

    # 3. Verify HMAC-SHA256 signature
    webhook_secret = get_secret('webhook_secret')
    if not signature or not verify_signature(body, signature, webhook_secret):
        print("Webhook signature verification failed")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Invalid signature'}),
        }

    # 4. Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid JSON'})}

    action = payload.get('action', '')

    # 5. Filter to relevant PR events only
    if action not in ('opened', 'synchronize', 'reopened'):
        print(f"Ignoring event action: {action}")
        return {'statusCode': 200, 'body': json.dumps({'message': f'Ignored: {action}'})}

    # 6. Build Step Functions input
    pr = payload['pull_request']
    repo = payload['repository']
    repo_full_name = repo['full_name']
    pr_number = pr['number']
    commit_sha = pr['head']['sha']

    sf_input = {
        'repository': {
            'owner': repo['owner']['login'],
            'name': repo['name'],
            'full_name': repo_full_name,
        },
        'pull_request': {
            'number': pr_number,
            'title': pr['title'],
            'head_sha': commit_sha,
            'base_branch': pr['base']['ref'],
            'head_branch': pr['head']['ref'],
        },
        'installation_id': str(payload['installation']['id']),
        'event_action': action,
        'triggered_at': pr['updated_at'],
    }

    # 7. Cancel previous execution for this PR (best-effort)
    cancel_existing_execution(repo_full_name, pr_number)

    # 8. Start new Step Functions execution
    execution_name = f"pr-{pr_number}-{commit_sha[:8]}-{int(time.time())}"
    execution = sfn_client.start_execution(
        stateMachineArn=WORKFLOW_ARN,
        name=execution_name,
        input=json.dumps(sf_input),
    )
    execution_arn = execution['executionArn']

    # 9. Register lock
    register_execution_lock(repo_full_name, pr_number, execution_arn, commit_sha)

    print(f"Started execution {execution_arn} for {repo_full_name}#{pr_number}")
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Analysis started', 'executionArn': execution_arn}),
    }
