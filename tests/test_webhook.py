import hashlib
import hmac
import json
import unittest


# ── Inline copy of the signature logic for isolated unit testing ──────────────

def verify_signature(payload_body: str, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode('utf-8'),
        payload_body.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def make_signature(payload: str, secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


ALLOWED_ACTIONS = {'opened', 'synchronize', 'reopened'}


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestSignatureVerification(unittest.TestCase):
    def test_valid_signature(self):
        secret = 'my-webhook-secret'
        payload = json.dumps({'action': 'opened'})
        sig = make_signature(payload, secret)
        self.assertTrue(verify_signature(payload, sig, secret))

    def test_invalid_signature_string(self):
        self.assertFalse(verify_signature('{"action":"opened"}', 'sha256=invalid', 'secret'))

    def test_wrong_secret(self):
        payload = json.dumps({'action': 'opened'})
        sig = make_signature(payload, 'secret-a')
        self.assertFalse(verify_signature(payload, sig, 'secret-b'))

    def test_tampered_payload(self):
        secret = 'my-webhook-secret'
        original = json.dumps({'action': 'opened'})
        sig = make_signature(original, secret)
        tampered = json.dumps({'action': 'opened', 'extra': 'injected'})
        self.assertFalse(verify_signature(tampered, sig, secret))

    def test_empty_signature(self):
        self.assertFalse(verify_signature('payload', '', 'secret'))


class TestEventFiltering(unittest.TestCase):
    def test_allowed_actions_pass(self):
        for action in ('opened', 'synchronize', 'reopened'):
            self.assertIn(action, ALLOWED_ACTIONS)

    def test_ignored_actions_blocked(self):
        for action in ('edited', 'closed', 'merged', 'labeled', 'unlabeled', 'assigned'):
            self.assertNotIn(action, ALLOWED_ACTIONS)


class TestPayloadParsing(unittest.TestCase):
    def _make_payload(self, action: str = 'opened') -> dict:
        return {
            'action': action,
            'installation': {'id': 12345678},
            'repository': {
                'full_name': 'owner/repo',
                'name': 'repo',
                'owner': {'login': 'owner'},
            },
            'pull_request': {
                'number': 42,
                'title': 'Add new feature',
                'updated_at': '2026-08-20T00:00:00Z',
                'head': {'sha': 'abc1234567890', 'ref': 'feature-branch'},
                'base': {'ref': 'main'},
            },
        }

    def test_step_functions_input_shape(self):
        payload = self._make_payload('opened')
        pr = payload['pull_request']
        repo = payload['repository']

        sf_input = {
            'repository': {
                'owner': repo['owner']['login'],
                'name': repo['name'],
                'full_name': repo['full_name'],
            },
            'pull_request': {
                'number': pr['number'],
                'title': pr['title'],
                'head_sha': pr['head']['sha'],
                'base_branch': pr['base']['ref'],
                'head_branch': pr['head']['ref'],
            },
            'installation_id': str(payload['installation']['id']),
            'event_action': payload['action'],
            'triggered_at': pr['updated_at'],
        }

        self.assertEqual(sf_input['repository']['full_name'], 'owner/repo')
        self.assertEqual(sf_input['pull_request']['number'], 42)
        self.assertEqual(sf_input['pull_request']['head_sha'], 'abc1234567890')
        self.assertEqual(sf_input['installation_id'], '12345678')


if __name__ == '__main__':
    unittest.main()
