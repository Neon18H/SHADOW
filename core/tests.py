from unittest.mock import patch
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .models import Alert, Playbook, PlaybookAction
from .services import PlaybookEngine


class WebhookIngestTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.payload = {
            'rule': {'id': '1001', 'level': 10, 'description': 'Test rule'},
            'agent': {'id': '001', 'name': 'host1', 'ip': '10.0.0.1'},
            'manager': {'name': 'wazuh-manager'},
            'timestamp': '2024-01-01T00:00:00Z',
            'full_log': 'raw',
        }

    @override_settings(SOAR_WEBHOOK_TOKEN='test-token')
    def test_webhook_ingest_creates_alert(self):
        response = self.client.post(
            '/api/integrations/wazuh/alerts',
            data=self.payload,
            format='json',
            HTTP_X_SOAR_TOKEN='test-token',
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Alert.objects.count(), 1)

    @override_settings(SOAR_WEBHOOK_TOKEN='test-token')
    def test_webhook_deduplicates_by_fingerprint(self):
        self.client.post(
            '/api/integrations/wazuh/alerts',
            data=self.payload,
            format='json',
            HTTP_X_SOAR_TOKEN='test-token',
        )
        self.client.post(
            '/api/integrations/wazuh/alerts',
            data=self.payload,
            format='json',
            HTTP_X_SOAR_TOKEN='test-token',
        )
        alert = Alert.objects.first()
        self.assertEqual(Alert.objects.count(), 1)
        self.assertEqual(alert.occurrences, 2)


class PlaybookExecutionTests(TestCase):
    def setUp(self):
        self.alert = Alert.objects.create(
            source='wazuh',
            severity='high',
            status='new',
            title='Alert',
            description='desc',
            rule_id='1002',
            rule_level=10,
            agent_id='001',
            agent_name='host1',
            agent_ip='10.0.0.1',
            raw_payload={},
            fingerprint='abc',
        )
        self.playbook = Playbook.objects.create(
            name='Test PB',
            description='desc',
            enabled=True,
            match_types=['1002'],
            min_severity='low',
            mode='auto',
        )
        PlaybookAction.objects.create(
            playbook=self.playbook,
            type='wazuh_active_response',
            order=1,
            config={'command': 'block_ip', 'arguments': ['{ip}']},
        )

    @patch('core.services.WazuhClient.active_response')
    def test_playbook_execute(self, mock_response):
        mock_response.return_value = {'result': 'ok'}
        engine = PlaybookEngine()
        execution = engine.execute(self.alert, self.playbook, user=None)
        self.assertEqual(execution.status, 'success')
        self.assertEqual(execution.steps.count(), 1)
