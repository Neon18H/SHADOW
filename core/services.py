import logging
import requests
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail

from .models import Execution, ExecutionStep, Playbook, IntegrationStatus

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}


class WazuhClient:
    def __init__(self):
        status = IntegrationStatus.objects.filter(name='wazuh').first()
        configured_url = status.api_url if status and status.api_url else settings.WAZUH_API_URL
        self.base_url = configured_url.rstrip('/') if configured_url else ''
        self.user = settings.WAZUH_API_USER
        self.password = settings.WAZUH_API_PASSWORD
        self.token = settings.WAZUH_API_TOKEN
        self.verify_tls = status.verify_tls if status else settings.WAZUH_VERIFY_TLS
        self.timeout = status.timeout if status else 10
        self.enabled = status.enabled if status else True

    def _headers(self):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def _auth(self):
        if self.token:
            return None
        if self.user and self.password:
            return (self.user, self.password)
        return None

    def request(self, method, path, **kwargs):
        if not self.enabled:
            raise ValueError('Wazuh integration is disabled')
        if not self.base_url:
            raise ValueError('WAZUH_API_URL is not configured')
        url = f"{self.base_url}{path}"
        timeout = kwargs.pop('timeout', self.timeout)
        response = requests.request(
            method,
            url,
            headers=self._headers(),
            auth=self._auth(),
            timeout=timeout,
            verify=self.verify_tls,
            **kwargs,
        )
        response.raise_for_status()
        return response.json()

    def test_connection(self):
        return self.request('GET', '/manager/info')

    def get_agent(self, agent_id=None, agent_name=None):
        if agent_id:
            return self.request('GET', f'/agents/{agent_id}')
        if agent_name:
            return self.request('GET', f'/agents', params={'name': agent_name})
        raise ValueError('agent_id or agent_name is required')

    def active_response(self, agent_id, command, arguments=None):
        payload = {
            'command': command,
            'custom': True,
            'arguments': arguments or [],
            'agents_list': [agent_id],
        }
        return self.request('POST', '/active-response', json=payload)


class PlaybookEngine:
    def __init__(self, wazuh_client=None):
        self.wazuh_client = wazuh_client or WazuhClient()

    def applicable_playbooks(self, alert):
        playbooks = Playbook.objects.filter(enabled=True)
        applicable = []
        for playbook in playbooks:
            if SEVERITY_RANK[alert.severity] < SEVERITY_RANK[playbook.min_severity]:
                continue
            if playbook.match_types:
                if not any(
                    str(match).lower() in (alert.rule_id.lower(), alert.description.lower(), alert.title.lower())
                    for match in playbook.match_types
                ):
                    continue
            applicable.append(playbook)
        return applicable

    def simulate(self, alert):
        playbooks = self.applicable_playbooks(alert)
        simulation = []
        for playbook in playbooks:
            simulation.append({
                'playbook': playbook,
                'actions': list(playbook.actions.all()),
            })
        return simulation

    def execute(self, alert, playbook, user):
        execution = Execution.objects.create(
            alert=alert,
            playbook=playbook,
            status='running',
            requested_by=user,
        )
        if playbook.mode == 'requires_approval':
            execution.status = 'approved_required'
            execution.save(update_fields=['status'])
            return execution
        return self._run_execution(execution)

    def approve(self, execution, user):
        if execution.status != 'approved_required':
            return execution
        execution.approved_by = user
        execution.status = 'running'
        execution.save(update_fields=['approved_by', 'status'])
        return self._run_execution(execution)

    def _run_execution(self, execution):
        steps = []
        failed = False
        for action in execution.playbook.actions.all():
            step = ExecutionStep.objects.create(
                execution=execution,
                action_type=action.type,
                action_config_snapshot=action.config,
                status='running',
                started_at=timezone.now(),
            )
            try:
                output = self._execute_action(action, execution.alert)
                step.status = 'success'
                step.output = output
            except Exception as exc:  # noqa: BLE001
                step.status = 'failed'
                step.error = str(exc)
                failed = True
                logger.exception('Playbook action failed')
            step.finished_at = timezone.now()
            step.save()
            steps.append(step)
            if failed:
                break
        execution.finished_at = timezone.now()
        if failed:
            execution.status = 'failed'
        else:
            execution.status = 'success'
        execution.save(update_fields=['finished_at', 'status'])
        return execution

    def _execute_action(self, action, alert):
        if action.type == 'wazuh_active_response':
            command = action.config.get('command')
            if not command:
                raise ValueError('Wazuh action missing command')
            agent_id = action.config.get('agent_id') or alert.agent_id
            if not agent_id:
                raise ValueError('No agent_id available for Wazuh action')
            arguments = action.config.get('arguments') or []
            arguments = [self._format_value(arg, alert) for arg in arguments]
            result = self.wazuh_client.active_response(agent_id, command, arguments)
            return str(result)
        if action.type == 'http_api':
            method = action.config.get('method', 'POST')
            url = action.config.get('url')
            if not url:
                raise ValueError('HTTP API action missing url')
            headers = action.config.get('headers', {})
            body = action.config.get('body')
            response = requests.request(method, url, headers=headers, json=body, timeout=10)
            response.raise_for_status()
            return response.text
        if action.type == 'notify':
            message = action.config.get('message', 'SOAR notification')
            message = self._format_value(message, alert)
            email_to = action.config.get('email_to')
            webhook_url = action.config.get('webhook_url')
            outputs = []
            if email_to:
                send_mail(
                    subject=action.config.get('subject', f'SOAR Alert {alert.id}'),
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email_to],
                )
                outputs.append('email sent')
            if webhook_url:
                response = requests.post(webhook_url, json={'message': message}, timeout=10)
                response.raise_for_status()
                outputs.append('webhook sent')
            if not outputs:
                outputs.append('notification skipped')
            return ', '.join(outputs)
        if action.type == 'ticket_stub':
            return 'ticket stub created'
        if action.type == 'script':
            return 'script execution placeholder'
        raise ValueError(f'Unsupported action type: {action.type}')

    def _format_value(self, value, alert):
        if not isinstance(value, str):
            return value
        return value.format(
            alert_id=alert.id,
            severity=alert.severity,
            title=alert.title,
            agent=alert.agent_name,
            ip=alert.agent_ip,
        )
