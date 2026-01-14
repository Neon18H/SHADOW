import json
import logging
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db.models import Count, Avg, F
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .forms import PlaybookForm, PlaybookActionFormSet
from .models import Alert, Playbook, Execution, AuditLog, IntegrationStatus
from .serializers import WazuhAlertSerializer
from .services import PlaybookEngine, WazuhClient
from .utils import map_severity, compute_fingerprint, now

logger = logging.getLogger(__name__)


def _audit(request, action, obj, before=None, after=None):
    AuditLog.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        action=action,
        object_type=obj.__class__.__name__,
        object_id=str(obj.pk),
        before=before,
        after=after,
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
    )


@login_required
def dashboard(request):
    alerts_today = Alert.objects.filter(first_seen__date=timezone.now().date()).count()
    severity_counts = Alert.objects.values('severity').annotate(total=Count('id'))
    failed_execs = Execution.objects.filter(status='failed').count()
    mttr = Execution.objects.filter(status='success').aggregate(avg=Avg(F('finished_at') - F('started_at')))
    latest_alerts = Alert.objects.all()[:10]

    severity_map = {item['severity']: item['total'] for item in severity_counts}
    context = {
        'alerts_today': alerts_today,
        'severity_counts': severity_map,
        'failed_execs': failed_execs,
        'mttr': mttr['avg'],
        'latest_alerts': latest_alerts,
    }
    return render(request, 'core/dashboard.html', context)


@login_required
def alerts_list(request):
    alerts = Alert.objects.all()
    severity = request.GET.get('severity')
    status_filter = request.GET.get('status')
    agent = request.GET.get('agent')
    rule = request.GET.get('rule')
    date_from = request.GET.get('from')
    date_to = request.GET.get('to')

    if severity:
        alerts = alerts.filter(severity=severity)
    if status_filter:
        alerts = alerts.filter(status=status_filter)
    if agent:
        alerts = alerts.filter(agent_name__icontains=agent)
    if rule:
        alerts = alerts.filter(rule_id__icontains=rule)
    if date_from:
        alerts = alerts.filter(first_seen__date__gte=date_from)
    if date_to:
        alerts = alerts.filter(first_seen__date__lte=date_to)

    return render(request, 'core/alerts_list.html', {'alerts': alerts})


@login_required
def alert_detail(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id)
    engine = PlaybookEngine()
    playbooks = engine.applicable_playbooks(alert)
    return render(request, 'core/alert_detail.html', {'alert': alert, 'playbooks': playbooks})


@login_required
def playbooks_list(request):
    playbooks = Playbook.objects.all()
    return render(request, 'core/playbooks_list.html', {'playbooks': playbooks})


@login_required
@permission_required('core.add_playbook', raise_exception=True)
def playbook_create(request):
    if request.method == 'POST':
        form = PlaybookForm(request.POST)
        formset = PlaybookActionFormSet(request.POST)
        if form.is_valid() and formset.is_valid():
            playbook = form.save()
            formset.instance = playbook
            formset.save()
            _audit(request, 'playbook.create', playbook, after={'name': playbook.name})
            messages.success(request, 'Playbook creado')
            return redirect('playbooks_list')
    else:
        form = PlaybookForm()
        formset = PlaybookActionFormSet()
    return render(request, 'core/playbook_form.html', {'form': form, 'formset': formset})


@login_required
@permission_required('core.change_playbook', raise_exception=True)
def playbook_edit(request, playbook_id):
    playbook = get_object_or_404(Playbook, pk=playbook_id)
    before = {'name': playbook.name, 'enabled': playbook.enabled}
    if request.method == 'POST':
        form = PlaybookForm(request.POST, instance=playbook)
        formset = PlaybookActionFormSet(request.POST, instance=playbook)
        if form.is_valid() and formset.is_valid():
            playbook = form.save()
            formset.save()
            _audit(request, 'playbook.update', playbook, before=before, after={'name': playbook.name})
            messages.success(request, 'Playbook actualizado')
            return redirect('playbooks_list')
    else:
        form = PlaybookForm(instance=playbook)
        formset = PlaybookActionFormSet(instance=playbook)
    return render(request, 'core/playbook_form.html', {'form': form, 'formset': formset, 'playbook': playbook})


@login_required
def executions_list(request):
    executions = Execution.objects.select_related('alert', 'playbook')
    return render(request, 'core/executions_list.html', {'executions': executions})


@login_required
def execution_detail(request, execution_id):
    execution = get_object_or_404(Execution, pk=execution_id)
    return render(request, 'core/execution_detail.html', {'execution': execution})


@login_required
def audit_list(request):
    logs = AuditLog.objects.all()[:200]
    return render(request, 'core/audit_list.html', {'logs': logs})


@login_required
def integrations_view(request):
    status_obj, _ = IntegrationStatus.objects.get_or_create(name='wazuh')
    context = {
        'wazuh_url': settings.WAZUH_API_URL,
        'wazuh_user': settings.WAZUH_API_USER,
        'verify_tls': settings.WAZUH_VERIFY_TLS,
        'status': status_obj,
    }
    return render(request, 'core/integrations.html', context)


class WazuhWebhookView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        token = request.headers.get('X-SOAR-TOKEN')
        if token != settings.SOAR_WEBHOOK_TOKEN:
            return Response({'detail': 'unauthorized'}, status=status.HTTP_403_FORBIDDEN)

        serializer = WazuhAlertSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        rule = data.get('rule', {})
        agent = data.get('agent', {})
        manager = data.get('manager', {})

        normalized = {
            'rule_id': str(rule.get('id', '')),
            'rule_level': int(rule.get('level', 0)),
            'rule_description': rule.get('description', ''),
            'agent_id': str(agent.get('id', '')),
            'agent_name': agent.get('name', ''),
            'agent_ip': agent.get('ip'),
            'manager_name': manager.get('name', ''),
        }
        fingerprint = compute_fingerprint(normalized)
        severity = map_severity(normalized['rule_level'])
        timestamp_raw = data.get('timestamp')
        timestamp = parse_datetime(timestamp_raw) if timestamp_raw else None
        title = normalized['rule_description'] or f"Wazuh rule {normalized['rule_id']}"

        alert, created = Alert.objects.get_or_create(
            fingerprint=fingerprint,
            defaults={
                'source': 'wazuh',
                'severity': severity,
                'status': 'new',
                'title': title,
                'description': normalized['rule_description'],
                'rule_id': normalized['rule_id'],
                'rule_level': normalized['rule_level'],
                'agent_id': normalized['agent_id'],
                'agent_name': normalized['agent_name'],
                'agent_ip': normalized['agent_ip'],
                'manager_name': normalized['manager_name'],
                'timestamp': timestamp,
                'raw_payload': request.data,
                'first_seen': now(),
                'last_seen': now(),
            },
        )
        if not created:
            alert.occurrences += 1
            alert.last_seen = now()
            alert.raw_payload = request.data
            alert.save(update_fields=['occurrences', 'last_seen', 'raw_payload'])

        logger.info('alert ingested %s', alert.id)
        return Response({'id': alert.id, 'created': created}, status=status.HTTP_201_CREATED)


class PlaybookSimulateView(APIView):
    def post(self, request, alert_id):
        alert = get_object_or_404(Alert, pk=alert_id)
        engine = PlaybookEngine()
        simulation = engine.simulate(alert)
        payload = [
            {
                'playbook': item['playbook'].name,
                'mode': item['playbook'].mode,
                'actions': [action.type for action in item['actions']],
            }
            for item in simulation
        ]
        return Response({'results': payload})


class PlaybookExecuteView(APIView):
    def post(self, request, alert_id, playbook_id):
        alert = get_object_or_404(Alert, pk=alert_id)
        playbook = get_object_or_404(Playbook, pk=playbook_id)
        engine = PlaybookEngine()
        execution = engine.execute(alert, playbook, request.user)
        _audit(request, 'playbook.execute', execution, after={'status': execution.status})
        return Response({'execution_id': execution.id, 'status': execution.status})


class PlaybookApproveView(APIView):
    def post(self, request, execution_id):
        execution = get_object_or_404(Execution, pk=execution_id)
        engine = PlaybookEngine()
        execution = engine.approve(execution, request.user)
        _audit(request, 'playbook.approve', execution, after={'status': execution.status})
        return Response({'execution_id': execution.id, 'status': execution.status})


class ExecutionStatusView(APIView):
    def get(self, request, execution_id):
        execution = get_object_or_404(Execution, pk=execution_id)
        return Response({
            'id': execution.id,
            'status': execution.status,
            'finished_at': execution.finished_at,
            'steps': [
                {
                    'id': step.id,
                    'status': step.status,
                    'action_type': step.action_type,
                    'output': step.output,
                    'error': step.error,
                }
                for step in execution.steps.all()
            ],
        })


class WazuhTestConnectionView(APIView):
    def post(self, request):
        status_obj, _ = IntegrationStatus.objects.get_or_create(name='wazuh')
        try:
            client = WazuhClient()
            response = client.test_connection()
            status_obj.last_status = 'ok'
            status_obj.details = json.dumps(response)
            status_obj.last_tested = timezone.now()
            status_obj.save()
            return Response({'status': 'ok'})
        except Exception as exc:  # noqa: BLE001
            status_obj.last_status = 'error'
            status_obj.details = str(exc)
            status_obj.last_tested = timezone.now()
            status_obj.save()
            return Response({'status': 'error', 'detail': str(exc)}, status=status.HTTP_502_BAD_GATEWAY)
