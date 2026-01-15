from django.conf import settings
from django.db import models
from django.utils import timezone


CRITICALITY_CHOICES = [
    ('low', 'Low'),
    ('medium', 'Medium'),
    ('high', 'High'),
    ('critical', 'Critical'),
]


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('new', 'New'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    source = models.CharField(max_length=50, default='wazuh')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    rule_id = models.CharField(max_length=120, blank=True)
    rule_level = models.IntegerField(null=True, blank=True)
    agent_id = models.CharField(max_length=120, blank=True)
    agent_name = models.CharField(max_length=255, blank=True)
    agent_ip = models.GenericIPAddressField(null=True, blank=True)
    manager_name = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(null=True, blank=True)
    raw_payload = models.JSONField()
    fingerprint = models.CharField(max_length=64, db_index=True, unique=True)
    occurrences = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    incident = models.ForeignKey('Incident', on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return f"{self.title} ({self.severity})"


class Asset(models.Model):
    CRITICALITY_CHOICES = CRITICALITY_CHOICES

    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=120, blank=True)
    criticality = models.CharField(max_length=20, choices=CRITICALITY_CHOICES, default='medium')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    environment = models.CharField(max_length=120, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    tags = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.criticality})"


class Incident(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('triaged', 'Triaged'),
        ('contained', 'Contained'),
        ('closed', 'Closed'),
    ]

    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=Alert.SEVERITY_CHOICES, default='low')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    agent_id = models.CharField(max_length=120, blank=True)
    rule_id = models.CharField(max_length=120, blank=True)
    attacker_ip = models.GenericIPAddressField(null=True, blank=True)
    correlation_key = models.CharField(max_length=255, db_index=True)
    alert_count = models.PositiveIntegerField(default=0)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return self.title


class Case(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('triage', 'Triage'),
        ('investigating', 'Investigating'),
        ('contained', 'Contained'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=Alert.SEVERITY_CHOICES, default='low')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    incident = models.ForeignKey(Incident, on_delete=models.SET_NULL, null=True, blank=True, related_name='cases')
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_cases'
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_cases'
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    sla_due_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if self.sla_due_at is None:
            sla_hours = getattr(settings, 'CASE_SLA_HOURS', 24)
            self.sla_due_at = (self.created_at or timezone.now()) + timezone.timedelta(hours=sla_hours)
        super().save(*args, **kwargs)


class CaseTask(models.Model):
    STATUS_CHOICES = [
        ('todo', 'To Do'),
        ('in_progress', 'In Progress'),
        ('blocked', 'Blocked'),
        ('done', 'Done'),
    ]

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='todo')
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='case_tasks'
    )
    due_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-id']


class Observable(models.Model):
    TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('hash', 'Hash'),
        ('user', 'User'),
        ('process', 'Process'),
        ('host', 'Host'),
    ]

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='observables')
    observable_type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    value = models.CharField(max_length=255)
    tags = models.JSONField(default=list, blank=True)
    confidence = models.PositiveIntegerField(default=50)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['observable_type', 'value']

    def __str__(self):
        return f"{self.observable_type}: {self.value}"


class TimelineEvent(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='timeline')
    timestamp = models.DateTimeField(default=timezone.now)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='timeline_events'
    )
    event_type = models.CharField(max_length=120, blank=True)
    description = models.TextField()

    class Meta:
        ordering = ['-timestamp']


class Evidence(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='evidence')
    title = models.CharField(max_length=255)
    evidence_type = models.CharField(max_length=120, blank=True)
    data = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    collected_at = models.DateTimeField(default=timezone.now)
    collected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_entries'
    )

    class Meta:
        ordering = ['-collected_at']


class Playbook(models.Model):
    MODE_CHOICES = [
        ('auto', 'Auto'),
        ('requires_approval', 'Requires Approval'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    match_types = models.JSONField(default=list, blank=True)
    min_severity = models.CharField(max_length=20, choices=Alert.SEVERITY_CHOICES, default='low')
    mode = models.CharField(max_length=50, choices=MODE_CHOICES, default='auto')
    two_person_on_critical = models.BooleanField(default=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class PlaybookVersion(models.Model):
    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='versions')
    version = models.PositiveIntegerField()
    change_summary = models.CharField(max_length=255, blank=True)
    definition_snapshot = models.JSONField(default=dict)
    diff = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='playbook_versions'
    )
    created_at = models.DateTimeField(default=timezone.now)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_playbook_versions'
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    rollback_from = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-version']
        unique_together = [('playbook', 'version')]

    def __str__(self):
        return f"{self.playbook.name} v{self.version}"


class PlaybookAction(models.Model):
    ACTION_CHOICES = [
        ('wazuh_active_response', 'Wazuh Active Response'),
        ('http_api', 'HTTP API'),
        ('script', 'Script'),
        ('notify', 'Notify'),
        ('ticket_stub', 'Ticket Stub'),
    ]

    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='actions')
    type = models.CharField(max_length=50, choices=ACTION_CHOICES)
    config = models.JSONField(default=dict, blank=True)
    order = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['order']

    def __str__(self):
        return f"{self.playbook.name} - {self.type}"


class Execution(models.Model):
    STATUS_CHOICES = [
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('partial', 'Partial'),
        ('approved_required', 'Approved Required'),
    ]

    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='executions')
    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name='executions')
    playbook_version = models.ForeignKey(
        PlaybookVersion, on_delete=models.SET_NULL, null=True, blank=True, related_name='executions'
    )
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='running')
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='requested_executions'
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_executions'
    )
    dry_run = models.BooleanField(default=False)
    required_approvals = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-started_at']


class ExecutionStep(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    execution = models.ForeignKey(Execution, on_delete=models.CASCADE, related_name='steps')
    action_type = models.CharField(max_length=50)
    action_config_snapshot = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    output = models.TextField(blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ['id']


class ExecutionApproval(models.Model):
    execution = models.ForeignKey(Execution, on_delete=models.CASCADE, related_name='approvals')
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='execution_approvals'
    )
    approved_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [('execution', 'approver')]


class AuditLog(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=255)
    object_type = models.CharField(max_length=120)
    object_id = models.CharField(max_length=120)
    before = models.JSONField(null=True, blank=True)
    after = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError('AuditLog entries are append-only.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError('AuditLog entries cannot be deleted.')


class RBACRole(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class RBACPermission(models.Model):
    role = models.ForeignKey(RBACRole, on_delete=models.CASCADE, related_name='permissions')
    action_type = models.CharField(max_length=50)
    max_criticality = models.CharField(max_length=20, choices=CRITICALITY_CHOICES, default='medium')

    class Meta:
        unique_together = [('role', 'action_type', 'max_criticality')]


class RBACAssignment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='rbac_assignments')
    role = models.ForeignKey(RBACRole, on_delete=models.CASCADE, related_name='assignments')

    class Meta:
        unique_together = [('user', 'role')]


class IntegrationStatus(models.Model):
    name = models.CharField(max_length=100, unique=True)
    api_url = models.URLField(blank=True)
    verify_tls = models.BooleanField(default=True)
    timeout = models.PositiveIntegerField(default=10)
    enabled = models.BooleanField(default=True)
    tags = models.JSONField(default=list, blank=True)
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    last_tested = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=50, blank=True)
    details = models.TextField(blank=True)
    last_logs = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
