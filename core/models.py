from django.conf import settings
from django.db import models
from django.utils import timezone


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

    class Meta:
        ordering = ['-last_seen']

    def __str__(self):
        return f"{self.title} ({self.severity})"


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

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


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
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='running')
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='requested_executions'
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_executions'
    )

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
