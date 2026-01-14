from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.CharField(default='wazuh', max_length=50)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], max_length=20)),
                ('status', models.CharField(choices=[('new', 'New'), ('in_progress', 'In Progress'), ('resolved', 'Resolved'), ('false_positive', 'False Positive')], default='new', max_length=20)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('rule_id', models.CharField(blank=True, max_length=120)),
                ('rule_level', models.IntegerField(blank=True, null=True)),
                ('agent_id', models.CharField(blank=True, max_length=120)),
                ('agent_name', models.CharField(blank=True, max_length=255)),
                ('agent_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('manager_name', models.CharField(blank=True, max_length=255)),
                ('timestamp', models.DateTimeField(blank=True, null=True)),
                ('raw_payload', models.JSONField()),
                ('fingerprint', models.CharField(db_index=True, max_length=64, unique=True)),
                ('occurrences', models.PositiveIntegerField(default=1)),
                ('first_seen', models.DateTimeField(default=django.utils.timezone.now)),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={'ordering': ['-last_seen']},
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=255)),
                ('object_type', models.CharField(max_length=120)),
                ('object_id', models.CharField(max_length=120)),
                ('before', models.JSONField(blank=True, null=True)),
                ('after', models.JSONField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-timestamp']},
        ),
        migrations.CreateModel(
            name='IntegrationStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('last_heartbeat', models.DateTimeField(blank=True, null=True)),
                ('last_tested', models.DateTimeField(blank=True, null=True)),
                ('last_status', models.CharField(blank=True, max_length=50)),
                ('details', models.TextField(blank=True)),
            ],
            options={'ordering': ['name']},
        ),
        migrations.CreateModel(
            name='Playbook',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('enabled', models.BooleanField(default=True)),
                ('match_types', models.JSONField(blank=True, default=list)),
                ('min_severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='low', max_length=20)),
                ('mode', models.CharField(choices=[('auto', 'Auto'), ('requires_approval', 'Requires Approval')], default='auto', max_length=50)),
            ],
            options={'ordering': ['name']},
        ),
        migrations.CreateModel(
            name='PlaybookAction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('wazuh_active_response', 'Wazuh Active Response'), ('http_api', 'HTTP API'), ('script', 'Script'), ('notify', 'Notify'), ('ticket_stub', 'Ticket Stub')], max_length=50)),
                ('config', models.JSONField(blank=True, default=dict)),
                ('order', models.PositiveIntegerField(default=1)),
                ('playbook', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='actions', to='core.playbook')),
            ],
            options={'ordering': ['order']},
        ),
        migrations.CreateModel(
            name='Execution',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('started_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('running', 'Running'), ('success', 'Success'), ('failed', 'Failed'), ('partial', 'Partial'), ('approved_required', 'Approved Required')], default='running', max_length=30)),
                ('alert', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='executions', to='core.alert')),
                ('approved_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_executions', to=settings.AUTH_USER_MODEL)),
                ('playbook', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='executions', to='core.playbook')),
                ('requested_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='requested_executions', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-started_at']},
        ),
        migrations.CreateModel(
            name='ExecutionStep',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action_type', models.CharField(max_length=50)),
                ('action_config_snapshot', models.JSONField(default=dict)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('success', 'Success'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('output', models.TextField(blank=True)),
                ('error', models.TextField(blank=True)),
                ('execution', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='steps', to='core.execution')),
            ],
            options={'ordering': ['id']},
        ),
    ]
