from django.contrib import admin
from .models import Alert, Playbook, PlaybookAction, Execution, ExecutionStep, AuditLog, IntegrationStatus


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('id', 'severity', 'status', 'title', 'agent_name', 'last_seen')
    search_fields = ('title', 'rule_id', 'agent_name')
    list_filter = ('severity', 'status')


class PlaybookActionInline(admin.TabularInline):
    model = PlaybookAction
    extra = 0


@admin.register(Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ('name', 'min_severity', 'mode', 'enabled')
    inlines = [PlaybookActionInline]


@admin.register(Execution)
class ExecutionAdmin(admin.ModelAdmin):
    list_display = ('id', 'alert', 'playbook', 'status', 'started_at', 'finished_at')


@admin.register(ExecutionStep)
class ExecutionStepAdmin(admin.ModelAdmin):
    list_display = ('id', 'execution', 'action_type', 'status', 'started_at', 'finished_at')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'actor', 'action', 'object_type', 'object_id')


@admin.register(IntegrationStatus)
class IntegrationStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'last_status', 'last_tested')
