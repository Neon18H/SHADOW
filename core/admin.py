from django.contrib import admin
from .models import (
    Alert,
    Asset,
    AuditLog,
    Case,
    CaseTask,
    Evidence,
    Execution,
    ExecutionApproval,
    ExecutionStep,
    Incident,
    IntegrationStatus,
    Observable,
    Playbook,
    PlaybookAction,
    PlaybookVersion,
    RBACAssignment,
    RBACPermission,
    RBACRole,
    TimelineEvent,
)


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


@admin.register(PlaybookVersion)
class PlaybookVersionAdmin(admin.ModelAdmin):
    list_display = ('playbook', 'version', 'created_at', 'created_by')


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'severity', 'status', 'alert_count', 'last_seen')


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'severity', 'status', 'assigned_to', 'sla_due_at')


@admin.register(CaseTask)
class CaseTaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'case', 'title', 'status', 'assigned_to')


@admin.register(Observable)
class ObservableAdmin(admin.ModelAdmin):
    list_display = ('id', 'case', 'observable_type', 'value', 'confidence')


@admin.register(TimelineEvent)
class TimelineEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'case', 'event_type', 'timestamp', 'actor')


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('id', 'case', 'title', 'evidence_type', 'collected_at')


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'criticality', 'environment', 'owner')


@admin.register(Execution)
class ExecutionAdmin(admin.ModelAdmin):
    list_display = ('id', 'alert', 'playbook', 'status', 'started_at', 'finished_at')


@admin.register(ExecutionApproval)
class ExecutionApprovalAdmin(admin.ModelAdmin):
    list_display = ('execution', 'approver', 'approved_at')


@admin.register(ExecutionStep)
class ExecutionStepAdmin(admin.ModelAdmin):
    list_display = ('id', 'execution', 'action_type', 'status', 'started_at', 'finished_at')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'actor', 'action', 'object_type', 'object_id')


@admin.register(IntegrationStatus)
class IntegrationStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'last_status', 'last_tested')


@admin.register(RBACRole)
class RBACRoleAdmin(admin.ModelAdmin):
    list_display = ('name',)


@admin.register(RBACPermission)
class RBACPermissionAdmin(admin.ModelAdmin):
    list_display = ('role', 'action_type', 'max_criticality')


@admin.register(RBACAssignment)
class RBACAssignmentAdmin(admin.ModelAdmin):
    list_display = ('user', 'role')
