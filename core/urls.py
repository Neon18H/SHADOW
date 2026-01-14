from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('playbooks/', views.playbooks_list, name='playbooks_list'),
    path('playbooks/new/', views.playbook_create, name='playbook_create'),
    path('playbooks/<int:playbook_id>/', views.playbook_edit, name='playbook_edit'),
    path('executions/', views.executions_list, name='executions_list'),
    path('executions/<int:execution_id>/', views.execution_detail, name='execution_detail'),
    path('audit/', views.audit_list, name='audit_list'),
    path('integrations/', views.integrations_view, name='integrations'),
    path('api/metrics/alerts-over-time', views.alerts_over_time, name='alerts_over_time'),
    path('api/metrics/alerts-by-severity', views.alerts_by_severity, name='alerts_by_severity'),
    path('api/metrics/top-rules', views.top_rules, name='top_rules'),
    path('api/metrics/executions-success-failed', views.executions_success_failed, name='executions_success_failed'),
    path('api/metrics/mttr-trend', views.mttr_trend, name='mttr_trend'),
    path('api/integrations/wazuh/alerts', views.WazuhWebhookView.as_view(), name='wazuh_webhook'),
    path('api/integrations/wazuh/test', views.WazuhTestConnectionView.as_view(), name='wazuh_test'),
    path('api/alerts/<int:alert_id>/simulate', views.PlaybookSimulateView.as_view(), name='playbook_simulate'),
    path('api/alerts/<int:alert_id>/playbooks/<int:playbook_id>/execute', views.PlaybookExecuteView.as_view(), name='playbook_execute'),
    path('api/executions/<int:execution_id>/approve', views.PlaybookApproveView.as_view(), name='playbook_approve'),
    path('api/executions/<int:execution_id>/status', views.ExecutionStatusView.as_view(), name='execution_status'),
]
