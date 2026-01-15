from .models import IntegrationStatus


def integration_summary(request):
    statuses = {status.name: status for status in IntegrationStatus.objects.all()}
    return {'integration_statuses': statuses}
