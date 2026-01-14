from django.apps import AppConfig
from django.contrib.auth.models import Group, Permission
from django.db.models.signals import post_migrate


ROLE_GROUPS = {
    'SOC_ANALYST': [
        'view_alert', 'change_alert', 'view_execution', 'add_execution', 'view_executionstep',
        'add_executionstep', 'view_playbook',
    ],
    'SOC_LEAD': [
        'view_alert', 'change_alert', 'view_execution', 'add_execution', 'change_execution',
        'view_executionstep', 'add_executionstep', 'view_playbook', 'change_playbook',
        'add_playbook', 'change_playbookaction', 'add_playbookaction',
    ],
    'ADMIN': [
        'view_alert', 'change_alert', 'view_execution', 'add_execution', 'change_execution',
        'view_executionstep', 'add_executionstep', 'view_playbook', 'change_playbook',
        'add_playbook', 'change_playbookaction', 'add_playbookaction', 'view_auditlog',
        'view_integrationstatus',
    ],
    'READ_ONLY': [
        'view_alert', 'view_execution', 'view_executionstep', 'view_playbook', 'view_auditlog',
        'view_integrationstatus',
    ],
}


def ensure_groups(sender, **kwargs):
    for group_name, perms in ROLE_GROUPS.items():
        group, _ = Group.objects.get_or_create(name=group_name)
        permissions = Permission.objects.filter(codename__in=perms)
        group.permissions.set(permissions)


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        post_migrate.connect(ensure_groups, sender=self)
