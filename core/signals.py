from django.apps import apps
from django.db.models.signals import post_migrate
from django.dispatch import receiver


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


@receiver(post_migrate)
def ensure_groups(sender, **kwargs):
    if sender.name != 'core':
        return

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    for group_name, perms in ROLE_GROUPS.items():
        group, _ = Group.objects.get_or_create(name=group_name)
        permissions = Permission.objects.filter(codename__in=perms)
        group.permissions.set(permissions)
