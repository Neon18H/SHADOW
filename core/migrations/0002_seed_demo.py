from django.db import migrations


def seed_playbooks(apps, schema_editor):
    Playbook = apps.get_model('core', 'Playbook')
    PlaybookAction = apps.get_model('core', 'PlaybookAction')

    ransomware, created = Playbook.objects.get_or_create(
        name='Ransomware suspected (critical)',
        defaults={
            'description': 'Respuesta crítica con aislamiento y notificación.',
            'enabled': True,
            'match_types': ['ransomware', 'malware'],
            'min_severity': 'critical',
            'mode': 'requires_approval',
        },
    )
    if created:
        PlaybookAction.objects.create(
            playbook=ransomware,
            type='notify',
            order=1,
            config={'email_to': 'soc@example.com', 'message': 'Ransomware suspected on {agent}'}
        )
        PlaybookAction.objects.create(
            playbook=ransomware,
            type='wazuh_active_response',
            order=2,
            config={'command': 'isolate_endpoint', 'arguments': []},
        )
        PlaybookAction.objects.create(
            playbook=ransomware,
            type='wazuh_active_response',
            order=3,
            config={'command': 'kill_process', 'arguments': ['placeholder']},
        )

    brute_force, created = Playbook.objects.get_or_create(
        name='Brute force SSH (high)',
        defaults={
            'description': 'Bloqueo de IP y notificación automática.',
            'enabled': True,
            'match_types': ['ssh', 'bruteforce'],
            'min_severity': 'high',
            'mode': 'auto',
        },
    )
    if created:
        PlaybookAction.objects.create(
            playbook=brute_force,
            type='wazuh_active_response',
            order=1,
            config={'command': 'block_ip', 'arguments': ['{ip}']},
        )
        PlaybookAction.objects.create(
            playbook=brute_force,
            type='notify',
            order=2,
            config={'email_to': 'soc@example.com', 'message': 'SSH brute force on {agent}'}
        )


def unseed(apps, schema_editor):
    Playbook = apps.get_model('core', 'Playbook')
    Playbook.objects.filter(name__in=['Ransomware suspected (critical)', 'Brute force SSH (high)']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_playbooks, reverse_code=unseed),
    ]
