import hashlib
from django.utils import timezone


SEVERITY_MAP = [
    (0, 4, 'low'),
    (5, 9, 'medium'),
    (10, 12, 'high'),
    (13, 100, 'critical'),
]


def map_severity(rule_level: int) -> str:
    for start, end, severity in SEVERITY_MAP:
        if start <= rule_level <= end:
            return severity
    return 'low'


def compute_fingerprint(data: dict) -> str:
    fields = [
        str(data.get('rule_id', '')),
        str(data.get('rule_level', '')),
        str(data.get('rule_description', '')),
        str(data.get('agent_id', '')),
        str(data.get('agent_name', '')),
        str(data.get('agent_ip', '')),
        str(data.get('manager_name', '')),
    ]
    raw = '|'.join(fields).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def now():
    return timezone.now()
