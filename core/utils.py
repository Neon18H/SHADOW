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


def extract_attacker_ip(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get('srcip'),
        payload.get('source_ip'),
        payload.get('src'),
        payload.get('client_ip'),
        payload.get('data', {}).get('srcip') if isinstance(payload.get('data'), dict) else None,
        payload.get('data', {}).get('src') if isinstance(payload.get('data'), dict) else None,
        payload.get('rule', {}).get('srcip') if isinstance(payload.get('rule'), dict) else None,
    ]
    for candidate in candidates:
        if candidate:
            return candidate
    return None


def correlation_key(agent_id: str, rule_id: str, attacker_ip: str | None) -> str:
    return f"{agent_id or 'unknown'}:{rule_id or 'unknown'}:{attacker_ip or 'na'}"
