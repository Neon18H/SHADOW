# SHADOW SOAR

Plataforma SOAR centralizada con Django 5.x + DRF + Bootstrap 5 (solo layout) para integrar alertas y respuestas con Wazuh SIEM/EDR.

## Requisitos

- Python 3.11+
- SQLite (dev por defecto)

## Instalación rápida

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## Variables de entorno

```bash
DJANGO_SECRET_KEY=change-me
DJANGO_DEBUG=true
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
SOAR_WEBHOOK_TOKEN=token-seguro

WAZUH_API_URL=https://wazuh.example:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=secret
WAZUH_API_TOKEN=
WAZUH_VERIFY_TLS=true

INCIDENT_CORRELATION_WINDOW_MINUTES=30
CASE_SLA_HOURS=24
```

> Para producción, reemplaza SQLite por PostgreSQL usando la configuración estándar de Django (`DATABASES`) sin SQL crudo.

## Webhook de Wazuh

Endpoint:

```
POST /api/integrations/wazuh/alerts
X-SOAR-TOKEN: <token>
```

Ejemplo de payload:

```json
{
  "rule": {"id": "1001", "level": 12, "description": "SSH brute force"},
  "agent": {"id": "001", "name": "host1", "ip": "10.0.0.1"},
  "manager": {"name": "wazuh-manager"},
  "timestamp": "2024-01-01T00:00:00Z",
  "full_log": "..."
}
```

## SOAR Enterprise

### Case Management

- **Case** con SLA automático, asignación y estados.
- **Tasks**, **Observables**, **Timeline** y **Evidence** asociados al caso.

### Correlation & Incidents

- Correlación por **agent + rule + time window + attacker IP**.
- `INCIDENT_CORRELATION_WINDOW_MINUTES` controla el rango temporal de agrupación.

### Playbooks profesionales

- **PlaybookVersion** con snapshot, diff y rollback.
- **Dry-run real** para previsualizar pasos antes de ejecutar.
- **Aprobaciones** (requires_approval + two-person rule en activos críticos).

### RBAC fino

- Roles con permisos por tipo de acción (`action_type`).
- Límite por criticidad (`max_criticality`).
- Asignaciones por usuario (`RBACAssignment`).

### Métricas y performance

- **MTTA/MTTR** automáticos.
- SLA por caso.
- Panel de performance por analista.

## Activación de approvals y RBAC

1. Crear roles y permisos en Django Admin:
   - `RBACRole`: SOC-Tier1, SOC-Tier2, etc.
   - `RBACPermission`: `action_type` = `wazuh_active_response`/`http_api`/`notify`, `max_criticality` = low/medium/high/critical.
   - `RBACAssignment`: asigna roles a usuarios.
2. En acciones de playbook, define en `config`:

```json
{
  "asset_criticality": "critical",
  "command": "isolate_endpoint"
}
```

3. Habilita `two_person_on_critical` en el playbook para two-person rule.

## UI Enterprise SOC

- Theme dark propio tipo Rapid7.
- Sidebar sticky con estado de integraciones.
- Dashboard con funnel 3D CSS/JS, glassmorphism y auto-refresh opcional.
- Evidence drawer (raw JSON, timeline, steps).
- Skeleton loaders para microinteracciones.

## Tests

```bash
python manage.py test
```

## Notas de seguridad

- Webhook protegido con `X-SOAR-TOKEN`.
- Rate limit básico en middleware para el webhook.
- Auditoría append-only para acciones críticas.
- Logs estructurados configurados en `settings.py`.
