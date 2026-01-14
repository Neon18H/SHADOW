# SHADOW SOAR

Plataforma SOAR centralizada con Django 5.x + DRF + Bootstrap 5 para integrar alertas y respuestas con Wazuh SIEM/EDR.

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

## Playbooks

Se cargan playbooks demo con migraciones:

- **Ransomware suspected (critical)** (requiere aprobación): notificación + active response.
- **Brute force SSH (high)** (auto): bloquea IP + notifica.

## Active response en agentes (conceptual)

Configura scripts de `active-response` en Wazuh Agents que acepten `command` y argumentos, p. ej.:

- `isolate_endpoint` → script que aísle la interfaz de red.
- `kill_process` → script que termine un proceso específico.
- `block_ip` → script local que bloquee una IP.

> Estos scripts deben ser controlados y auditados por el equipo SOC antes de habilitarlos.

## Tests

```bash
python manage.py test
```

## Notas de seguridad

- Webhook protegido con `X-SOAR-TOKEN`.
- Rate limit básico en middleware para el webhook.
- Auditoría append-only para acciones críticas.
- Logs estructurados configurados en `settings.py`.

## UI

- Dashboard con métricas.
- Alertas con detalle y raw payload.
- Playbooks con edición de acciones.
- Ejecuciones y auditoría.
- Integraciones con prueba de conexión Wazuh.
