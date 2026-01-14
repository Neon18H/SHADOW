from rest_framework import serializers


class WazuhAlertSerializer(serializers.Serializer):
    rule = serializers.DictField()
    agent = serializers.DictField(required=False)
    manager = serializers.DictField(required=False)
    timestamp = serializers.CharField(required=False)
    full_log = serializers.CharField(required=False, allow_blank=True)
    data = serializers.JSONField(required=False)

    def validate_rule(self, value):
        if 'id' not in value or 'level' not in value:
            raise serializers.ValidationError('rule.id and rule.level are required')
        return value
