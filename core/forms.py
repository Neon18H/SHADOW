from django import forms
from django.forms import inlineformset_factory
from .models import Playbook, PlaybookAction, IntegrationStatus


class PlaybookForm(forms.ModelForm):
    class Meta:
        model = Playbook
        fields = ['name', 'description', 'enabled', 'match_types', 'min_severity', 'mode']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'match_types': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'min_severity': forms.Select(attrs={'class': 'form-select'}),
            'mode': forms.Select(attrs={'class': 'form-select'}),
            'enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean_match_types(self):
        value = self.cleaned_data['match_types']
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return []
            try:
                import json

                parsed = json.loads(value)
                if not isinstance(parsed, list):
                    raise forms.ValidationError('match_types must be a JSON list.')
                return parsed
            except json.JSONDecodeError as exc:
                raise forms.ValidationError('match_types must be valid JSON.') from exc
        return value


class PlaybookActionForm(forms.ModelForm):
    class Meta:
        model = PlaybookAction
        fields = ['type', 'order', 'config']
        widgets = {
            'type': forms.Select(attrs={'class': 'form-select'}),
            'order': forms.NumberInput(attrs={'class': 'form-control'}),
            'config': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
        }

    def clean_config(self):
        value = self.cleaned_data['config']
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return {}
            try:
                import json

                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise forms.ValidationError('config must be a JSON object.')
                return parsed
            except json.JSONDecodeError as exc:
                raise forms.ValidationError('config must be valid JSON.') from exc
        return value


PlaybookActionFormSet = inlineformset_factory(
    Playbook,
    PlaybookAction,
    form=PlaybookActionForm,
    extra=1,
    can_delete=True,
)


class IntegrationConfigForm(forms.ModelForm):
    tags = forms.CharField(
        required=False,
        help_text='Separadas por coma.',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'soc,prod,primary'}),
    )

    class Meta:
        model = IntegrationStatus
        fields = ['api_url', 'verify_tls', 'timeout', 'enabled', 'tags']
        widgets = {
            'api_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://wazuh.example/api'}),
            'verify_tls': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'timeout': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 120}),
            'enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean_tags(self):
        value = self.cleaned_data.get('tags', '')
        if not value:
            return []
        if isinstance(value, list):
            return value
        return [tag.strip() for tag in value.split(',') if tag.strip()]
