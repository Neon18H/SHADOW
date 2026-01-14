from django import forms
from django.forms import inlineformset_factory
from .models import Playbook, PlaybookAction


class PlaybookForm(forms.ModelForm):
    class Meta:
        model = Playbook
        fields = ['name', 'description', 'enabled', 'match_types', 'min_severity', 'mode']
        widgets = {
            'match_types': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
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
