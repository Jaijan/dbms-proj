from django import forms
from .models import Credential

COMMON_WEBSITES = ['Google', 'Facebook', 'Instagram', 'Twitter', 'Reddit', 'LinkedIn', 'Netflix', 'Amazon']

class CredentialForm(forms.ModelForm):
    website = forms.CharField(
        widget=forms.TextInput(attrs={
            'list': 'websites',
            'placeholder': 'Enter website'
        })
    )

    class Meta:
        model = Credential
        fields = ['website', 'username']

    password = forms.CharField(widget=forms.PasswordInput())
