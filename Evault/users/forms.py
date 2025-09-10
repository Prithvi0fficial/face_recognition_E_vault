# forms.py
from django import forms
from django.contrib.auth.models import User

class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    pin = forms.CharField(max_length=6, required=True, widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists")
        return username
    
class PINLoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    pin = forms.CharField(max_length=6, widget=forms.PasswordInput)