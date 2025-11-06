from django import forms
import html
import re

class PasswordForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter your password', 'id': 'password-input'}),
        max_length=128,
        required=True,
        label="Password"
    )

    def clean_password(self):
        password = self.cleaned_data.get('password', '').strip()
        password = html.escape(password)

        errors = []
        if len(password) < 12:
            errors.append("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", password):
            errors.append("Must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            errors.append("Must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            errors.append("Must contain at least one digit.")
        if not re.search(r"[@$!%*?&#^+=_-]", password):
            errors.append("Must contain at least one special character.")

        if errors:
            raise forms.ValidationError(errors)

        return password
