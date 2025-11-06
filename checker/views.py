from django.shortcuts import render
from .forms import PasswordForm
from django.http import JsonResponse 
import hashlib
import requests

def check_breach_api(request):
    """AJAX API: returns whether password is breached."""
    password = request.GET.get("password", "")
    if not password:
        return JsonResponse({"error": "No password"}, status=400)

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        breached = suffix in res.text
        return JsonResponse({"breached": breached})
    except Exception as e:
        print("[DEBUG] Breach check failed:", e)
        return JsonResponse({"breached": None})
    
def password_check_view(request):
    strength = None
    details = {}
    breached = None
    form = PasswordForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        password = form.cleaned_data['password']

        # Run breach check
        breached = check_breach(password)

        # Calculate strength
        checks = {
            "length": len(password) >= 12,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "digit": any(c.isdigit() for c in password),
            "special": any(c in "@$!%*?&#^+=_-" for c in password),
        }

        passed = sum(checks.values())
        levels = {
            5: "Very Strong 💪",
            4: "Strong 👍",
            3: "Medium ⚠️",
            2: "Weak ❗",
            1: "Very Weak ❌",
            0: "Invalid ❌"
        }
        strength = levels[passed]
        details = checks

    return render(request, "checker/check.html", {
        "form": form,
        "strength": strength,
        "details": details,
        "breached": breached
    })
