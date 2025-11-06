from django.shortcuts import render
from .forms import PasswordForm
from django.http import JsonResponse, Http404
from django.conf.urls import handler404, handler500
import hashlib
import requests
import logging
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import struct
from django.conf import settings


logger = logging.getLogger(__name__)

# Your encryption key - MUST match frontend exactly!
# In production, store this in environment variables

ENCRYPTION_KEY = settings.ENCRYPTION_KEY


def encryption_key_context(request):
    """
    Context processor to make encryption key available to all templates
    """
    return {
        'ENCRYPTION_KEY': settings.ENCRYPTION_KEY
    }



def decrypt_aes_cryptojs(ciphertext_b64: str, passphrase: str) -> str:
    """
    Decrypt data encrypted with CryptoJS.AES.encrypt()
    Compatible with CryptoJS's OpenSSL-compatible format.
    """
    try:
        # Decode the base64 ciphertext
        encrypted = base64.b64decode(ciphertext_b64)
        
        # CryptoJS prepends "Salted__" (8 bytes) + salt (8 bytes) to the ciphertext
        if encrypted[:8] != b'Salted__':
            logger.error("Missing 'Salted__' prefix")
            return None
            
        salt = encrypted[8:16]
        ciphertext = encrypted[16:]
        
        # Derive key and IV using MD5 (CryptoJS default KDF)
        def derive_key_and_iv(password: str, salt: bytes, key_length: int = 32, iv_length: int = 16):
            """
            Equivalent to OpenSSL's EVP_BytesToKey with MD5
            This is what CryptoJS uses by default
            """
            import hashlib
            d = d_i = b''
            while len(d) < key_length + iv_length:
                d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
                d += d_i
            return d[:key_length], d[key_length:key_length + iv_length]
        
        key, iv = derive_key_and_iv(passphrase, salt)
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        if isinstance(padding_length, str):
            padding_length = ord(padding_length)
            
        decrypted = decrypted[:-padding_length]
        
        return decrypted.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}", exc_info=True)
        return None


def check_breach_api(request):
    """AJAX API: returns whether password is breached (with encryption)."""
    # Get encrypted data from query params
    encrypted_data = request.GET.get("data", "")

    if not encrypted_data:
        return JsonResponse({
            "breached": None,
            "error": "Missing data parameter"
        }, status=400)

    # Log for debugging (remove in production)
    logger.info(f"Received encrypted data (first 50 chars): {encrypted_data[:50]}...")

    # Decrypt the password
    password = decrypt_aes_cryptojs(encrypted_data, ENCRYPTION_KEY)
    
    if not password:
        logger.error("Failed to decrypt password")
        return JsonResponse({
            "breached": None,
            "error": "Invalid or corrupted data"
        }, status=400)

    logger.info(f"Successfully decrypted password (length: {len(password)})")

    try:
        # Hash the password with SHA-1
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        # Check against haveibeenpwned API
        res = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        
        if res.status_code != 200:
            return JsonResponse({
                "breached": None,
                "error": "API error"
            }, status=502)
        
        # Check if suffix appears in response
        breached = any(suffix in line for line in res.text.splitlines())
        return JsonResponse({"breached": breached})

    except requests.Timeout:
        return JsonResponse({
            "breached": None,
            "error": "Timeout"
        }, status=504)
    except Exception as e:
        logger.error(f"Breach check failed: {e}")
        return JsonResponse({
            "breached": None,
            "error": "Service unavailable"
        }, status=500)


def check_breach(password):
    """Helper function to check if password is breached."""
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        
        res = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        
        if res.status_code == 200:
            return any(suffix in line for line in res.text.splitlines())
        return None
    except Exception as e:
        logger.error(f"Breach check error: {e}")
        return None


def password_check_view(request):
    """Main password checker view."""
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


def custom_404_view(request, exception=None):
    """Handles 404 errors globally for both API and normal pages."""
    logger.warning(f"404 Not Found: {request.path}")

    # Check if it's an API endpoint
    api_paths = ["/Y2hlY2tfYnJlYWNo/", "/api/"]
    
    if any(request.path.startswith(path) for path in api_paths):
        return JsonResponse({
            "status": 404,
            "error": "Not Found",
            "message": f"The requested endpoint '{request.path}' does not exist."
        }, status=404)

    # Render custom HTML 404 page
    return render(request, "404.html", status=404)


def custom_500_view(request):
    """Handles unexpected server errors globally."""
    logger.error("500 Internal Server Error", exc_info=True)

    # Return JSON for API endpoints
    if request.path.startswith("/api/") or request.path.startswith("/Y2hlY2tfYnJlYWNo/"):
        return JsonResponse({
            "status": 500,
            "error": "Internal Server Error",
            "message": "An unexpected error occurred."
        }, status=500)

    return render(request, "500.html", status=500)


# Register handlers globally
handler404 = custom_404_view
handler500 = custom_500_view