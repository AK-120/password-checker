# yourproject/context_processors.py
from django.conf import settings

def encryption_key_context(request):
    return {"ENCRYPTION_KEY": settings.ENCRYPTION_KEY}
