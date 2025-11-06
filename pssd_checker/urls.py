from django.contrib import admin
from django.urls import path, include  # ✅ include is used to bring in app urls

urlpatterns = [
    path('YWRtaW4/', admin.site.urls),
    path('', include('checker.urls')),  # ✅ include the checker app URLs
]
