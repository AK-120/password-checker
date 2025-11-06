from django.urls import path
from . import views

urlpatterns = [
    path("", views.password_check_view, name="password_check"),
    path("Y2hlY2tfYnJlYWNo/", views.check_breach_api, name="check_breach_api"),
]
