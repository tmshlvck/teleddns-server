"""
URL configuration for DDNS API endpoints.

Provides both /ddns/update and /update paths for DDNS clients.
"""
from django.urls import path
from . import views

app_name = 'ddns'

urlpatterns = [
    # Standard DDNS endpoints
    path('ddns/update', views.ddns_update, name='ddns_update'),
    path('update', views.ddns_update, name='ddns_update_alt'),
]