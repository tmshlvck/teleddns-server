"""
URL configuration for dns_manager app.
"""
from django.urls import path
from . import views

app_name = 'dns_manager'

urlpatterns = [
    path('healthcheck/', views.health_check, name='health_check'),
    path('robots.txt', views.robots_txt, name='robots_txt'),
]