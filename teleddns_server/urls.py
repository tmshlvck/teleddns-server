"""
URL configuration for teleddns_server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.views.static import serve
from dns_manager.admin import admin_site

urlpatterns = [
    path('admin/', admin_site.urls),
    path('', include('ddns.urls')),  # DDNS endpoints
    path('', include('dns_manager.urls')),  # Health check and other management endpoints
]

# Serve static files in container environment (since we use runserver instead of proper WSGI server)
# In production with proper web server, this would be handled by nginx/apache
urlpatterns += [
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]
