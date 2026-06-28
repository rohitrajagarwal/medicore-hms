"""
MediCore HMS URL Configuration
SECURITY TRAINING PROJECT - Intentionally vulnerable
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Django admin - no additional protection
    path('admin/', admin.site.urls),

    # API endpoints
    path('api/v1/patients/', include('patients.urls')),
    path('api/v1/appointments/', include('appointments.urls')),
    path('api/v1/prescriptions/', include('prescriptions.urls')),
    path('api/v1/staff/', include('staff.urls')),
    path('api/v1/billing/', include('billing.urls')),
    path('api/v1/lab/', include('lab.urls')),

    # Admin panel with RCE vulnerabilities
    path('api/v1/admin/', include('admin_panel.urls')),

    # REST framework browsable API
    path('api-auth/', include('rest_framework.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
