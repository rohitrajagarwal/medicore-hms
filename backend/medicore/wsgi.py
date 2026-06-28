"""
WSGI config for MediCore HMS project.
SECURITY TRAINING PROJECT - Intentionally vulnerable
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'medicore.settings')

application = get_wsgi_application()
