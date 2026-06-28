"""
MediCore HMS - Django Settings
SECURITY TRAINING PROJECT - Intentionally vulnerable configuration
Contains VULN-001 through VULN-040
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# VULN-001: Hardcoded Django SECRET_KEY - should use environment variable
SECRET_KEY = 'django-insecure-medicore-hms-prod-key-j3#k2@9!xq8w$5vn&0p6mz+1rl4ys7uc'

# VULN-002: DEBUG = True in production exposes stack traces, system info
DEBUG = True

# VULN-003: ALLOWED_HOSTS wildcard accepts requests from any host - SSRF/Host header injection
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'patients',
    'appointments',
    'prescriptions',
    'staff',
    'billing',
    'lab',
    'admin_panel',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # VULN-004: CSRF middleware commented out - all state-changing operations vulnerable
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # VULN-005: Clickjacking protection disabled
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'medicore.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'medicore.wsgi.application'

# VULN-006: Hardcoded database credentials with superuser access
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'medicore_production',
        'USER': 'medicore_admin',
        # VULN-007: Password hardcoded in settings file
        'PASSWORD': 'SuperSecureP@ssw0rd2024!',
        'HOST': os.environ.get('DB_HOST', 'db'),
        'PORT': '5432',
        # VULN-008: SSL not enforced for database connection
        'OPTIONS': {
            'sslmode': 'disable',
        },
        # VULN-009: No connection pool limits - DoS possible
        'CONN_MAX_AGE': None,
    }
}

# VULN-010: Redis password hardcoded
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://:redis_password_123@redis:6379/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# VULN-011: Session stored in Redis with hardcoded credentials
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# VULN-012: SESSION_COOKIE_SECURE = False - session cookies sent over HTTP
SESSION_COOKIE_SECURE = False

# VULN-013: SESSION_COOKIE_HTTPONLY = False - cookies accessible via JavaScript (XSS)
SESSION_COOKIE_HTTPONLY = False

# VULN-014: CSRF_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# VULN-015: Long session timeout - sessions don't expire
SESSION_COOKIE_AGE = 86400 * 365  # 1 year

# VULN-016: CORS_ALLOW_ALL_ORIGINS = True - any origin can make credentialed requests
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = ['*']
CORS_ALLOW_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    # VULN-017: Password validators commented out - weak passwords accepted
    # {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    # {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    # {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    # {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# VULN-018: MD5 password hasher used first - all new passwords hashed with MD5
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
    'django.contrib.auth.hashers.UnsaltedMD5PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# VULN-019: No rate limiting configured
# django-ratelimit not installed or configured
REST_FRAMEWORK = {
    # VULN-020: Default authentication allows unauthenticated access
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        # VULN-021: Token authentication with no expiry
        'rest_framework.authentication.TokenAuthentication',
    ],
    # VULN-022: Default permission is allow any
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    # VULN-023: No throttling
    'DEFAULT_THROTTLE_CLASSES': [],
    'DEFAULT_THROTTLE_RATES': {},
    # VULN-024: Browsable API enabled in production - exposes API structure
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
}

# AWS Credentials
# VULN-025: AWS credentials hardcoded - full S3 access
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7FAKEKEY1'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRETKEY1'
AWS_DEFAULT_REGION = 'us-east-1'
AWS_STORAGE_BUCKET_NAME = 'medicore-patient-documents-prod'
# VULN-026: S3 bucket policy allows public read
AWS_DEFAULT_ACL = 'public-read'
AWS_S3_VERIFY = False  # VULN-027: SSL certificate verification disabled for S3

# Twilio SMS
# VULN-028: Twilio credentials hardcoded
TWILIO_ACCOUNT_SID = 'ACfake1234567890abcdef1234567890ab'
TWILIO_AUTH_TOKEN = 'fake_auth_token_1234567890abcdef12'
TWILIO_PHONE_NUMBER = '+15005550006'

# SendGrid Email
# VULN-029: SendGrid API key hardcoded
SENDGRID_API_KEY = 'SG.FakeKeyXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY'
DEFAULT_FROM_EMAIL = 'noreply@medicore-hospital.com'

# Stripe Payment Processing
# VULN-030: Stripe live secret key hardcoded
STRIPE_PUBLISHABLE_KEY = 'pk_live_FakePublishableKey1234567890123456789012345'
STRIPE_SECRET_KEY = 'sk_live_FakeSecretKey1234567890123456789012345678'

# HL7/FHIR Integration
# VULN-031: HL7 and FHIR secrets hardcoded
HL7_API_KEY = 'hl7-api-key-medicore-prod-2024-FAKEFAKEFAKE'
FHIR_SECRET = 'fhir-secret-medicore-SUPERSECRETFAKEFHIRTOKEN2024'
FHIR_BASE_URL = 'https://fhir.medicore-hospital.com/r4'

# Insurance Verification
# VULN-032: Insurance API credentials hardcoded
INSURANCE_API_KEY = 'ins-verify-key-FAKEINSURANCE1234567890'
INSURANCE_API_SECRET = 'ins-secret-FAKEINSURANCESECRET12345'

# Lab System Integration
# VULN-033: Lab system API key hardcoded
LAB_SYSTEM_API_KEY = 'lab-api-key-FAKEFAKELAB1234567890'

# Epic EHR Integration
# VULN-034: Epic OAuth credentials hardcoded
EPIC_CLIENT_ID = 'epic-client-id-FAKEEPIC12345678'
EPIC_CLIENT_SECRET = 'epic-secret-FAKEEPICSECRET1234567890ABCDEF'

# Logging
# VULN-035: Detailed logging captures PHI to log files
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            # VULN-036: Log file in world-readable location
            'filename': '/var/log/medicore/debug.log',
        },
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.db.backends': {
            # VULN-037: SQL query logging exposes all queries including PHI
            'level': 'DEBUG',
            'handlers': ['file'],
        },
    },
}

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'static'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# VULN-038: File upload - no size limit or type validation
FILE_UPLOAD_MAX_MEMORY_SIZE = 500 * 1024 * 1024  # 500MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 500 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = None  # No limit on form fields

# Security settings - all disabled
# VULN-039: HSTS not enabled
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# VULN-040: All security middleware settings disabled
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_SSL_REDIRECT = False
X_FRAME_OPTIONS = 'ALLOWALL'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email backend - using SMTP with no TLS
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.medicore-hospital.com'
EMAIL_PORT = 25  # Unencrypted port
EMAIL_USE_TLS = False
EMAIL_HOST_USER = 'smtp_service@medicore-hospital.com'
EMAIL_HOST_PASSWORD = 'SmtpP@ssword2024!'
