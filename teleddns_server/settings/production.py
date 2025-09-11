from .base import *
import environ

# Initialize environment variables
env = environ.Env()

# Read .env file
environ.Env.read_env(BASE_DIR / '.env')

# Production-specific settings
DEBUG = False
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[])

# Use SECRET_KEY from environment
SECRET_KEY = env('SECRET_KEY')

# Production database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': env('DATABASE_PATH', default='/data/teleddns.sqlite'),
    }
}

# Security settings
SECURE_SSL_REDIRECT = False  # Disabled - HTTPS handled by proxy
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# Production logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': env('DJANGO_LOG_LEVEL', default='WARNING'),
            'propagate': False,
        },
    },
}