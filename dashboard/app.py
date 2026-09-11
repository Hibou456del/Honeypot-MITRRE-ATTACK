"""
Django application for the Dynamic Honeypot Platform Dashboard.
Provides web interface for monitoring and analysis.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import django
from django.conf import settings
from django.core.wsgi import get_wsgi_application

# Configure Django settings
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='dev-secret-key-change-in-production',
        ALLOWED_HOSTS=['localhost', '127.0.0.1'],
        
        # Installed apps
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
        ],
        
        # Database
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': project_root / 'data' / 'honeypot.db',
            }
        },
        
        # Static files
        STATIC_URL='/static/',
        STATIC_ROOT=project_root / 'dashboard' / 'static',
        
        # Templates
        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [project_root / 'dashboard' / 'templates'],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                    ],
                },
            },
        ],
        
        # Time zone
        USE_TZ=True,
        TIME_ZONE='UTC',
    )
    
    django.setup()

# Django WSGI application
application = get_wsgi_application()


def run_dashboard(host='0.0.0.0', port=8000):
    """
    Run the dashboard development server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
    """
    from django.core.management import execute_from_command_line
    
    execute_from_command_line(['manage.py', 'runserver', f'{host}:{port}'])


if __name__ == '__main__':
    run_dashboard()