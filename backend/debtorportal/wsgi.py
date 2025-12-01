"""
WSGI config for debtorportal project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'debtorportal.settings')

application = get_wsgi_application()
