# -*- coding: utf-8 -*-

import requests
import re

DEFAULT_PORTS = [80, 8080, 443, 8000, 8081]
DEFAULT_PATHS = ['/', '/jenkins']
TARGET_NAME   = 'Jenkins'

def fingerprint(html):
    return re.search(r'jenkins', html, re.IGNORECASE | re.MULTILINE)
