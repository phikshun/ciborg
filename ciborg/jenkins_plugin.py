# -*- coding: utf-8 -*-

import requests
import jenkins

DEFAULT_PORTS = [80, 8080, 443, 8000, 8081]
DEFAULT_PATHS = ['/', '/jenkins']
TARGET_NAME   = 'Jenkins'

def fingerprint(res):
    if res.status_code == 403:
        if res.headers.get('x-hudson') or res.headers.get('x-jenkins') or \
                        'window.location.replace(\'/login?from=' in res.text:
            return 'authenticated'
    if res.status_code == 200 and '<title>Dashboard [Jenkins]</title>' in res.text:
        return 'open'
    return None
