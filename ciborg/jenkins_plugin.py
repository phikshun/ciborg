# -*- coding: utf-8 -*-

import requests
import jenkins
import re

DEFAULT_PORTS = [80, 8080, 443, 8000, 8081]
DEFAULT_PATHS = ['/', '/jenkins']
TARGET_NAME   = 'Jenkins'

def fingerprint(res):
    if res.status_code == 403:
        if res.headers.get('x-hudson') or res.headers.get('x-jenkins') or \
                        'window.location.replace(\'/login?from=' in res.text:
            if res.headers.get('x-jenkins'):
                version = res.headers.get('x-jenkins')
            else:
                version = 'unknown'
            return { 'use_security': True, 'version': version }
    if res.status_code == 200 and '<title>Dashboard [Jenkins]</title>' in res.text:
        match = re.search(r'Jenkins ver\. ([\d\.]+)', res.text)
        if match:
            version = match.group(1)
        elif res.headers.get('x-jenkins'):
            version = res.headers.get('x-jenkins')
        else:
            version = 'unknown'
        return { 'use_security': False, 'version': version }
    return None
