# -*- coding: utf-8 -*-

import aws
import jenkins_plugin
import ssh
import util
import time
import requests
import nmap
import pprint
import urllib3
import socket
from threading import Thread, Semaphore, active_count
from requests.exceptions import SSLError, ConnectionError, RequestException, Timeout

class CIborg:

    def __init__(self, opts):
        requests.packages.urllib3.disable_warnings()
        self.plugins  = [ jenkins_plugin ]
        self.ip_range = opts.pop('ip_range', None)
        self.udp_scan = opts.pop('udp_scan', False)
        self.use_aws  = opts.pop('use_aws', False)
        self.threads  = 20
        self.thread_lock = Semaphore(value=1)

    def scanresult_to_url(self, ip, port, path):
        if '443' in str(port):
            scheme = 'https://'
        else:
            scheme = 'http://'
        if port == 443 or port == 80:
            url = scheme + ip + path
        else:
            url = scheme + ip + ':' + str(port) + path
        return url

    def portscan(self, ip_range, ports):
        results = []
        nm = nmap.PortScanner()
        res = nm.scan(ip_range, ports, arguments='-Pn -T4')
        if 'scan' in res:
            for host, values in res['scan'].iteritems():
                if 'tcp' in values:
                    for port, port_result in values['tcp'].iteritems():
                        if 'state' in port_result and port_result['state'] == 'open':
                            results.append(host + ':' + str(port))
        return results

    def web_scan_thread(self, targets, plugin, ip, port, path):
        url = self.scanresult_to_url(ip, port, path)
        res = None
        try:
            res = requests.get(url, verify=False, timeout=10)
        except (SSLError, ConnectionError, Timeout, RequestException,
                    urllib3.exceptions.LocationParseError) as e:
            self.thread_lock.acquire()
            print 'Error: ' + str(e)
            self.thread_lock.release()
            return

        if res and res.status_code == 200 or res.status_code == 403 or res.status_code == 401:
            self.thread_lock.acquire()
            print 'Success getting %s' % url 
            fp = plugin.fingerprint(res)
            if fp:
                print 'Found %s' % plugin.TARGET_NAME
                if ip not in targets:
                    targets[ip] = []
                targets[ip].append({
                    'url': url,
                    'port': port,
                    'path': path,
                    'plugin': plugin,
                    'status': fp
                })
            self.thread_lock.release()
        else:
            self.thread_lock.acquire()
            print 'Error %d getting %s' % (res.status_code, url)
            self.thread_lock.release()
        return

    def find_by_range(self, iprange):
        print 'Scanning %s' % iprange
        targets = {}
        for plugin in self.plugins:
            ports = ','.join([str(x) for x in plugin.DEFAULT_PORTS])
            results = self.portscan(iprange, ports)

            for result in results:
                print 'Trying candidate system %s' % result
                ip, port = result.split(':')
                for path in plugin.DEFAULT_PATHS:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    t = Thread(target=self.web_scan_thread, args=(targets, plugin, ip, port, path))
                    t.start()
        while active_count() > 1:
            time.sleep(0.1)
        return targets

    def parse_udp_response(self, data, host):
        if 'hudson' in data or 'jenkins' in data:
            return host[0]
        else:
            return None

    def find_by_udp(self):
        hosts = []
        targets = {}

        address = ('255.255.255.255', 33848)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.2)
        sock.sendto('\n', address)

        for _ in range(20):
            try:
                hosts.append(self.parse_udp_response(*sock.recvfrom(65535)))
            except socket.timeout:
                continue

        for host in hosts:
            if host is None:
                continue
            targets.update(self.find_by_range(host))
        return targets

    def find_by_aws(self):
        targets = {}
        scanner = aws.AWSScanner()
        hosts = scanner.run()

        for group in list(util.chunks(hosts, 100)):
            print 'Scanning %d hosts...' % len(group)
            targets.update(self.find_by_range(' '.join([str(x) for x in group])))

        return targets

    def run(self):
        targets = {}

        if self.ip_range:
            targets.update(self.find_by_range(self.ip_range))
        if self.udp_scan:
            targets.update(self.find_by_udp())
        if self.use_aws:
            targets.update(self.find_by_aws())

        for ip, target in targets.iteritems():
            for endpoint in target:
                endpoint['plugin'].assess(endpoint)
        pprint.pprint(targets)
