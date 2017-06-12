# -*- coding: utf-8 -*-

import aws
import jenkins
import ssh
import requests
import nmap
import pprint
import urllib3

class CIborg:

    def __init__(self, opts):
        requests.packages.urllib3.disable_warnings()
        self.plugins = [ jenkins ]
        self.ip_range = opts.pop('ip_range', None)
        self.udp_scan = opts.pop('udp_scan', False)
        self.use_aws = opts.pop('use_aws', False)

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
        res = nm.scan(ip_range, ports)
        if 'scan' in res:
            for host, values in res['scan'].iteritems():
                if 'tcp' in values:
                    for port, port_result in values['tcp'].iteritems():
                        if 'state' in port_result and port_result['state'] == 'open':
                            results.append(host + ':' + str(port))
        return results

    def find_by_range(self):
        print 'Scanning %s' % self.ip_range
        targets = {}
        for plugin in self.plugins:
            ports = ','.join([str(x) for x in plugin.DEFAULT_PORTS])
            results = self.portscan(self.ip_range, ports)

            for result in results:
                print 'Trying candidate system %s' % result
                ip, port = result.split(':')
                for path in plugin.DEFAULT_PATHS:
                    url = self.scanresult_to_url(ip, port, path)
                    try:
                        print url
                        res = requests.get(url, verify=False, timeout=2)
                    except requests.exceptions.SSLError as e:
                        print 'SSL connection error'
                        continue
                    except requests.exceptions.ConnectionError as e:
                        print 'Connection error'
                        continue
                    except requests.exceptions.Timeout as e:
                        print 'Connection timeout'
                        continue
                    except requests.exceptions.RequestException as e:
                        print 'Error: ' + str(e)
                        continue
                    except urllib3.exceptions.LocationParseError as e:
                        print 'Redirect error: ' + str(e)
                        continue

                    if res.status_code == 200:
                        print 'Success getting %s' % url 
                        if plugin.fingerprint(res.text):
                            print 'Found %s' % plugin.TARGET_NAME
                            targets[ip] = { 'port': port, 'path': path, 'type': plugin }
                    else:
                        print 'Error %d getting %s' % (res.status_code, url)
        return targets

    def run(self):
        targets = {}

        if self.ip_range:
            targets.update(self.find_by_range())

        pprint.pprint(targets)
