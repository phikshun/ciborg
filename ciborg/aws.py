# -*- coding: utf-8 -*-

import boto3
import botocore

class AWSScanner:

    def __init__(self):
        self.ec2 = boto3.resource('ec2')

    def run(self):
        hosts = []
        try:
            running_instances = self.ec2.instances.filter(Filters=[{
                                                     'Name': 'instance-state-name',
                                                     'Values': ['running']}])
            for instance in running_instances:
                hosts.append(instance.public_ip_address)
                hosts.append(instance.private_ip_address)

        except botocore.exceptions.ClientError as e:
            print 'Error accessing AWS: ' + str(e)
        
        return hosts
