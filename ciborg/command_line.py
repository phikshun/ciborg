#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ciborg
import argparse
import os
import sys


def banner():
    print('''
 _______ _____ ______   _____   ______  ______
 |         |   |_____] |     | |_____/ |  ____
 |_____  __|__ |_____] |_____| |    \_ |_____|
                                              
                 Version 0.1
    ''')


def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--range', type=str, help='specify IP range to scan')
    parser.add_argument('-u', '--udp', action='store_true', help='find via UDP broadcast')
    parser.add_argument('-a', '--aws', action='store_true', help='find EC2 targets using AWS API')
    args = parser.parse_args()

    options = {
        'ip_range': args.range,
        'udp_scan': args.udp,
        'use_aws':  args.aws
    }

    borg = ciborg.CIborg(options)
    borg.run()


if __name__ == '__main__':
    main()
