#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015. The Koodous Authors. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
   
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import requests
import argparse
import json

__author__ = 'A.Sánchez <asanchez@koodous.com>'

TOKEN = '' #Register at https://koodous.com to obtain your token


def download_report(sha256, dst, token):
    """
        Function to download and save the Androguard report from Koodous.
    """

    url = 'https://koodous.com/api/apks/%s/analysis' % sha256
    data = dict()
    response = requests.get(url=url, 
                       headers = {"Authorization": "Token %s" % token})

    if response.status_code == 401:
        print 'You must provide you token access in the script (register in Koodous, it\'s free!'
        return False
    if response.status_code == 404:
        #Exists this APK in Koodous?
        response2 = requests.get(url='https://koodous.com/apks/%s' % sha256,
                                headers = {"Authorization": "Token %s" % token})
        if response2.status_code == 404:
            print 'Sorry, we haven\'t this APK in Koodous. You can share with community through our website.'
            return False
        else:
            print "Sorry, this APK has no report yet, you can requests it via Koodous website."
            return False

    data = response.json()

    json.dump(data.get('androguard', None), open(dst, 'w'))

    return True


def main():
    parser = argparse.ArgumentParser(
                            description='Tool to download reports from Koodous')
    parser.add_argument('-s', '--sha256', action='store', 
                                 dest='sha256')
    parser.add_argument('-o', '--output', action='store', dest='filename',
                        help='File to dump the downloaded report, by default: {sha256}-report.json')

    args = parser.parse_args()

    if len(TOKEN) == 0:
        print 'You must provide you token access in the script (register in Koodous, it\'s free!'
        return

    if not args.sha256:
        print "I need at least a SHA256 hash!"
        parser.print_help()
        return

    report_name = '%s-report.json' % args.sha256
    if args.filename:
        report_name = args.filename


    success = download_report(sha256=args.sha256, dst=report_name, token=TOKEN)
    if success:
        print 'Androguard report saved in %s' % report_name


if __name__ == '__main__':
    main()
