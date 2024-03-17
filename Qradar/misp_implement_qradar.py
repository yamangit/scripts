#!/usr/bin/env python


###################################################
# Auther: Yaman Singh Rana                        #
# Date: Jan 29, 2024                              #
# Description: Script to implement misp in qradar #
# Help: python3 misp_implement_qradar.py --help   #
###################################################


import requests
import json
import argparse


requests.packages.urllib3.disable_warnings()


class MispConnection(object):
    # MISP server Connection
    def __init__(self, ip, ssl=False, verify=False, auth_token='', timeout=10):
        self.ip = ip
        self.ssl = ssl
        self.verify = verify
        self.auth_token = auth_token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False

        self.headers = {
            'Authorization': auth_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.BASE_URL = f'https://{self.ip}/attributes/restSearch/json'
    
    def pull_data(self, query_type: str, time_filter='1d', category='Network activity'):
        query = {
            "request": {
                "type": query_type,
                "category": category,
                "last": time_filter,
                "enforceWarnlinglist": "True"
            }
        }

        with self.session.post(url=self.BASE_URL, headers=self.headers, json=query) as request:
            request.raise_for_status()
            try:
                data = request.json().get('response', {}).get('Attribute', [])
                # print(json.dumps(data, indent=4))
                response_data = [ret_data.get('value') for ret_data in data]
                return response_data
            except json.JSONDecodeError as e:
                raise ValueError(f"Error decoding JSON response: {e}")


class QradarConnection(object):
    # Qradar server Connection
    def __init__(self, ip, ssl=False, verify=False, auth_token='', timeout=10):
        self.ip = ip
        self.ssl = ssl
        self.verify = verify
        self.auth_token = auth_token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False 
        self.BASE_URL = f'https://{self.ip}/api/'
        self.headers = {
            'SEC': self.auth_token,
            'Content-Type': 'application/json',
            'Version': '19.0',
            'Accept': 'application/json'
        }

    def get_reference_set_name(self, reference_name):
        url = f'{self.BASE_URL}reference_data/sets/{reference_name}'
        
        with self.session.get(url=url,headers=self.headers) as request:
            if request.status_code == 200:
                print(f'[+] Reference set: {reference_name} is exists, so data will be added here.')
                return True
            else:
                print(f"[+] Reference set: {reference_name} doesn't exists, it will be created.") 
                return

    
    def create_reference_set(self, reference_path:str):
        url = f'{self.BASE_URL}reference_data/sets?element_type=ALNIC&name={reference_path}'
        
        with self.session.post(url=url, headers=self.headers) as request:
            request.raise_for_status()

            if request.status_code == 201:
                print(f'[+] New Reference Set: /api/reference_data/sets/{reference_path} is created')
            else:
                print(f"[-] Unknown Error: Reference set {reference_path} can't be created")

    def push_data(self, data: list, misp_path: str):
        url = f'{self.BASE_URL}reference_data/sets/bulk_load/SHARED/{misp_path}/SHARED'

        if not self.get_reference_set_name(reference_name=misp_path):
            self.create_reference_set(reference_path=misp_path)

        with self.session.post(url=url, headers=self.headers, json=data) as request:
            request.raise_for_status()
            try:
                if request.status_code == 200:
                    print(f'[+] Number: {len(data)} data has been added/updated in path --> {url}')
                else:
                    print("[-] Reference data can't be added/Updated")
            except Exception as e:
                raise Exception(f'Error: {e}')
            
def main():

    parser = argparse.ArgumentParser(
        description='Fetch data from MISP and push it to QRadar reference sets.',
        formatter_class=argparse.RawTextHelpFormatter
        
    )
    
    parser.add_argument('--misp-server','-ms', type=str, help='MISP server IP or domain', required=True)
    parser.add_argument('--misp-token','-mt', type=str, help='MISP server authentication token', required=True)
    parser.add_argument('--misp-query','-mq', type=str, help='MISP query for data retrieval,eg. --misp-query dst_ip', required=True)

    parser.add_argument('--qradar-console','-qc', type=str, help='QRadar console IP or domain', required=True)
    parser.add_argument('--qradar-token','-qt', type=str, help='QRadar security token', required=True)
    parser.add_argument('--misp-category','-ct', type=str, help='Misp query category', required=False)
    parser.add_argument('--misp-filter-time','-ft', type=str, help='Misp Filter time', required=False)

    args = parser.parse_args()

    # MISP Connection Initiation
    misp = MispConnection(ip=args.misp_server, auth_token=args.misp_token)

    # Malware data fetching
    if args.misp_category and not args.misp_filter_time:
        domain_data = misp.pull_data(query_type=args.misp_query, category=args.misp_category)
    if not args.misp_category and args.misp_filter_time:
        domain_data = misp.pull_data(query_type=args.misp_query, time_filter=args.misp_filter_time)
    if args.misp_category and args.misp_filter_time:
        domain_data = misp.pull_data(query_type=args.misp_query, category=args.misp_category, time_filter=args.misp_filter_time)
    if not args.misp_category and not args.misp_filter_time:
        domain_data = misp.pull_data(query_type=args.misp_query)
    
    print(f'[+] Total counts last 1 days:{len(domain_data)}')

    # Qradar Connection Initiation
    qradar = QradarConnection(ip=args.qradar_console, auth_token=args.qradar_token)

    # Pushing data to QRadar reference sets
    qradar.push_data(data=domain_data, misp_path=f"misp_{args.misp_query.replace('-','_')}".upper())


if __name__ == '__main__':
    main()