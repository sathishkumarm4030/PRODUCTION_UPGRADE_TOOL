#!/usr/bin/env python

"""
This Tool is designed for upgrading Versa CPE.
"""

__author__ = "Sathishkumar murugesan"
__copyright__ = "Copyright(c) 2018 Colt Technologies india pvt ltd."
__credits__ = ["Danny Pinto"]
__license__ = "GPL"
__version__ = "1.0.1"
__maintainer__ = "Sathishkumar Murugesan"
__email__ = "Sathishkumar.Murugesan@colt.net"
__status__ = "Developed"

import requests
import urllib3
from datetime import datetime
import csv
import time
import requests
import errno
import os
import logging
import logging.handlers
import urllib3
import datetime
from datetime import datetime
from Utils import templates as t1
import json
import pandas as pd


#urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
vd_dict = {}
vd_dict['ip'] = '10.91.116.35'
vdurl = 'https://10.91.116.35:9182'
appliance_url = '/vnms/appliance/appliance?offset=0&limit=1000'
package_url = '/api/operational/nms/packages/package?select=name;uri'
user = 'Sathish'
passwd = 'Jan*1234'
headers3 = {'Accept': 'application/json', 'Content-Type': 'application/json'}
up_pkg_dict = {}
# model = 'FWA-3260'
# pkg_name = 'CPE-16.1R2S2.2'
# mdl_pkg_dict = {}
#
# while True:
#     model, pkg_name = raw_input("Please enter Vcpe MODEL and package name:\n").split()
#     mdl_pkg_dict[model] = pkg_name
#     if raw_input("DO You Have More Models For Upgrade.Please enter yes or no\n") != 'yes':
#         break
#
# print model
# print pkg_name
#
#
# print mdl_pkg_dict

logfile_dir = '.'
devices_list = []

# def read_csv_file(filename):
#     csv_data_read = pd.read_csv(filename)
#     pl = csv_data_read.loc[csv_data_read['model']]
#     filtered_cpes = pl.loc[pl['batch'] == int(batch)]
#     return filtered_cpes


def build_csv(device_list):
    data_header = ['name', 'ipAddress', 'day', 'batch', 'ownerOrg', 'type', 'softwareVersion', 'ping-status', 'sync-status', 'serialNo', 'model', 'existing-packageName']
    with open('DEVICED.csv', 'w') as file_writer:
        writer = csv.writer(file_writer)
        writer.writerow(data_header)
        for item in device_list:
            writer.writerow(item)
    csv_data_read = pd.read_csv('DEVICED.csv')
    models = csv_data_read['model'].drop_duplicates().values
    # csv_data_read.
    model_dict = {}
    for model in models:
        print model
        model_dict[model] = raw_input("Package name for " + model + ":\n")
    with open(vd_dict['ip'] + '_Vcpe_List.csv', 'w') as file_writer1:
        data_header = ['name', 'ipAddress', 'day', 'batch', 'ownerOrg', 'type', 'softwareVersion', 'ping-status',
                       'sync-status', 'serialNo', 'model', 'existing-packageName', 'Upgrade-PackageName', 'Upgradepackage']
        writer = csv.writer(file_writer1)
        writer.writerow(data_header)
        for item in device_list:
            item.append(model_dict[item[10]])
            item.append(get_upgrade_package_name(model_dict[item[10]]))
            writer.writerow(item)


def get_upgrade_package_name(package_name):
    global up_pkg_dict
    if package_name not in up_pkg_dict:
        response1 = requests.get(vdurl + package_url,
                                 auth=(user, passwd),
                                 headers=headers3,
                                 verify=False)
        data1 = response1.json()
        # print data1
        for i in data1['package']:
            if i['name'] == package_name:
                pkg_version =  i['uri']
                pkg_version = pkg_version.replace(".bin", "")
                up_pkg_dict[package_name] = pkg_version
    return up_pkg_dict[package_name]

def get_device_list():
    response1 = requests.get(vdurl + appliance_url,
                             auth=(user, passwd),
                             headers=headers3,
                             verify=False)
    data1 = response1.json()
    count, day, batch = 1, 1, 1
    for i in data1['versanms.ApplianceStatusResult']['appliances']:
        device_list = []
        if i['type']=='branch':
            if i['ownerOrg'] != 'Colt':
                if i['ping-status'] == 'REACHABLE':
                    if count%10 == 0:
                        batch += 1
                    device_list.append(i['name'])
                    device_list.append(i['ipAddress'])
                    device_list.append(day)
                    device_list.append(batch)
                    device_list.append(i['ownerOrg'])
                    device_list.append(i['type'])
                    device_list.append(i['softwareVersion'])
                    device_list.append(i['ping-status'])
                    device_list.append(i['sync-status'])
                    try:
                        if i['Hardware']!="":
                            device_list.append(i['Hardware']['serialNo'])
                            device_list.append(i['Hardware']['model'])
                            device_list.append(i['Hardware']['packageName'])
                    except KeyError as ke:
                        print i['name']
                        print "Hardware Info NIL"
                    #print count, day, batch
                    count +=1
                    devices_list.append(device_list)
    return devices_list







def main():
    # main_logger.info("Prepare CSV sheet")
    start_time = datetime.now()
    build_csv(get_device_list())
    # main_logger.info("SCRIPT Completed.")
    # main_logger.info("Result Stored in " + logfile_dir + "/RESULT.csv")
    # main_logger.info("LOG FILES Path: " + logfile_dir)
    # main_logger.info("Time elapsed: {}\n".format(datetime.now() - start_time))


if __name__ == "__main__":
    main()
