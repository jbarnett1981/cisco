#!/usr/bin/env python

'''
Created `01/15/2016 03:13`

@author omeek@tableau.com, jbarnett@tableau.com
@version 0.1

switch_config.py:

Displays or modifies switch port configuration on cisco switches

changelog:

0.1
---
First draft
'''

import sys
import os
import paramiko
import argparse
import json
import time
import re
import xmltodict

def get_args():
    parser = argparse.ArgumentParser()

    credentials_parser = parser.add_argument_group('required login arguments')
    credentials_parser.add_argument('--username', required=True, help='username to authenticate to switch')
    credentials_parser.add_argument('--password', required=True, help='password to authenticate to switch')
    credentials_parser.add_argument('--switch', required=True, help='Switch name or IP')
    credentials_parser.add_argument('--interface', required=True, help='Interface to configure')

    subparsers = parser.add_subparsers(help='commands')

    query_parser = subparsers.add_parser('query', help='Query command')
    query_parser.set_defaults(which='query')

    configure_parser = subparsers.add_parser('configure', help='Configure command')
    configure_parser.set_defaults(which='configure')
    configure_parser_group = configure_parser.add_argument_group('required interface options')
    configure_parser_group.add_argument('--vlan', required=True, help='VLAN to configure interface')
    configure_parser_group.add_argument('--name', required=True, help='Set the interface name/description')

    args = vars(parser.parse_args())

    return args

def get_interface_details(switch, interfaces, uname, pword):
    # Create list of interfaces passed to script
    queryinterfaces = interfaces.split(',')

    remote_conn_pre = paramiko.SSHClient()

    remote_conn_pre.set_missing_host_key_policy(
         paramiko.AutoAddPolicy())

    try:
        remote_conn_pre.connect(switch, username=uname, password=pword)

    except:
        sys.exit('Error connecting to switch ' + switch)

    remote_conn = remote_conn_pre.invoke_shell()

    try:
        intlist = []

        for interface in queryinterfaces:
            remote_conn.send('show int ' + interface + ' status | xml | no-more\n')

            # Wait for the command to complete
            time.sleep(2)
            output = remote_conn.recv(50000)
            output1 = re.findall('\<\?xml.*reply\>', output, re.DOTALL)

            # Convert output to temp dictionary for cleanup
            o = xmltodict.parse(output1[0],process_namespaces=True)

            interfaceData = o['urn:ietf:params:xml:ns:netconf:base:1.0:rpc-reply']['urn:ietf:params:xml:ns:netconf:base:1.0:data']['http://www.cisco.com/nxos:1.0:if_manager:show']['http://www.cisco.com/nxos:1.0:if_manager:interface']['http://www.cisco.com/nxos:1.0:if_manager:__XML__INTF_ifeth_status']['http://www.cisco.com/nxos:1.0:if_manager:status']['http://www.cisco.com/nxos:1.0:if_manager:__XML__OPT_Cmd_show_interface_status_if_eth___readonly__']['http://www.cisco.com/nxos:1.0:if_manager:__readonly__']['http://www.cisco.com/nxos:1.0:if_manager:TABLE_interface']['http://www.cisco.com/nxos:1.0:if_manager:ROW_interface']

            # Use list comprehension to replace junk in key names
            intlist.append(dict({x.replace('http://www.cisco.com/nxos:1.0:if_manager:', ''): interfaceData[x] for x in interfaceData.keys()}))

        return json.dumps(intlist)

    except:
        remote_conn_pre.close()
        sys.exit('Error encountered while retrieving interface results from ' + switch)

    remote_conn_pre.close()


def configure_switch_interface(switch, interface, vlan, description, uname, pword):

    remote_conn_pre = paramiko.SSHClient()
    remote_conn_pre.set_missing_host_key_policy(
         paramiko.AutoAddPolicy())

    # Initiate connection
    try:
        remote_conn_pre.connect(switch, username=uname, password=pword)

    except:
        remote_conn_pre.close()
        sys.exit("Error connecting to switch " + switch + "")

    remote_conn = remote_conn_pre.invoke_shell()
    output = remote_conn.recv(1000)

    # Change VLAN on Interface
    try:
        remote_conn.send("conf t\n")
        remote_conn.send("int " + interface + "\n")
        remote_conn.send("sw ac vlan " + vlan + "\n")

        if description is "" or description is " ":
            remote_conn.send("no description\n")
        else:
            remote_conn.send("desc " + description + "\n")

        remote_conn.send("copy running-config startup-config\n")
        time.sleep(2)
        output = remote_conn.recv(5000)

        print("Interface " + interface + " configured for VLAN " + vlan)

    except:
        remote_conn_pre.close()
        sys.exit("Error configuring interface " + interface)

def main():
    '''
    Main function
    '''

    args = get_args()

    if args['which'] is 'query':
        config_results = get_interface_details(args['switch'], args['interface'], args['username'], args['password'])
        print(config_results)

    elif args['which'] is 'configure':
        config_interface = configure_switch_interface(args['switch'], args['interface'], args['vlan'], args['name'], args['username'], args['password'])
        print(config_interface)


if __name__ == '__main__':
    main()
