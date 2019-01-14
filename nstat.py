#!/Users/jbarnett/.virtualenvs/cisco/bin/python

'''
Created `05/11/2015 11:36`

@author jbarnett@tableau.com
@version 0.2

find_port.py: return switch, interface and port-channel info for hosts

TODO:
1. Consistency checking against both core routers. Currently only verifying on one
2. Clean up console formatting
3. Check to see if connection already exists in import loop. No need to create another duplicate connection. should be able to reuse
4. Support hosts that are direct connected to the router with or without port channel configurations (MCP1-3)
'''

import paramiko
import time
import socket
import argparse
import re
import sys
import logging
import platform
import os
import json
import csv
import subprocess
from colorama import Fore, Back, Style, init
from getpass import getpass

def main():
    # Enable printing color reset after each print
    init(autoreset=True)

    # Assumes your core router(s) have the following names. Please change if this is not the case. (only one used currently)
    switch_data={"device_ids": {
        "2501.0.0": "tssea-dev-rt-1.network.tsi.lan",
        "2502.0.0": "tssea-dev-rt-2.network.tsi.lan",
        "2511.0.0": "tssea-dev-sw-3.network.tsi.lan",
        "2512.0.0": "tssea-dev-sw-4.network.tsi.lan",
        "2521.0.0": "tssea-dev-sw-5.network.tsi.lan",
        "2522.0.0": "tssea-dev-sw-6.network.tsi.lan",
        "2531.0.0": "tssea-dev-sw-7.network.tsi.lan",
        "2532.0.0": "tssea-dev-sw-8.network.tsi.lan",
        "2541.0.0": "tssea-dev-sw-9.network.tsi.lan",
        "2542.0.0": "tssea-dev-sw-10.network.tsi.lan",
        "2551.0.0": "tssea-dev-sw-11.network.tsi.lan",
        "2552.0.0": "tssea-dev-sw-12.network.tsi.lan"
        },
        "port-channel-pairs": {
        "1500.0.0": ["tssea-dev-rt-1.network.tsi.lan", "tssea-dev-rt-2.network.tsi.lan"],
        "1501.0.0": ["tssea-dev-sw-3.network.tsi.lan", "tssea-dev-sw-4.network.tsi.lan"],
        "1502.0.0": ["tssea-dev-sw-5.network.tsi.lan", "tssea-dev-sw-6.network.tsi.lan"],
        "1503.0.0": ["tssea-dev-sw-7.network.tsi.lan", "tssea-dev-sw-8.network.tsi.lan"],
        "1504.0.0": ["tssea-dev-sw-9.network.tsi.lan", "tssea-dev-sw-10.network.tsi.lan"],
        "1505.0.0": ["tssea-dev-sw-11.network.tsi.lan", "tssea-dev-sw-12.network.tsi.lan"],
        "1506.0.0": ["tssea-dev-sw-13.network.tsi.lan", "tssea-dev-sw-14.network.tsi.lan"]
        }
    }

    # Get command line args
    args = usage()

    if 'CISCO_USER' and 'CISCO_PASS' not in os.environ:
        sys.exit("CISCO_USER and/or CISCO_PASS environment variables not set.")
    else:
        username = os.environ['CISCO_USER']
        password = os.environ['CISCO_PASS']

    router1 = switch_data['device_ids']['2541.0.0']
    router2 = switch_data['device_ids']['2542.0.0']

    if args['debug']:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if args['which'] == 'query' and args['name']:
        host_ip = get_ip(args['name'])
        if not host_ip:
            sys.exit("Host not found in DNS. Please try again")

        # Create StartConnect object for router1
        conns = StartConnect(username, password)
        conns.client_connect(router1)
        # Use invoke_shell to establish an 'interactive session'
        shell = conns.connections[0].invoke_shell()
        # Strip the initial router prompt
        router_shell_output = shell.recv(1000)
        # Turn off paging
        conns.disable_paging(shell)
        #set timeout in seconds
        shell.settimeout(30)

        # If host can't be pinged, exit cleanly
        stdin, stdout, stderr = conns.connections[0].exec_command("ping -c 10 %s" % host_ip)
        output = stdout.read()
        if '100.00% packet loss' in output:
            sys.exit("Could not ping host")

        # ping router1 so it recognizes the host
        proc = subprocess.Popen("ping -c 10 %s" % router1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if err:
            sys.exit("failed: %s" % err)

        mac_address = conns.client_get_mac(shell, host_ip)
        address_table_output = conns.client_get_address_table(shell, mac_address)
        #switch_id = parse_regex(switch_regex, address_table_output)
        switch_id = parse_regex(address_table_output)
        if switch_id.startswith("15"):
            switch_pairs = switch_data['port-channel-pairs'][switch_id]
            printc("Bond MAC", mac_address)
            print
            # Router already added as a connection, starting index at 1
            i = 1
            for sw in switch_pairs:
                printc("Device", sw)

                # Create instance of SSHClient object and add to the class connections list
                conns.client_connect(sw)
                switch_shell = conns.connections[i].invoke_shell()


                switch_shell_output = switch_shell.recv(1000)
                logging.debug(switch_shell_output)
                conns.disable_paging(switch_shell)

                switch_address_table_output = conns.client_get_address_table(switch_shell, mac_address)
                #po = parse_regex(po_regex, switch_address_table_output)
                po = parse_regex(switch_address_table_output)

                po_interface_output = conns.client_get_port_channel_summary(switch_shell, po)
                #interface = parse_regex(int_regex, po_interface_output)
                interface = parse_regex(po_interface_output)

                printc("Po", po)
                printc("Interface", interface)
                print
                i += 1

        elif switch_id.startswith("Eth"):
            switch_name = router1
            printc("Device", switch_name)
            printc("Interface", switch_id)

        else:
            switch_name = switch_data['device_ids'][switch_id]

            #print(switch_name)
            printc("Device", switch_name)

            # Create instance of SSHClient object and add to the class connections list
            conns.client_connect(switch_name)

            switch_shell = conns.connections[1].invoke_shell()

            switch_shell_output = switch_shell.recv(1000)
            logging.debug(switch_shell_output)
            conns.disable_paging(switch_shell)

            switch_address_table_output = conns.client_get_address_table(switch_shell, mac_address)
            #interface = parse_regex(int_regex, switch_address_table_output)
            interface = parse_regex(switch_address_table_output)

            printc("Interface", interface)

        ### Debug output
        if args['full']:
            switch_shell.send("show running-config interface %s\n" % interface)
            # Wait for output in case of delay
            time.sleep(1)
            output = switch_shell.recv(1000)
            m = re.search("(^interface(?s).*)(?=tssea)", output, re.MULTILINE)
            running_config = m.group(0)
            print("running-config:")
            print(Fore.GREEN + running_config.strip())

        if conns.connections:
            for conn in conns.connections:
                conn.close()

    if args['which'] == 'import' and args['csv']:
        # Create StartConnect object
        conns = StartConnect(username, password)
        f = open(args['csv'], "r")
        reader = csv.reader(f, delimiter=',')
        # Skip first commented header row
        reader.next()
        for row in reader:
            hostname = row[0].lower()
            switch_name = row[1]
            switch_port = row[2]
            switch_vlan = row[3]
            conn = conns.conn_exists(conns, switch_name)
            if conn == False:
                print("No existing connections. Creating new connection")
                # Connect to appropriate switch for each host in csv
                conns.client_connect(switch_name)
                # Use invoke_shell to establish an 'interactive session'
                shell = conns.connections[-1].invoke_shell()
            else:
                print("Existing connection found.")
                shell = conn.invoke_shell()
            # Strip the initial router prompt
            router_shell_output = shell.recv(1000)
            # Turn off paging
            conns.disable_paging(shell)
            #set timeout in seconds
            shell.settimeout(30)
            conns.client_int_conf(shell, switch_port, hostname, switch_vlan)
            print("%s configured successfully on switch: %s Port: %s VLAN: %s" % (hostname, switch_name, switch_port, switch_vlan))

        # If any connections are still open, close them.
        if conns.connections:
            for conn in conns.connections:
                conn.close()


def usage():
    '''argparse usage function'''
    # Command line parameters via argparse.
    parser = argparse.ArgumentParser(description='%(prog)s help')

    parser.add_argument("--version", action="version", version="%(prog)s 0.1")

    subparsers = parser.add_subparsers()

    parser_query = subparsers.add_parser('query', help='query a hostname', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="syntax:\nnstat query --name host1")
    parser_query.set_defaults(which='query')
    parser_query.add_argument("-n", "--name", required=True, help="Name or IP of device to find")
    parser_query.add_argument("-d", "--debug", required=False, action="store_true", help="print debug messages to stdout")
    parser_query.add_argument("-f", "--full", required=False, action="store_true", help="print full port detail")

    parser_import = subparsers.add_parser('import', help='import config from csv file', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="syntax:\nnstat import hosts.csv")
    parser_import.set_defaults(which='import')
    parser_import.add_argument('csv', help='csv file')

    args = vars(parser.parse_args())
    return args

def printc(string, var):
    print(string + ":\t" + Fore.GREEN + var).expandtabs(12)

def get_ip(dnsname):
    try:
        return socket.gethostbyname(dnsname)
    except socket.gaierror:
        return 0

def parse_regex(theinput):
    switch_regex = "(\d{4}\.\d\.\d)"
    int_regex = "(Eth\d+\/\d\/\d+|Eth\d+\/\d)"
    po_regex = "(Po\d{4})"
    regex_list = [switch_regex, int_regex, po_regex]
    for reg in regex_list:
        try:
            m = re.search(reg, theinput)
            output = m.group(0)
            return output
        except AttributeError as e:
            pass
            #sys.exit("Did not return valid switch id")

class StartConnect:
    '''Class to manage connections and commands to devices'''
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.hosts = [] # I can get rid of this?
        self.connections = []

    def disable_paging(self, shell):
        '''Disable paging'''
        shell.send("terminal length 0\n")
        # Wait for output in case of delay
        time.sleep(1)

        # Clear the buffer on the screen
        output = shell.recv(1000)

        return output

    def client_connect(self, host):
        '''Create paramiko connection object for host and add to list of connections'''
        try:
            # Create instance of SSHClient object
            client = paramiko.SSHClient()
            # Automatically add untrusted hosts
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # initiate SSH connection
            client.connect(host, username=self.username, password=self.password)
        #catch any authentication exceptions
        except paramiko.AuthenticationException as e:
            print("{0} Please check your username or password and try again.".format(e))
            sys.exit()

        self.connections.append(client)


    def client_get_mac(self, shell, host_ip):
        '''get mac address from host ip'''
        shell.send("show ip arp %s\n" % host_ip)
        # Wait for output in case of delay
        time.sleep(1)
        output = shell.recv(1000)
        logging.debug(output)
        m = re.search("(\S{4}\.\S{4}\.\S{4})", output)
        try:
            mac_address = m.group(0)
        except AttributeError as e:
            sys.exit("No MAC associated with ip %s in ARP table" % host_ip)
        return mac_address

    def client_get_address_table(self, shell, mac_address):
        '''return mac address table from specific device shell based on given mac'''
        shell.send("show mac address-table | i %s\n" % mac_address)
        # Wait for output in case of delay
        time.sleep(1)
        output = shell.recv(1000)
        logging.debug(output)
        return output

    def client_get_port_channel_summary(self, shell, po):
        ''' return port channel summary info for particular Po '''
        shell.send("show port-channel summary | i %s\n" % po)
        # Wait for output in case of delay
        time.sleep(1)
        output = shell.recv(1000)
        logging.debug(output)
        return output

    def client_int_conf(self, shell, port, desc, vlan):
        '''send command to device'''
        shell.send("conf t\n")
        shell.send("int %s\n" % port)
        if not vlan == "":
            shell.send("sw ac vlan %s\n" % vlan)
        else:
            shell.send("desc %s\n" % desc)
            shell.send("copy running-config startup-config")
            time.sleep(1)
            output = shell.recv(5000)
        return output

    def conn_exists(self, conns, switch_name):
        for index, obj in enumerate(conns.connections):
            if obj._host_keys.keys()[0] == switch_name:
                conn = conns.connections[index]
                return conn
        return False

if __name__ == '__main__':
    main()

