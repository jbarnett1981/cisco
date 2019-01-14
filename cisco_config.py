#!/usr/bin/python

'''
Created `05/11/2015 10:13`

@author jbarnett@tableau.com
@version 0.1

cisco_config.py: update switch port with given hostname and vlan #
'''


import paramiko
import time


def disable_paging(remote_conn):
    '''Disable paging on a Cisco router'''

    remote_conn.send("terminal length 0\n")
    time.sleep(1)

    # Clear the buffer on the screen
    output = remote_conn.recv(1000)

    return output


if __name__ == '__main__':


    # VARIABLES THAT NEED CHANGED
    switch = 'tssea-dev-sw-5.network.tsi.lan'
    username = 'USERNAME'
    password = 'PASSWORD'

    # Create instance of SSHClient object
    remote_conn_pre = paramiko.SSHClient()

    # Automatically add untrusted hosts (make sure okay for security policy in your environment)
    remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # initiate SSH connection
    remote_conn_pre.connect(ip, username=username, password=password)
    print "SSH connection established to %s" % ip

    # Use invoke_shell to establish an 'interactive session'
    remote_conn = remote_conn_pre.invoke_shell()
    print "Interactive SSH session established"

    # Strip the initial router prompt
    output = remote_conn.recv(1000)

    # See what we have
    #print output

    # Turn off paging
    disable_paging(remote_conn)

    # Now let's try to send the router a command
    remote_conn.send("\n")
    remote_conn.send("conf t\n")
    remote_conn.send("int Eth141/1/1\n")
    remote_conn.send("desc test-desc\n")
    remote_conn.send("sw ac vlan 3301\n")

    time.sleep(1)

    output = remote_conn.recv(5000)
    #print output
