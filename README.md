nstat.py 0.2
=====
author: Julian Barnett // jbarnett@tableau.com

nstat.py is a command line tool used to determine the network device and port a host is connected to.

Pre-Requisites:

You must install the following modules (available via pip). Script will fail without these:

colorama
paramiko


Manage credentials and server details via environment variables:

*nix
export CISCO_USER=<username>
export CISCO_PASS=<password>

windows
set CISCO_USER=<username>
set CISCO_PASS=<password>

Type python nstat.py --help for more information.
