#!/usr/bin/env python


##### WAN IP UPDATER #####
#
# This script should be run automatically via cron and update tunnel config
# with the current WAN IP address, as our ISP changes the IP on
# disconnect/reconnect.
#
# Currently, reluctantly, using Python 2, as that's the default Python on
# Ubiquiti EdgeOS at the moment. Queue complaining and shaming on 2020-01-01!
#
# Written by zmw, 201912
# Last Updated: 20200302T192100Z



# IMPORT LIBRARIES
import signal
import sys
import os
import subprocess
import json
import requests



# Silently exit upon user interruption (e.g. ctrl-c)
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError: Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # KeyboardInterrupt: Ctrl-C
sys.tracebacklimit=0 # System error handling



# Define Command Wrappers
wrap_conf = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper '
wrap_oper = '/opt/vyatta/bin/vyatta-op-cmd-wrapper '
wrap_cli_api = 'cli-shell-api '



# Functions for getting the current WAN IP, getting a list of tunnel
# interfaces, as well as adding/changing/updating configuration...
def get_wan_ip():
  # Get list of Interfaces and their current IP addresses
  response = os.popen(wrap_oper + 'show interfaces').read()
  # Extract pppoe0 interface IP
  for line in response.splitlines():
    if 'pppoe0' in line:
      get_wan_ip.wan_ip = line.split()[1]

def get_tun_ints():
  response = os.popen(wrap_oper + 'show interfaces').read()
  # Extract tunnel interfaces into a list
  get_tun_ints.tun_ints = []
  for line in response.splitlines():
    if 'tun' in line:
      get_tun_ints.tun_ints.append(line.split()[0])

def configure_router(config_set):
  for cmd in config_set:
    subprocess.call(cmd, shell=True)

def update_he_tunnelbroker():
  # Get HE TunnelBroker credentials, etc. from secrets.json
  with open('secrets.json', 'r') as secrets:
    secrets = json.loads(secrets.read())
    he_username = secrets['he_tunnelbroker']['username']
    he_update_key = secrets['he_tunnelbroker']['update_key']
    he_tunnel_id = secrets['he_tunnelbroker']['tunnel_id']
  # Define HE TunnelBroker Update URI
  he_tunnelbroker_uri = 'https://' + he_username + ':' + he_update_key + '@ipv4.tunnelbroker.net/nic/update?hostname=' + he_tunnel_id + '&myip=' + get_wan_ip.wan_ip 
  # HTTP GET to HE TunnelBroker Update URI to trigger update with specified IP address
  requests.get(he_tunnelbroker_uri)

def centurylink_6rd():
  # Steps:
  # 0. Initial setup of EdgeOS firewall rules, tunnel interface, LAN interface, etc. on router
  # 1. Get v4 WAN IP from pppoe0
  # 2. Calculate v6 RD prefix (/56)
  # 3. Assign address to tunnel interface
  # 4. Assign address to LAN interface
  # 5. Define routes
  # 6. Test connectivity / DONE!



# Main Function
def main():
  # Get current WAN IP address
  get_wan_ip()
  # Get list of tunnel interfaces
  get_tun_ints()
  # Iterate through tunnel interfaces and update local-ip to current WAN IP
  for tun_int in get_tun_ints.tun_ints:
    # Configuration command set
    config_set = [
      wrap_conf + 'begin',
      wrap_conf + 'set interfaces tunnel ' + tun_int + ' local-ip ' + get_wan_ip.wan_ip,
      wrap_conf + 'commit',
      wrap_conf + 'save'
    ]
    # Run configure_router function with config_set
    try:
      configure_router(config_set)
      print(tun_int + ' updated with current WAN IP (' + get_wan_ip.wan_ip + ')')
    except:
      print('Unable to configure ' + tun_int + ' with current WAN IP.')



# RUN MAIN FUNCTION
if __name__ == "__main__":
  main()



# eof
