#!/usr/bin/env python

##### WAN IP UPDATER #####
#
# This script should be run automatically via cron and update tunnel config
# with the current WAN IPv4 address, as our ISP changes the DHCP IP on
# disconnect/reconnect.
#
# Currently, reluctantly, using Python 2, as that's the default Python on
# Ubiquiti EdgeOS at the moment. Queue complaining and shaming on 2020-01-01!
#
# Written by zmw, 201912
# Last Updated: 20200303T201026Z


# IMPORT LIBRARIES
import json
import os
#import requests
import signal
import subprocess
import sys


# Silently exit upon user interruption (e.g. ctrl-c)
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError: Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # KeyboardInterrupt: Ctrl-C
sys.tracebacklimit=0 # System error handling


# Define Command Wrappers
wrap_conf = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper '
wrap_oper = '/opt/vyatta/bin/vyatta-op-cmd-wrapper '
wrap_cli_api = 'cli-shell-api '


# GET CURRENT WAN IP
def get_wan_ip():
  # Using Linux CLI, get current info for pppoe0 interface
  ip_output = os.popen('ip -4 a show pppoe0').read().split('\n')
  # Extract just the IPv4 address
  wan_ip = [item for item in ip_output if 'inet' in item][0].strip().split(' ')[1]
  # Return WAN IP
  return wan_ip


# GET LIST OF TUNNEL INTERFACES
def get_tun_ifaces():
  response = os.popen(wrap_oper + 'show interfaces').read()
  # Extract tunnel interfaces into a list
  tun_ifaces = []
  for line in response.splitlines():
    if 'tun' in line:
      tun_ifaces.append(line.split()[0])
  # Return list of tunnel interfaces
  return tun_ifaces


# EDGEOS CONFIGURATION FUNCTION
def configure_router(config_set):
  for cmd in config_set:
    subprocess.call(cmd, shell=True)


# UPDATE HURRICANE ELECTRIC TUNNELBROKER WITH CURRENT WAN IP
def update_he_tunnelbroker():
  # Get HE TunnelBroker credentials, etc. from secrets.json
  with open('secrets.json', 'r') as secrets:
    secrets = json.loads(secrets.read())
    he_username = secrets['he_tunnelbroker']['username']
    he_update_key = secrets['he_tunnelbroker']['update_key']
    he_tunnel_id = secrets['he_tunnelbroker']['tunnel_id']
  # Get current WAN IPv4 address
  wan_ip = get_wan_ip()
  # Define HE TunnelBroker Update URI
  he_tunnelbroker_uri = 'https://' + he_username + ':' + he_update_key + '@ipv4.tunnelbroker.net/nic/update?hostname=' + he_tunnel_id + '&myip=' + wan_ip 
  # HTTP GET to HE TunnelBroker Update URI to trigger update with specified IP address
  requests.get(he_tunnelbroker_uri)


# CENTURYLINK FIBER 6RD CONFIG UPDATES
def centurylink_6rd():
  # 0. Initial setup of EdgeOS firewall rules, tunnel interface, LAN interface, etc. on router
  # 1. Get v4 WAN IP from pppoe0 & calculate v6 RD prefix (/56) and other v6 addresses
  # 2. Assign addresses to tunnel & LAN interfaces
  # 3. Define routes & test connectivity
  #
  # Get current WAN IPv4 address
  wan_ip = get_wan_ip()
  # Split IPv4 address into octets
  v4parts = wan_ip.split('.')
  # Define IPv6 address parts as a list and begin with '2602', as that will always be the first
  # part of the resulting IPv6 address
  v6parts = ['2602']
  # Iterate through octets and convert to hexadecimal (without '0x' prefix)
  for octet in v4parts:
    v6parts.append('{0:x}'.format(int(octet)))
  # Iterate through v6parts list, identifying the index (idx) and value (val)
  for idx, val in enumerate(v6parts):
    # Process indexes 2 and 3 only
    if 1 < idx < 5:
      # Pad with a prepending '0' if the length of the value is less than 2
      if len(val) < 2:
        v6parts[idx] = '0' + val
  # Base IPv6 block to build other subnets from
  myv6_base = v6parts[0] + ':' + v6parts[1] + ':' + v6parts[2] + v6parts[3] + ':' +  v6parts[4] + '00'
  # Entire /56 prefix
  myv6_prefix = myv6_base + '::' + '/56'
  # Tunnel interface /128
  myv6_wan_128 = myv6_base + '::1/128'
  # Generate LAN /64s (doing 3x here, but only using the first one)
  myv6_lan_64_1 = myv6_base[:-1] + '1::/64'
  myv6_lan_64_2 = myv6_base[:-1] + '2::/64'
  myv6_lan_64_3 = myv6_base[:-1] + '3::/64'
  # Build a dictionary of the values to be returned when running this function
  cl_6rd_dict = {
    'v4wan': wan_ip,
    'v6rdtun': myv6_wan_128,
    'v6lan1': myv6_lan_64_1
  }
  # Return dict of generated values
  return cl_6rd_dict


# MAIN FUNCTION
def main():
  # Get current WAN IP address
  wan_ip = get_wan_ip()
  # Get list of tunnel interfaces
  tun_ifaces = get_tun_ifaces()
  # Iterate through tunnel interfaces and update local-ip to current WAN IP
  for tun_iface in tun_ifaces:
    # Configuration command set
    config_set = [
      wrap_conf + 'begin',
      wrap_conf + 'set interfaces tunnel ' + tun_iface + ' local-ip ' + wan_ip,
      wrap_conf + 'commit',
      wrap_conf + 'save'
    ]
    # Run configure_router function with config_set
    try:
      configure_router(config_set)
      print(tun_iface + ' updated with current WAN IP (' + wan_ip + ')')
    except:
      print('Unable to configure ' + tun_iface + ' with current WAN IP.')


# RUN MAIN FUNCTION
if __name__ == "__main__":
  main()


# eof