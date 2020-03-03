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
# Last Updated: 20200303T033130Z


# IMPORT LIBRARIES
import fcntl
import json
import os
#import requests
import signal
import socket
import struct
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
  #
  # Use socket, fcntl & struct libraries to obtain WAN IP
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  # Return IPv4 WAN IP address
  ipv4addr = socket.inet_ntoa(
    fcntl.ioctl(
      s.fileno(),
      0x8915, # SIOCGIFADDR
      struct.pack('256s', 'pppoe0'[:15]) # Change from pppoe0 if using another interface
    )[20:24]
  )
  # Split IPv4 address into octets
  v4parts = ipv4addr.split('.')
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
  myv6_prefix = v6parts[0] + ':' + v6parts[1] + ':' + v6parts[2] + v6parts[3] + ':' +  v6parts[4] + '00'
  # Entire /56 prefix
  myv6_block = myv6_prefix + '::' + '/56'
  # Tunnel interface /128
  myv6_wan_128 = myv6_prefix + '::1/128'
  # 1st LAN /64
  myv6_lan_64_1 = myv6_prefix[:-1] + '1::/64'
  # 2nd LAN /64
  myv6_lan_64_2 = myv6_prefix[:-1] + '2::/64'
  # 3rd LAN /64
  myv6_lan_64_3 = myv6_prefix[:-1] + '3::/64'
  # Build a dictionary of the values to be returned when running this function
  cl_6rd_dict = {
    'v4addr': ipv4addr,
    'v6tunnel': myv6_wan_128,
    'v6lan': myv6_lan_64_1
  }
  # Return dict
  return cl_6rd_dict


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