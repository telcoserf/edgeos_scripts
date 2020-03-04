#!/usr/bin/env python

##### WAN IP UPDATER #####
#
# This script should be run automatically via cron and update tunnel config with the current WAN
# IPv4 address, as our ISP changes the DHCP IP on disconnect/reconnect.
#
# Currently, reluctantly, using Python 2, as that's the default Python on Ubiquiti EdgeOS at the
# moment. Queue complaining and shaming on 2020-01-01!
#
# Written by zmw, 201912
# Last Updated: 20200303T235132Z


# IMPORT LIBRARIES
import json
import os
import signal
import subprocess
import sys


# Silently exit upon user interruption (e.g. ctrl-c)
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError: Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # KeyboardInterrupt: Ctrl-C
sys.tracebacklimit=0 # System error handling


# Define your interfaces
wan_iface = 'pppoe0'
lan_iface = 'eth1.11'

# Determine WAN interface type
if wan_iface:
  try:
    if 'pppoe' in wan_iface:
      wan_iface_type = 'pppoe'
    elif 'eth' in wan_iface:
      wan_iface_type = 'ethernet'
    elif 'tun' in wan_iface:
      wan_iface_type = 'tunnel'
  except:
    print('Please specify a WAN interface (e.g. pppoe0, eth0, tun0, etc.) -- quitting!')
    sys.exit()

# Determine if LAN interface has a subinterface/vif
if lan_iface:
  try:
    if '.' in lan_iface:
      lan_subiface = 'vif ' + lan_iface.split('.')[1]
    else:
      lan_subiface = ''
  except:
    print('Please specify a LAN interface (e.g. eth1 or eth1.11, etc.) -- quitting!')
    sys.exit()


# Define Command Wrappers, used to pass commands to EdgeOS in the correct mode and translating
# based on each different context
wrap_conf = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper '
wrap_oper = '/opt/vyatta/bin/vyatta-op-cmd-wrapper '
wrap_cliapi = 'cli-shell-api '


# EDGEOS CONFIGURATION FUNCTION
def edgeos_conf(config_set):
  for cmd in config_set:
    subprocess.call(wrap_conf + cmd, shell=True)


# EDGEOS OPERATIONAL ("SHOW") COMMANDS FUNCTION
def edgeos_oper(command):
  oper_output = os.popen(wrap_oper + command).read()
  return oper_output


# EDGEOS CLI SHELL API FUNCTION
def edgeos_cli_api(command):
  subprocess.call(wrap_cliapi + command, shell=True)


# GET CURRENT WAN IP
def get_wan_ip():
  # Using EdgeOS CLI, get current info for pppoe0 interface and split on newlines
  iface_output = edgeos_oper('show interfaces pppoe pppoe0').split('\n')
  # Extract just the IPv4 address by stripping out whitespace at the beginning, splitting on spaces,
  # and grabbing index 1 (1st item after 'iface' in normal 'show interface <type> <iface>' output)
  wan_ip = [item for item in iface_output if 'inet' in item][0].strip().split(' ')[1]
  # Return WAN IP
  return wan_ip


# GET LIST OF TUNNEL INTERFACES
def get_tun_ifaces():
  tun_output = edgeos_oper('show interfaces tunnel').splitlines()
  # Extract tunnel interfaces into a list
  tun_ifaces = []
  for line in tun_output:
    if 'tun' in line:
      tun_ifaces.append(line.split()[0])
  # Return list of tunnel interfaces
  return tun_ifaces


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
  he_tunnelbroker_uri = ('https://' + he_username + ':' + he_update_key +
    '@ipv4.tunnelbroker.net/nic/update?hostname=' + he_tunnel_id + '&myip=' + wan_ip) 
  # HTTP GET to HE TunnelBroker Update URI to trigger update with specified IP address
  requests.get(he_tunnelbroker_uri)
  # ^ ^ ^ ^ ^
  # Python requests library is NOT installed in EdgeOS by default -- need an alternative solution


# CENTURYLINK FIBER 6RD CONFIG UPDATES
def centurylink_6rd():
  # Steps:
  # 0. Initial setup of EdgeOS firewall rules, tunnel interface, LAN interface, etc. on router
  # 1. Get v4 WAN IP from pppoe0 & calculate v6 RD prefix (/56) and other v6 addresses
  # 2. Assign addresses to tunnel & LAN interfaces
  # 3. Define routes & test connectivity
  #
  # Get current WAN IPv4 address
  wan_ip = get_wan_ip()
  # Split IPv4 address into octets
  octets = wan_ip.split('.')
  # Define IPv6 address groups as a list and begin with '2602', as our resulting address will
  # always begin with that
  hextets = ['2602']
  # Iterate through octets and convert to hexadecimal (without '0x' prefix)
  for octet in octets:
    hextets.append('{0:x}'.format(int(octet)))
  # Iterate through hextets list, identifying the index (idx) and value (val)
  for idx, val in enumerate(hextets):
    # Process indexes 2 and 3 only
    if 1 < idx < 5:
      # Pad with a prepending '0' if the length of the value is less than 2
      if len(val) < 2:
        hextets[idx] = '0' + val
  # Base IPv6 block to build other subnets from
  myv6_base = (hextets[0] + ':' + hextets[1] + ':' + hextets[2] + hextets[3] + ':' + hextets[4] +
    '00')
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
  # Generate IPv6 RD subnets
  cl_6rd_dict = centurylink_6rd()
  ## Iterate through tunnel interfaces and update local-ip to current WAN IP <-- NO LONGER
  ## NECESSARY, as we are using '0.0.0.0' as the local-ip for each tun interface, which uses the
  ## current IPv4 WAN IP automatically
  #for tun_iface in tun_ifaces:
  #  # Configuration command set
  #  config_set = [
  #    'begin',
  #    'set interfaces tunnel ' + tun_iface + ' local-ip ' + wan_ip,
  #    'commit',
  #    'save'
  #  ]
  #  # Run edgeos_conf function with config_set
  #  try:
  #    edgeos_conf(config_set)
  #    print(tun_iface + ' updated with current WAN IP (' + wan_ip + ')')
  #  except:
  #    print('Unable to configure ' + tun_iface + ' with current WAN IP.')


# RUN MAIN FUNCTION
if __name__ == "__main__":
  main()


# eof