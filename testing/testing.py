#!/usr/bin/env python


##### testing.py #####
#
# Test functions, etc. for edgeos
#
# Written by zmw, 202001
# Last Updated: 20200102T193253Z



# IMPORT LIBRARIES
import signal
import sys
import os
import subprocess



# Silently exit upon user interruption (e.g. ctrl-c)
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError: Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # KeyboardInterrupt: Ctrl-C
sys.tracebacklimit=0 # System error handling



# Define Command Wrappers
wrap_conf = '/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper '
wrap_oper = '/opt/vyatta/bin/vyatta-op-cmd-wrapper '
wrap_cli_api = 'cli-shell-api '



# FUNCTIONS FOR GETTING INFORMATION (SHOW COMMANDS)

def get_ints_config():
  # Get current interface configuration
  response = os.popen(wrap_conf + 'show interfaces').read()
  get_ints_config.ints_config = response.splitlines()
  # FOR DEBUGGING
  #print('Interface Configuration:')
  #for line in get_ints_config.ints_config: print(line)
  #print()

def get_edgeos_ver():
  # Get current EdgeOS version information
  response = os.popen(wrap_oper + 'show version').read()
  # Extract version number (similar to '| match Version')
  for line in response.splitlines():
    if 'Version:' in line:
      get_edgeos_ver.edgeos_ver = line.split()[1]
  # FOR DEBUGGING
  #print('EdgeOS Version: ' + get_edgeos_ver.edgeos_ver)
  #print()

def get_ospfv3_config():
  # Get OSPFv3 protocol configuration
  response = os.popen(wrap_cli_api + 'showCfg protocols ospfv3').read()
  # FOR DEBUGGING
  #print('OSPFv3 Configuration:')
  #print(response)
  #print()

def get_wan_ip():
  # Get list of Interfaces and their current IP addresses
  response = os.popen(wrap_oper + 'show interfaces').read()
  # Extract pppoe0 interface IP
  for line in response.splitlines():
    if 'pppoe0' in line:
      get_wan_ip.wan_ip = line.split()[1]
  # FOR DEBUGGING
  #print('WAN IP Address: ' + wan_ip)
  #print()

def get_tun_ints():
  response = os.popen(wrap_oper + 'show interfaces').read()
  # Extract tunnel interfaces into a list
  get_tun_ints.tun_ints = []
  for line in response.splitlines():
    if 'tun' in line:
      get_tun_ints.tun_ints.append(line.split()[0])
  # FOR DEBUGGING
  #print('Tunnel Interfaces: ' + str(tun_ints))
  #print()



# FUNCTIONS FOR CHANGING/UPDATING CONFIGURATION

def configure_router(config_set):
  for cmd in config_set:
    subprocess.call(cmd, shell=True)



# MAIN FUNCTION

def main():
  pass



# RUN MAIN FUNCTION
if __name__ == "__main__":
  main()



# eof