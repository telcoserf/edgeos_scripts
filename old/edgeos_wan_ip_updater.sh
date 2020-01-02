#!/bin/vbash

##### WAN IP UPDATER #####
#
# This script should be run automatically via cron and update tunnel config
# with the current WAN IP address, as our ISP changes the IP on
# disconnect/reconnect.
#
# Written by zmw, 201912
# Last Updated: 20191227T014736Z



### Get current WAN IP from interface pppoe0

# Set source file to vyatta script-template
source /opt/vyatta/etc/functions/script-template

# Run CLI command and use grep/sed to clean up output
wan_ip=`run show interfaces pppoe pppoe0 | grep 'inet' | sed -e 's/inet\(.*\)peer.*/\1/'`



### Get a list of all tunnel interfaces

# Run CLI command and use grep/uniq/sed to clean up output
tun_ints=`run show configuration commands | grep -o 'set interfaces tunnel tun[0-9]*' | uniq | sed 's/^.*tun/tun/'`



### Set tunnel interface local-ip to 'wan_ip'

# Enter configuratin mode
configure

# Loop through all interfaces in $tun_ints
for i in $tun_ints
do
  # Set tunnel interface local-ip to $wan_ip
  set interfaces tunnel $i local-ip $wan_ip
done

# Commit & save configuration
commit; save



# eof