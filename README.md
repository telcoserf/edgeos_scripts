# edgeos_scripts

## What is this?
* A collection of scripts to perform certain functions on and/or add abilities to Ubiquiti EdgeOS/EdgeMax/EdgeRouter devices

## Major Tools
* edgeos_wan_ip_updater.py
  - This script should be run automatically via cron and update tunnel config with the current WAN IP address, as our ISP changes the IP on disconnect/reconnect.
  - Will soon add the ability to update HE Tunnelbroker with the current WAN IP as well, so that we can automate re-establishing tunnel/BGP connectivity with them.

