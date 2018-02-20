################################################################################
# Wifi Network Connection Example
#
# Created: 2016-07-27 11:00:55.020628
#
################################################################################

import streams

# import the wifi interface
from wireless import wifi

# import wifi support
from espressif.esp32net import esp32wifi as wifi_driver

streams.serial()

# init the wifi driver!
# The driver automatically registers itself to the wifi interface
# with the correct configuration for the selected device
wifi_driver.auto_init()

# use the wifi interface to link to the Access Point
# change network name, security and password as needed
print("Establishing Link...")
try:
    # FOR THIS EXAMPLE TO WORK, "Network-Name" AND "Wifi-Password" MUST BE SET
    # TO MATCH YOUR ACTUAL NETWORK CONFIGURATION
    wifi.link("Network-name",wifi.WIFI_WPA2,"password")
    print("Link Established")
except Exception as e:
    print("ooops, something wrong while linking :(", e)
    while True:
        sleep(1000)
