################################################################################
# Wifi SoftAP Example
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
print("Creating Access Point...")
try:
    wifi.softap_init("ESP32",wifi.WIFI_WPA2,"ZerynthEsp32")
    print("Access Point started!")
    while True:
        info = wifi.softap_get_info()
        mac = ":".join([hex(x,"") for x in info[3]])
        print(info[0],info[1],info[2],mac)
        sleep(3000)

except Exception as e:
    print("ooops, something :(", e)
    while True:
        sleep(1000)
