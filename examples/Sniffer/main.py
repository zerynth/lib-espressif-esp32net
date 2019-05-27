################################################################################
# Wifi Sniffer
#
# Created at 2019-05-08 15:19:21.114503
#
################################################################################

import streams
from espressif.esp32net import esp32wifi as wifi_driver


try:
    streams.serial()
    #let's init the driver
    wifi_driver.auto_init()
except Exception as e:
    print("ooops, something wrong with the driver", e)
    while True:
        sleep(1000)

try:

    while True:
        # loop over all channels
        for channel in  [1,2,3,4,5,6,7,8,9,10,11,12,13,14]:
            print("Sniffing channel",channel)
            print("================")
            # start the sniffer for management and data packets
            # on the current channel
            # filtering packets going in and out of DS, and also packets with no direction
            # keep a buffer of 128 packets
            # but don't store the payloads (max_payloads=0)
            wifi_driver.start_sniffer(
                packet_types=[wifi_driver.WIFI_PKT_DATA,wifi_driver.WIFI_PKT_MGMT],
                channels = [channel],
                direction = wifi_driver.WIFI_DIR_TO_DS_FROM_NULL | wifi_driver.WIFI_DIR_TO_NULL_FROM_DS | wifi_driver.WIFI_DIR_TO_NULL_FROM_NULL,
                pkt_buffer=128,
                max_payloads=0)

            # The sniffer is sniffing :)
            # let's loop for 10 seconds on each channel
            seconds = 0
            while seconds<10:
                sleep(1000)
                seconds+=1
                pkts = wifi_driver.sniff()
                for pkt in pkts:
                    print(pkt[:-1])  # print everything except the payload
                # let's also check some sniffing stats 
                print("Stats",wifi_driver.get_sniffer_stats())

            # This is not necessary, we can go back to the loop and call start_sniffer again
            # but let's call stop nonetheless
            wifi_driver.stop_sniffer()

except Exception as e:
    print(e)
