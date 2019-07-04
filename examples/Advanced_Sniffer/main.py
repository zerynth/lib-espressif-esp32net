################################################################################
# Advanced Wifi Sniffer
#
# Created at 2019-05-08 15:19:21.114503
#
################################################################################


import streams
from espressif.esp32net import esp32wifi as wifi_driver


try:
    streams.serial()
    wifi_driver.auto_init()
except Exception as e:
    print("ooops, something wrong while linking :(", e)
    while True:
        sleep(1000)

try:
    # configure the sniffer for probe requests
    # on all channels
    # stay on each channel for 4 seconds
    # 32 probes buffer
    # also save payloads (up to a total of 8Kb)
    # they can be analyzed to gather more  information on identities
    wifi_driver.start_sniffer(
        packet_types=[wifi_driver.WIFI_PKT_MGMT],
        channels = [1,2,3,4,5,6,7,8,9,10,11,12,13],
        mgmt_subtypes=[wifi_driver.WIFI_PKT_MGMT_PROBE_REQ],
        direction = wifi_driver.WIFI_DIR_TO_NULL_FROM_NULL,
        pkt_buffer=32,
        max_payloads=8192,
        hop_time=4000)


    identities = {}
    while True:
        seconds = 0
        # gather probe request packet for 60 seconds
        while seconds<60:
            sleep(1000)
            seconds+=1
            pkts = wifi_driver.sniff()
            for pkt in pkts:
                payload = pkt[-1]
                # being a to_ds 0, from_ds 0 packet, address 2 is the source mac
                # identifying the wifi station
                source = pkt[8]  # source mac of the station probing the network
                # get also the rssi value
                rssi = pkt[11]
                # print the packet without payload
                print(pkt[:-1])
                if source not in identities:
                    # add the current rssi to the new source
                    identities[source]=rssi
                else:
                    # average the previous rssi with the new one
                    # Note: don't do this if you have moving stations, like smartphones on people :)
                    identities[source]=(identities[source]+rssi)//2


        # 60 seconds finished, display a summary
        print("Identities summary")
        print("=========================================")
        print("Mac               |  rssi  |  distance  | ")
        print("=========================================")
        for mac, rssis in identities.items():
            # calculate distance using rssi: http://tdmts.net/2017/02/04/using-wifi-rssi-to-estimate-distance-to-an-access-point/
            d = 10** ((-84 - rssis) / (10 * 4))
            print(mac,"   ",rssis,"    %2.2f"%d)
        print("=========================================")



except Exception as e:
    print(e)
