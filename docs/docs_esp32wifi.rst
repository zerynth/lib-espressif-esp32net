.. module:: esp32wifi

*****************
ESP32 Wifi Module
*****************

This module implements the Zerynth driver for the Espressif ESP32 Wi-Fi chip (`Resources and Documentation <https://esp-idf.readthedocs.io/en/latest/api-reference/wifi/index.html>`_).
This module supports SoftAP mode and SSL/TLS. It also support promiscuous mode for wifi packet sniffing.

    
.. function:: init()  
        
        initializes the Wi-Fi chip connected to the device.
        
        The WiFi chip is setup and can be managed using the :ref:`Wi-Fi Module <stdlib_wifi>` of the Zerynth Standard Library.      
            
    
.. function:: get_rssi()

    Returns the current RSSI in dBm

    
.. function:: start_sniffer(packet_types=[], direction=0xf, channels=[], mgmt_subtypes=[], ctrl_subtypes=[], data_subtypes=[], hop_time=5000, pkt_buffer=32, max_payloads=4096)

    Start the wifi sniffer or change its configuration if already started.
    The sniffer itself is very flexible and configurable by means of type, subtype and direction filters.
    Wifi packets from `IEEE 802.11 specification <https://en.wikipedia.org/wiki/IEEE_802.11>`_ can be of management, control or data types, each type implementing a different functionality of the standard.

    The argument :samp:`packet_types` is a list of types represented by the constants :samp:`WIFI_PKT_MGMT`, :samp:`WIFI_PKT_CTRL` and :samp:`WIFI_PKT_DATA`. If :samp:`packet_types` is empty, the sniffer is configured by default  with :samp:`WIFI_PKT_MGMT` considering only management packets.

    For each packet type, many different subtypes are possible according to the specification. The sniffer can be configured to only collect a subset of the allowed subtypes. To do so, three different argument can be specified to control the subsets:

    * :samp:`mgmt_subtypes`, a list of management packet subtypes (if empty sniffs probe requests and response)
    * :samp:`ctrl_subtypes`, a list of control packet subtypes (if empty sniffs control ack)
    * :samp:`data_subtypes`, a list of data packet subtypes

    Subtypes are specified with the integer value of the subtypes in the packet `frame <https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html>`_. A number of constants is provided to specify packet subtypes, reported below.

    Wifi packets also have two bits indicating the "direction" of the packet, either from or to the distribution system (DS). The distribution system is generally the Access Point that behaves as the physical bridge between the wireless network and another network, usually ethernet based. The two direction bits are usually called "from_ds" and "to_ds" meaning that the packet is coming from the DS and going to the DS respectively. Since management and control packets never leave the wireless network, the two bits are always 00. For data packets they usually are either 10 or 01 for packets entering or leaving the network. The case 11 is also possible for WDS systems where multiple wifi networks are organized together for packet routing. More details `here <https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/>`_. The sniffer can be configured to selectively filter only packets with a certain direction by providing the :samp:`direction` argument. It is a bitmask of the following constants:

    * :samp:`WIFI_DIR_TO_NULL_FROM_NULL`, for 00 direction
    * :samp:`WIFI_DIR_TO_DS_FROM_NULL`, for 10 direction, packets leaving the network
    * :samp:`WIFI_DIR_TO_NULL_FROM_DS`, for 01 direction, packets entering the network
    * :samp:`WIFI_DIR_TO_DS_FROM_DS`, for 11 direction, packets entering/leaving the network in a WDS system

    The sniffer can only sniff one channel at a time. To work around this limitation is possible to specify a list of :samp:`channels` in the range [1..14] and a :samp:`hop_time` in milliseconds. The sniffer will listen on each channel in :samp:`channels` for :samp:`hop_time` before jumping to the next.

    Sniffing packets can be a memory intensive task because both the high rate of packet traffic and the size of each packet that can reach 2Kb. It is possible to configure the sniffer memorywise by specifying the number of packets headers to retain in memory (:samp:`pkt_buffer`) and how much memory reserve to packet payloads (the actual data contained in the packet) :samp:`max_payloads`. The sniffer will keep collecting headers until :samp:`pkt_buffer` packets are buffered, discarding all the incoming packets if the buffer is full. The packet payload is buffered only if there is enough memory in the payload memory pool. It is therefore possible to sniff packet with complete headers but missing payloads if the memory pool is full but the packet buffer is not.

    To remove packet from the buffer and free up memory it is necessary to read them with :function:`sniff()` or :function:`sniff_raw()`.

    By calling this function again it is possible to reconfigure the sniffer. At each reconfiguration, the packet buffer and payload memory pool are emptied and the channel index restarted.


    Here below the list of constants for specifying packet subtypes:

    * :samp:`WIFI_PKT_MGMT_ASSOC_REQ`, association request
    * :samp:`WIFI_PKT_MGMT_ASSOC_RES`, association response
    * :samp:`WIFI_PKT_MGMT_REASSOC_REQ`, reassociation request
    * :samp:`WIFI_PKT_MGMT_REASSOC_RES`, reassociation response
    * :samp:`WIFI_PKT_MGMT_PROBE_REQ`, probe request
    * :samp:`WIFI_PKT_MGMT_PROBE_RES`, probe response
    * :samp:`WIFI_PKT_MGMT_TIMING_ADV`, timing advertisment
    * :samp:`WIFI_PKT_MGMT_BEACON`, AP beacon
    * :samp:`WIFI_PKT_MGMT_ATIM`, announcement traffic indication
    * :samp:`WIFI_PKT_MGMT_DISASSOC`, disassociation event
    * :samp:`WIFI_PKT_MGMT_AUTH`, authentication event
    * :samp:`WIFI_PKT_MGMT_DEAUTH`, deauthentication event
    * :samp:`WIFI_PKT_MGMT_ACTION`, action
    * :samp:`WIFI_PKT_MGMT_ACTION_NACK`, action no ack
    * :samp:`WIFI_PKT_CTRL_PSPOLL`, power saving poll
    * :samp:`WIFI_PKT_CTRL_RTS`, request to send
    * :samp:`WIFI_PKT_CTRL_CTS`, clear to send
    * :samp:`WIFI_PKT_CTRL_ACK`, ack
    * :samp:`WIFI_PKT_CTRL_CFEND`, cfp end frame
    * :samp:`WIFI_PKT_CTRL_CFEND_ACK`, cfp end frame ack
    * :samp:`WIFI_PKT_DATA_DATA`, data packet
    * :samp:`WIFI_PKT_DATA_DATA_CFACK`, data packet with cf ack
    * :samp:`WIFI_PKT_DATA_DATA_CFPOLL`, data packet with cf poll
    * :samp:`WIFI_PKT_DATA_DATA_CFPOLL_ACK`, data packet with cf poll ack
    * :samp:`WIFI_PKT_DATA_NULLDATA`, data packet with no data (usually keepalives)
    * :samp:`WIFI_PKT_DATA_NULLDATA_CFACK`, data packet with no data with cf ack
    * :samp:`WIFI_PKT_DATA_NULLDATA_CFPOLL`, data packet with no data with cf poll
    * :samp:`WIFI_PKT_DATA_NULLDATA_CFPOLL_ACK`, data packet with no data with cf poll ack
    * :samp:`WIFI_PKT_DATA_QOS`, data packet for qos
    * :samp:`WIFI_PKT_DATA_QOS_CFACK`, data packet for qos with cf ack
    * :samp:`WIFI_PKT_DATA_QOS_CFPOLL`, data packet for qos with cf poll
    * :samp:`WIFI_PKT_DATA_QOS_CFPOLL_ACK`, data packet for qos with cf poll ack
    * :samp:`WIFI_PKT_DATA_NULLQOS`, data packet with no data for qos
    * :samp:`WIFI_PKT_DATA_NULLQOS_CFPOLL`, data packet with no data for qos with cf poll
    * :samp:`WIFI_PKT_DATA_QOS_CFPOLL_ACK`, data packet with no data for qos with cf poll ack

    
.. function:: get_sniffer_stats()

    Return a tuple with sniffer statistics:

    * number of sniffed packets since last start
    * number of management packets that did not match a management subtype filter
    * number of control packets that did not match a control subtype filter
    * number of data packets that did not match a data subtype filter
    * number of packets that did not match the direction filter
    * number of packets missed due to buffer full
    * number of packets in the buffer
    * number of bytes used up in the payload memory pool
    * current sniffer channel

    Filters are applied in a specific order: direction filter first and then subtype filter. 

    
.. function:: sniff_raw()

    Return a list of sniffed packets from the underlying packet buffer.

    Each packet is itself a list with the following items:

    * an integer representing the packet type
    * an integer representing the packet subtype
    * an integer representing the to_ds bit
    * an integer representing the from_ds bit
    * an integer representing the remaining packet flags
    * an integer representing the duration_id field of the packet
    * an integer representing the sequence control field of the packet
    * a bytes of 6 elements representing the mac address 1
    * a bytes of 6 elements representing the mac address 2 
    * a bytes of 6 elements representing the mac address 3
    * a bytes of 6 elements representing the mac address 4
    * an integer representing the RSSI
    * an integer representing the channel
    * an integer representing the payload size
    * a bytes of either payload size elements or zero elements (if not enough space in memory pool was available)

    The values of packet type and subtype match the :samp:`WIFI_PKT_` constants described above.

    The semantic of addresses changes based on samp:`to_ds` and :samp:`from_ds` bits and message type/subtype.
    In general one it can be assumed that:

    * for :samp:`to_ds` 0 and :samp:`from_ds` 0:
        * address 1 is the destination MAC
        * address 2 is the source MAC
        * address 3 is the BSSID (the MAC of the AP)
    * for :samp:`to_ds` 1 and :samp:`from_ds` 0: 
        * address 1 is the BSSID
        * address 2 is the source MAC
        * address 3 is the destination MAC (outside the wifi network)
    * for :samp:`to_ds` 0 and :samp:`from_ds` 1: 
        * address 1 is the destination MAC
        * address 2 is the BSSID
        * address 3 is the source MAC (outside the wifi network)
    * for :samp:`to_ds` 1 and :samp:`from_ds` 1:
        * address 1 is the receiver MAC (inside the wifi WDS network)
        * address 2 is the transmitter MAC (inside the wifi WDS network)
        * address 3 is the destination MAC (outside the wifi WDS network)
        * address 4 is the source MAC (outside the wifi WDS network)

    Payload size is always specified in the packet tuple. However it is possible, if the memory pool for payload is exhausted, that the actual payload is not present.

    The returned list of packets is usually as big as the number of packets in the buffer and never exceeds that amount.

    
.. function:: sniff()

    The same as sniff_raw, except that the addresses are returned as hexadecimal strings in the format AA:BB:CC:DD:EE:FF.

    
.. function:: stop_sniffer()

    Stops the sniffer and free buffer and pool memory.

    
