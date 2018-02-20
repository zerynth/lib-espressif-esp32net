"""
.. module:: esp32wifi

*****************
ESP32 Wifi Module
*****************

This module implements the Zerynth driver for the Espressif ESP32 Wi-Fi chip (`Resources and Documentation <https://esp-idf.readthedocs.io/en/latest/api-reference/wifi/index.html>`_).
This module supports SoftAP mode and SSL/TLS

    """




@native_c("_espwifi_init",["csrc/wifi_ifc.c"],["VHAL_WIFI"],[])
def _hwinit():
    pass


def auto_init():
    init()

def init():
    """
.. function:: init()  
        
        initializes the Wi-Fi chip connected to the device.
        
        The WiFi chip is setup and can be managed using the :ref:`Wi-Fi Module <stdlib_wifi>` of the Zerynth Standard Library.      
            
    """
    _hwinit()
    __builtins__.__default_net["wifi"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__


@native_c("esp32_wifi_link",[],[])
def link(ssid,sec,password):
    pass

@native_c("esp32_wifi_is_linked",[],[])
def is_linked():
    pass


@native_c("esp32_wifi_scan",["csrc/*"])
def scan(duration):
    pass

@native_c("esp32_wifi_unlink",["csrc/*"])
def unlink():
    pass


@native_c("esp32_net_link_info",[])
def link_info():
    pass

@native_c("esp32_net_set_link_info",[])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("esp32_net_resolve",["csrc/*"])
def gethostbyname(hostname):
    pass


@native_c("esp32_net_socket",["csrc/*"])
def socket(family,type,proto):
    pass

@native_c("esp32_net_setsockopt",["csrc/*"])
def setsockopt(sock,level,optname,value):
    pass


@native_c("esp32_net_close",["csrc/*"])
def close(sock):
    pass


@native_c("esp32_net_sendto",["csrc/*"])
def sendto(sock,buf,addr,flags=0):
    pass

@native_c("esp32_net_send",["csrc/*"])
def send(sock,buf,flags=0):
    pass

@native_c("esp32_net_send_all",["csrc/*"])
def sendall(sock,buf,flags=0):
    pass


@native_c("esp32_net_recv_into",["csrc/*"])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass


@native_c("esp32_net_recvfrom_into",["csrc/*"])
def recvfrom_into(sock,buf,bufsize,flags=0):
    pass


@native_c("esp32_net_bind",["csrc/*"])
def bind(sock,addr):
    pass

@native_c("esp32_net_listen",["csrc/*"])
def listen(sock,maxlog=2):
    pass

@native_c("esp32_net_accept",["csrc/*"])
def accept(sock):
    pass

@native_c("esp32_net_connect",["csrc/*"])
def connect(sock,addr):
    pass

@native_c("esp32_net_select",[])
def select(rlist,wist,xlist,timeout):
    pass


@native_c("esp32_softap_init",["csrc/*"])
def softap_init(ssid,sec,password,max_conn):
    pass

@native_c("esp32_softap_config",["csrc/*"])
def softap_config(ip,gw,net):
    pass

@native_c("esp32_turn_ap_off",["csrc/*"])
def softap_off():
    pass

@native_c("esp32_turn_station_on",["csrc/*"])
def station_on():
    pass

@native_c("esp32_turn_station_off",["csrc/*"])
def station_off():
    pass

@native_c("esp32_softap_get_info",["csrc/*"])
def softap_get_info():
    pass

@native_c("esp32_wifi_rssi",[])
def get_rssi():
    """
.. function:: get_rssi()

    Returns the current RSSI in dBm

    """
    pass


@native_c("esp32_secure_socket",[],[])
def secure_socket(family, type, proto, ctx):
    pass
