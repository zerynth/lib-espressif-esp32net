"""
.. module:: esp32eth

*********************
ESP32 Ethernet Module
*********************

This module implements the Zerynth driver for the Espressif ESP32 Ethernet (`Resources and Documentation <https://esp-idf.readthedocs.io/en/latest/api-reference/wifi/index.html>`_).
This module supports SSL/TLS

    """




@native_c("_espeth_init",
    [
        #-if ZERYNTH_SSL
        "#csrc/misc/zstdlib.c",
        #-endif
        "#csrc/zsockets/*",
        "#csrc/hwcrypto/*",
        "csrc/wifi_ifc.c",
        "csrc/cbuild.json"
    ],
    [
        "VHAL_ETH",
        "CONFIG_PHY_SMI_MDC_PIN=23",
        "CONFIG_PHY_SMI_MDIO_PIN=18"
    ],
    [
        "-I.../csrc",
        "-I#csrc/zsockets",
        "-I#csrc/hwcrypto"
    ]
)
def _hwinit():
    pass

def auto_init():
    init()

def init():
    """
..  function:: init()

    Initializes the Ethernet chip connected to the device.

    The Ethernet chip is setup and can be managed using the :ref:`Ethernet Module <stdlib_eth>` of the Zerynth Standard Library.
    """
    _hwinit()
    __builtins__.__default_net["eth"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__


@native_c("esp32_eth_link",[],[])
def link():
    pass

@native_c("esp32_eth_is_linked",[],[])
def is_linked():
    pass


@native_c("esp32_eth_unlink",["csrc/*"])
def unlink():
    pass


@native_c("esp32_net_link_info",[])
def link_info():
    pass

@native_c("esp32_net_set_link_info",[])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("py_net_resolve",["csrc/*"])
def gethostbyname(hostname):
    pass


@native_c("py_net_socket",["csrc/*"])
def socket(family,type,proto):
    pass

@native_c("py_net_setsockopt",["csrc/*"])
def setsockopt(sock,level,optname,value):
    pass


@native_c("py_net_close",["csrc/*"])
def close(sock):
    pass


@native_c("py_net_sendto",["csrc/*"])
def sendto(sock,buf,addr,flags=0):
    pass

@native_c("py_net_send",["csrc/*"])
def send(sock,buf,flags=0):
    pass

@native_c("py_net_send_all",["csrc/*"])
def sendall(sock,buf,flags=0):
    pass


@native_c("py_net_recv_into",["csrc/*"])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass


@native_c("py_net_recvfrom_into",["csrc/*"])
def recvfrom_into(sock,buf,bufsize,flags=0):
    pass


@native_c("py_net_bind",["csrc/*"])
def bind(sock,addr):
    pass

@native_c("py_net_listen",["csrc/*"])
def listen(sock,maxlog=2):
    pass

@native_c("py_net_accept",["csrc/*"])
def accept(sock):
    pass

@native_c("py_net_connect",["csrc/*"])
def connect(sock,addr):
    pass

@native_c("py_net_select",[])
def select(rlist,wist,xlist,timeout):
    pass

@native_c("py_secure_socket",[],[])
def secure_socket(family, type, proto, ctx):
    pass
