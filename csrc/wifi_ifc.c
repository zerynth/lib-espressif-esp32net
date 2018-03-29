#include "zerynth.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/api.h"
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#undef printf
//#define printf(...) vbl_printf_stdout(__VA_ARGS__)
#define printf(...)

#define CHECK_RES() (esp_err != ESP_OK)

#define STATUS_IDLE 0
#define STATUS_LINKING 1
#define STATUS_UNLINKING 2
#define STATUS_STOPPING 3
#define STATUS_APLINKING 4

#define ERROR_CANT_CONNECT 1

#if defined(VHAL_WIFI)

typedef struct _wifidrv {
    VSemaphore link_lock;
    VSemaphore ssl_lock;
    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;
    ip4_addr_t dns;
    uint8_t status;
    uint8_t error;
    uint8_t connected;
    uint8_t has_link_info;
    wifi_mode_t mode;
} WifiDrv;

WifiDrv drv;
#endif

#if defined(VHAL_ETH)

typedef struct _ethdrv {
    VSemaphore link_lock;
    VSemaphore ssl_lock;
    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;
    ip4_addr_t dns;
    uint8_t status;
    uint8_t error;
    uint8_t connected;
    uint8_t has_link_info;
} EthDrv;

EthDrv drv;

#endif


typedef struct _sslsock {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_config conf;
    mbedtls_net_context fd;
    int32_t family;
    int32_t socktype;
    int32_t proto;
    uint8_t assigned;
    uint8_t initialized;
} SSLSock;

#define MAX_SSLSOCKS 2

SSLSock sslsocks[MAX_SSLSOCKS];

#define SSLSOCK_NUM (0xfe + LWIP_SOCKET_OFFSET)

int mbedtls_full_connect(SSLSock* ssock, const struct sockaddr* name, socklen_t namelen);
int mbedtls_full_close(SSLSock* ssock);

#define MBEDTLS_connect(sock, addr, addrlen) mbedtls_full_connect(&sslsocks[(sock)-SSLSOCK_NUM], addr, addrlen)
#define MBEDTLS_send(sock, buf, len, flags) mbedtls_ssl_write(&sslsocks[(sock)-SSLSOCK_NUM].ssl, buf, len)
#define MBEDTLS_recv(sock, buf, len, flags) mbedtls_ssl_read(&sslsocks[(sock)-SSLSOCK_NUM].ssl, buf, len)
#define MBEDTLS_close(sock) mbedtls_full_close(&sslsocks[(sock)-SSLSOCK_NUM]) 

#define NETFN(fun, ...) (sock < SSLSOCK_NUM) ? (lwip_##fun##_r(__VA_ARGS__)) : (MBEDTLS_##fun(__VA_ARGS__))



esp_err_t net_event_handler(void* ctx, system_event_t* event)
{

    switch (event->event_id) {

#if defined(VHAL_WIFI)
    case SYSTEM_EVENT_STA_GOT_IP: {
        drv.ip = event->event_info.got_ip.ip_info.ip;
        drv.gw = event->event_info.got_ip.ip_info.gw;
        drv.mask = event->event_info.got_ip.ip_info.netmask;
        printf("GOT IP %x %x %x\n", drv.ip.addr, drv.gw.addr, drv.mask.addr);
        vosSemSignal(drv.link_lock);
    } break;
    case SYSTEM_EVENT_STA_CONNECTED: {
        printf("Connected\n");
        drv.connected = 1;
    } break;
    case SYSTEM_EVENT_AP_START: {
        if (drv.status == STATUS_APLINKING) {
            vosSemSignal(drv.link_lock);
        }
    } break;
    case SYSTEM_EVENT_STA_STOP:
    case SYSTEM_EVENT_AP_STOP: {
        if (drv.status == STATUS_STOPPING) {
            vosSemSignal(drv.link_lock);
        }
    } break;
    case SYSTEM_EVENT_STA_DISCONNECTED: {
        if (drv.status == STATUS_UNLINKING) {
            //requested unlink
            printf("Disconnected\n");
            vosSemSignal(drv.link_lock);
        }
        else if (drv.status == STATUS_LINKING) {
            printf("Can't connect\n");
            drv.error = ERROR_CANT_CONNECT;
            printf("disconnect reason: %d", event->event_info.disconnected.reason);
            vosSemSignal(drv.link_lock);
        }
        else {
            //disconnected, try to reconnect: TODO, do it better with a background thread
            esp_wifi_connect();
        }
        drv.connected = 0;
    } break;
#endif
#if defined(VHAL_ETH)
    case SYSTEM_EVENT_ETH_GOT_IP:{               /**< ESP32 ethernet got IP from connected AP */
        drv.ip = event->event_info.got_ip.ip_info.ip;
        drv.gw = event->event_info.got_ip.ip_info.gw;
        drv.mask = event->event_info.got_ip.ip_info.netmask;
        printf("GOT IP %x %x %x\n", drv.ip.addr, drv.gw.addr, drv.mask.addr);
        vosSemSignal(drv.link_lock);
    }
    break;
    case SYSTEM_EVENT_ETH_CONNECTED:{
        drv.connected = 1;
    } break;
    case SYSTEM_EVENT_ETH_DISCONNECTED:{
        if (drv.status == STATUS_UNLINKING) {
            //requested unlink
            printf("Disconnected\n");
            vosSemSignal(drv.link_lock);
        }
        else if (drv.status == STATUS_LINKING) {
            printf("Can't connect\n");
            printf("disconnect reason: %d", event->event_info.disconnected.reason);
            drv.error = ERROR_CANT_CONNECT;
            vosSemSignal(drv.link_lock);
        } 
        drv.connected = 0;
    } break;
#endif
    default:
        printf("RECEIVED EVENT %i\n", event->event_id);
        break;
    }

    return ESP_OK;
}

#if defined(VHAL_WIFI)
extern wifi_init_config_t _wificfg;
C_NATIVE(_espwifi_init)
{
    NATIVE_UNWARN();
    int err;
    esp_err_t esp_err;

    memset(&drv, 0, sizeof(WifiDrv));
    drv.link_lock = vosSemCreate(0);
    drv.ssl_lock = vosSemCreate(1);
    nvs_flash_init();
    tcpip_adapter_init();
    esp_err = esp_event_loop_init(net_event_handler, NULL);
    if (CHECK_RES())
        return ERR_IOERROR_EXC;

    // wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    printf("CFG %x %x\n",&_wificfg);
    esp_err = esp_wifi_init(&_wificfg);
    if (CHECK_RES())
        return ERR_IOERROR_EXC;
    esp_err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (CHECK_RES())
        return ERR_IOERROR_EXC;
    esp_err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (CHECK_RES())
        return ERR_IOERROR_EXC;
    drv.mode = WIFI_MODE_STA;
    *res = MAKE_NONE();

    return ERR_OK;
}
#endif

#if defined(VHAL_ETH)

#if defined(ESP32_ETH_PHY_LAN8720)
#include "eth_phy/phy_lan8720.h"
#define DEFAULT_ETHERNET_PHY_CONFIG phy_lan8720_default_ethernet_config 
//passed by hwinit as macros
#define PIN_SMI_MDC   CONFIG_PHY_SMI_MDC_PIN
#define PIN_SMI_MDIO  CONFIG_PHY_SMI_MDIO_PIN



static void eth_gpio_config_rmii(void)
{
    // RMII data pins are fixed:
    // TXD0 = GPIO19
    // TXD1 = GPIO22
    // TX_EN = GPIO21
    // RXD0 = GPIO25
    // RXD1 = GPIO26
    // CLK == GPIO0
    phy_rmii_configure_data_interface_pins();
    phy_rmii_smi_configure_pins(PIN_SMI_MDC, PIN_SMI_MDIO);
}

#endif


C_NATIVE(_espeth_init)
{
    NATIVE_UNWARN();
    int err;
    esp_err_t esp_err;

    memset(&drv, 0, sizeof(EthDrv));
    drv.ssl_lock = vosSemCreate(1);
    drv.link_lock = vosSemCreate(0);
    nvs_flash_init();
    tcpip_adapter_init();
    esp_event_loop_init(net_event_handler, NULL);
    
    eth_config_t cfg = DEFAULT_ETHERNET_PHY_CONFIG;
    cfg.phy_addr = 0; //CONFIG_PHY_ADDRESS;
    cfg.gpio_config = eth_gpio_config_rmii;
    cfg.tcpip_input = tcpip_adapter_eth_input;
    cfg.clock_mode = ETH_CLOCK_GPIO0_IN;// CONFIG_PHY_CLOCK_MODE;

    esp_err = esp_eth_init(&cfg);
    if (CHECK_RES())
        return ERR_IOERROR_EXC;
    *res = MAKE_NONE();
    return ERR_OK;
}

#endif

#if defined(VHAL_WIFI)
C_NATIVE(esp32_wifi_link)
{
    NATIVE_UNWARN();

    uint8_t* ssid;
    int sidlen, sec, passlen;
    uint8_t* password;
    int32_t err;
    esp_err_t esp_err;

    *res = MAKE_NONE();

    if (parse_py_args("sis", nargs, args, &ssid, &sidlen, &sec, &password, &passlen) != 3)
        return ERR_TYPE_EXC;

    wifi_config_t sta_config;
    memset(&sta_config, 0, sizeof(sta_config));
    __memcpy(sta_config.sta.ssid, ssid, sidlen);
    __memcpy(sta_config.sta.password, password, passlen);
    sta_config.sta.bssid_set = false;

    RELEASE_GIL();
    esp_err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        printf("- %x\n", esp_err);
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }

    drv.status = STATUS_LINKING;
    if (drv.has_link_info) {
        tcpip_adapter_ip_info_t ip_info;
        ip_info.ip = drv.ip;
        ip_info.gw = drv.gw;
        ip_info.netmask = drv.mask;
        tcpip_adapter_dhcpc_stop(TCPIP_ADAPTER_IF_STA);
        tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_STA, &ip_info);
        dns_setserver(0, &drv.dns);
    }
    else {
        tcpip_adapter_dhcpc_start(TCPIP_ADAPTER_IF_STA);
    }
    esp_err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("* %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    esp_err = esp_wifi_start();
    printf("START\n");
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("** %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    esp_err = esp_wifi_connect();
    printf("CONNECT\n");
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("*** %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    vosSemWait(drv.link_lock);
    drv.status = STATUS_IDLE;
    ACQUIRE_GIL();

    if (drv.error) {
        printf("**** %x\n", esp_err);
        drv.error = 0;
        return ERR_IOERROR_EXC;
    }
    return ERR_OK;
}

C_NATIVE(esp32_wifi_unlink)
{
    NATIVE_UNWARN();
    *res = MAKE_NONE();
    esp_err_t esp_err;

    RELEASE_GIL();
    esp_err = esp_wifi_disconnect();
    if (esp_err != ESP_OK) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }
    drv.status = STATUS_UNLINKING;
    vosSemWait(drv.link_lock);
    ACQUIRE_GIL();

    return ERR_OK;
}

C_NATIVE(esp32_wifi_is_linked)
{
    NATIVE_UNWARN();
    if (!drv.connected) {
        *res = PBOOL_FALSE();
    }
    else {
        *res = PBOOL_TRUE();
    }
    return ERR_OK;
}

C_NATIVE(esp32_wifi_rssi)
{
    NATIVE_UNWARN();
    int32_t rssi;
    wifi_ap_record_t rec;

    RELEASE_GIL();
    esp_wifi_sta_get_ap_info(&rec);
    ACQUIRE_GIL();
    rssi = rec.rssi;
    *res = PSMALLINT_NEW(rssi);
    return ERR_OK;
}


#endif

#if defined(VHAL_ETH)

C_NATIVE(esp32_eth_link)
{
    NATIVE_UNWARN();

    int32_t err;
    esp_err_t esp_err;

    *res = MAKE_NONE();

    RELEASE_GIL();

    esp_eth_enable();
    drv.status = STATUS_LINKING;
    printf("HAS LINK INFO %i\n",drv.has_link_info);
    if (drv.has_link_info) {
        tcpip_adapter_ip_info_t ip_info;
        ip_info.ip = drv.ip;
        ip_info.gw = drv.gw;
        ip_info.netmask = drv.mask;
        tcpip_adapter_dhcpc_stop(TCPIP_ADAPTER_IF_ETH);
        tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_ETH, &ip_info);
        dns_setserver(0, &drv.dns);
    }
    else {
        tcpip_adapter_dhcpc_start(TCPIP_ADAPTER_IF_ETH);
    }
    
    vosSemWait(drv.link_lock);
    drv.status = STATUS_IDLE;
    ACQUIRE_GIL();

    if (drv.error) {
        drv.error = 0;
        printf("**** %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    return ERR_OK;
}


C_NATIVE(esp32_eth_unlink)
{
    NATIVE_UNWARN();
    *res = MAKE_NONE();
    esp_err_t esp_err;

    RELEASE_GIL();
    drv.status = STATUS_UNLINKING;
    esp_err = esp_eth_disable();
    if (esp_err != ESP_OK) {
        ACQUIRE_GIL();
        drv.status = STATUS_IDLE;
        return ERR_IOERROR_EXC;
    }
    vosSemWait(drv.link_lock);
    ACQUIRE_GIL();
    return ERR_OK;
}

C_NATIVE(esp32_eth_is_linked)
{
    NATIVE_UNWARN();
    if (!drv.connected) {
        *res = PBOOL_FALSE();
    }
    else {
        *res = PBOOL_TRUE();
    }
    return ERR_OK;
}

#endif

C_NATIVE(esp32_net_link_info)
{
    NATIVE_UNWARN();

    NetAddress addr;
    addr.port = 0;

    PTuple* tpl = psequence_new(PTUPLE, 5);

    addr.ip = drv.ip.addr;
    PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
    addr.ip = drv.mask.addr;
    PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
    addr.ip = drv.gw.addr;
    PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
    addr.ip = dns_getserver(0).u_addr.ip4.addr; //esp_net_dns.addr;
    PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));

    PObject* mac = psequence_new(PBYTES, 6);
    #if defined(VHAL_WIFI)
    esp_wifi_get_mac(ESP_IF_WIFI_STA, PSEQUENCE_BYTES(mac));
    #else
    esp_eth_get_mac(PSEQUENCE_BYTES(mac));
    #endif
    PTUPLE_SET_ITEM(tpl, 4, mac);
    *res = tpl;

    return ERR_OK;
}


C_NATIVE(esp32_net_set_link_info)
{
    C_NATIVE_UNWARN();

    NetAddress ip;
    NetAddress mask;
    NetAddress gw;
    NetAddress dns;

    if (parse_py_args("nnnn", nargs, args,
            &ip,
            &mask,
            &gw,
            &dns)
        != 4)
        return ERR_TYPE_EXC;

    if (dns.ip == 0) {
        OAL_MAKE_IP(dns.ip, 8, 8, 8, 8);
    }
    if (mask.ip == 0) {
        OAL_MAKE_IP(mask.ip, 255, 255, 255, 255);
    }
    if (gw.ip == 0) {
        OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
    }

    drv.ip.addr = ip.ip;
    drv.gw.addr = gw.ip;
    drv.dns.addr = dns.ip;
    drv.mask.addr = mask.ip;
    if (ip.ip != 0)
        drv.has_link_info = 1;
    else
        drv.has_link_info = 0;

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_net_resolve)
{
    C_NATIVE_UNWARN();
    uint8_t* url;
    uint32_t len;
    int32_t code;
    NetAddress addr;
    if (parse_py_args("s", nargs, args, &url, &len) != 1)
        return ERR_TYPE_EXC;
    addr.ip = 0;
    uint8_t* name = (uint8_t*)gc_malloc(len + 1);
    __memcpy(name, url, len);
    name[len] = 0;
    RELEASE_GIL();
    struct ip4_addr ares;
    code = netconn_gethostbyname(name, &ares);
    ACQUIRE_GIL();
    gc_free(name);
    if (code != ERR_OK)
        return ERR_IOERROR_EXC;
    addr.port = 0;
    addr.ip = ares.addr;
    *res = netaddress_to_object(&addr);
    return ERR_OK;
}

#define DRV_SOCK_DGRAM 1
#define DRV_SOCK_STREAM 0
#define DRV_AF_INET 0

typedef struct sockaddr_in sockaddr_t;

void bcm_prepare_addr(sockaddr_t* vmSocketAddr, NetAddress* addr)
{
    vmSocketAddr->sin_family = AF_INET;
    vmSocketAddr->sin_port = addr->port;
    vmSocketAddr->sin_addr.s_addr = addr->ip;
}
// int errno;

// int* __errno(void)
// {
//     return &errno;
// }

C_NATIVE(esp32_net_socket)
{
    C_NATIVE_UNWARN();
    int32_t family = DRV_AF_INET;
    int32_t type = DRV_SOCK_STREAM;
    int32_t proto = IPPROTO_TCP;
    int32_t sock;
    if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3)
        return ERR_TYPE_EXC;
    if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM)
        return ERR_TYPE_EXC;
    if (family != DRV_AF_INET)
        return ERR_UNSUPPORTED_EXC;
    //printf("--CMD_SOCKET: %i %x\n", errno, (int)lwip_socket);
    RELEASE_GIL();
    // printf("-CMD_SOCKET: %i %x\n", errno, (int)lwip_socket);
    sock = lwip_socket(AF_INET, (type == DRV_SOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM,
        (type == DRV_SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
    ACQUIRE_GIL();
    //printf("CMD_SOCKET: %i %i\n", sock, errno);
    if (sock < 0)
        return ERR_IOERROR_EXC;
    *res = PSMALLINT_NEW(sock);
    printf("etest %x %i\n", (int)lwip_socket, sock);
    return ERR_OK;
}

C_NATIVE(esp32_net_connect)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;

    if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
        return ERR_TYPE_EXC;
    sockaddr_t vmSocketAddr;
    bcm_prepare_addr(&vmSocketAddr, &addr);
    RELEASE_GIL();
    //sock = lwip_connect(sock, &vmSocketAddr, sizeof(vmSocketAddr));
    sock = NETFN(connect, sock, &vmSocketAddr, sizeof(vmSocketAddr));
    ACQUIRE_GIL();
    printf("CMD_OPEN: %i %i\r\n", sock, 0);
    if (sock < 0) {
        if (sock<=MBEDTLS_ERR_X509_INVALID_FORMAT && sock>=MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT){
            return ERR_CONNECTION_ABR_EXC;
        }
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(esp32_net_close)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    int rr;
    if (parse_py_args("i", nargs, args, &sock) != 1)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    rr = NETFN(close, sock);
    printf("closing sock - result %i\n", rr);
    ACQUIRE_GIL();
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(esp32_net_send)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    if (parse_py_args("isi", nargs, args,
            &sock,
            &buf, &len,
            &flags)
        != 3)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    printf("SEND %i %i\n", sock, len);
    sock = NETFN(send, sock, buf, len, flags);
    ACQUIRE_GIL();
    if (sock < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(esp32_net_send_all)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    int32_t wrt;
    int32_t w;
    if (parse_py_args("isi", nargs, args,
            &sock,
            &buf, &len,
            &flags)
        != 3)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    wrt = 0;
    while (wrt < len) {
        w = NETFN(send, sock, buf + wrt, len - wrt, flags);
        if (w < 0)
            break;
        wrt += w;
    }
    ACQUIRE_GIL();
    if (w < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_net_sendto)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("isni", nargs, args,
            &sock,
            &buf, &len,
            &addr,
            &flags)
        != 4)
        return ERR_TYPE_EXC;

    RELEASE_GIL();
    sockaddr_t vmSocketAddr;
    bcm_prepare_addr(&vmSocketAddr, &addr);
    sock = lwip_sendto_r(sock, buf, len, flags, &vmSocketAddr, sizeof(sockaddr_t));
    ACQUIRE_GIL();

    if (sock < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(esp32_net_recv_into)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t sz;
    int32_t flags;
    int32_t ofs;
    int32_t sock;
    //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",args[0],args[1],args[2],args[3],args[4],args[5]);
    if (parse_py_args("isiiI", nargs, args,
            &sock,
            &buf, &len,
            &sz,
            &flags,
            0,
            &ofs)
        != 5)
        return ERR_TYPE_EXC;
    buf += ofs;
    len -= ofs;
    len = (sz < len) ? sz : len;
    RELEASE_GIL();
    int rb = 0;
    int r;
    //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",sock,buf,len,sz,flags,ofs);
    while (rb < len) {
        r = NETFN(recv, sock, buf + rb, len - rb, flags);
        if (r <= 0)
            break;
        rb += r;
    }
    ACQUIRE_GIL();
    //printf("err %i\n",r);
    if (r <= 0) {
        if (r == 0) {
            if (rb < len) {
                return ERR_IOERROR_EXC;
            }
        }
        else {
            if (r == MBEDTLS_ERR_SSL_TIMEOUT || *__errno() == EAGAIN || *__errno() == ETIMEDOUT)
                return ERR_TIMEOUT_EXC;
            return ERR_IOERROR_EXC;
        }
    }
    *res = PSMALLINT_NEW(rb);

    return ERR_OK;
}

C_NATIVE(esp32_net_recvfrom_into)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t sz;
    int32_t flags;
    int32_t ofs;
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("isiiI", nargs, args,
            &sock,
            &buf, &len,
            &sz,
            &flags,
            0,
            &ofs)
        != 5)
        return ERR_TYPE_EXC;
    buf += ofs;
    len -= ofs;
    len = (sz < len) ? sz : len;

    RELEASE_GIL();
    addr.ip = 0;
    int r;
    sockaddr_t vmSocketAddr;
    socklen_t tlen = sizeof(vmSocketAddr);
    r = lwip_recvfrom_r(sock, buf, len, flags, &vmSocketAddr, &tlen);
    ACQUIRE_GIL();
    addr.ip = vmSocketAddr.sin_addr.s_addr;
    addr.port = vmSocketAddr.sin_port;
    if (r < 0) {
        if (r == ETIMEDOUT)
            return ERR_TIMEOUT_EXC;
        return ERR_IOERROR_EXC;
    }
    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 2);
    PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(r));
    PObject* ipo = netaddress_to_object(&addr);
    PTUPLE_SET_ITEM(tpl, 1, ipo);
    *res = tpl;
    return ERR_OK;
}

C_NATIVE(esp32_net_setsockopt)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    int32_t level;
    int32_t optname;
    int32_t optvalue;

    if (parse_py_args("iiii", nargs, args, &sock, &level, &optname, &optvalue) != 4)
        return ERR_TYPE_EXC;

    if (level == 0xffff)
        level = SOL_SOCKET;

    // SO_RCVTIMEO zerynth value
    if (optname == 1) {
        optname = SO_RCVTIMEO;
    }

    RELEASE_GIL();
    if (optname == SO_RCVTIMEO && sock >= SSLSOCK_NUM) {
        mbedtls_ssl_conf_read_timeout(&sslsocks[(sock)-SSLSOCK_NUM].conf, optvalue);
    }
    else if (optname == SO_RCVTIMEO) {
        struct timeval tms;
        tms.tv_sec = optvalue / 1000;
        tms.tv_usec = (optvalue % 1000) * 1000;
        sock = lwip_setsockopt_r(sock, level, optname, &tms, sizeof(struct timeval));
    }
    else {
        if (sock >= SSLSOCK_NUM) {
            mbedtls_net_context* ctx = &sslsocks[(sock)-SSLSOCK_NUM].fd;
            sock = ctx->fd;
        }
        sock = lwip_setsockopt_r(sock, level, optname, &optvalue, sizeof(optvalue));
    }
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_net_bind)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
        return ERR_TYPE_EXC;
    sockaddr_t serverSocketAddr;
    //addr.ip = bcm_net_ip.addr;
    bcm_prepare_addr(&serverSocketAddr, &addr);
    RELEASE_GIL();
    sock = lwip_bind_r(sock, &serverSocketAddr, sizeof(sockaddr_t));
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_net_listen)
{
    C_NATIVE_UNWARN();
    int32_t maxlog;
    int32_t sock;
    if (parse_py_args("ii", nargs, args, &sock, &maxlog) != 2)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    maxlog = lwip_listen_r(sock, maxlog);
    ACQUIRE_GIL();
    if (maxlog)
        return ERR_IOERROR_EXC;
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_net_accept)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("i", nargs, args, &sock) != 1)
        return ERR_TYPE_EXC;
    sockaddr_t clientaddr;
    socklen_t addrlen;
    memset(&clientaddr, 0, sizeof(sockaddr_t));
    addrlen = sizeof(sockaddr_t);
    RELEASE_GIL();
    sock = lwip_accept_r(sock, &clientaddr, &addrlen);
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;
    addr.port = clientaddr.sin_port;
    addr.ip = clientaddr.sin_addr.s_addr;

    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 2);
    PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(sock));
    PObject* ipo = netaddress_to_object(&addr);
    PTUPLE_SET_ITEM(tpl, 1, ipo);
    *res = tpl;
    return ERR_OK;
}

C_NATIVE(esp32_net_select)
{
    C_NATIVE_UNWARN();
    int32_t timeout;
    int32_t tmp, i, j, sock = -1;

    if (nargs < 4)
        return ERR_TYPE_EXC;

    fd_set rfd;
    fd_set wfd;
    fd_set xfd;
    struct timeval tms;
    struct timeval* ptm;
    PObject* rlist = args[0];
    PObject* wlist = args[1];
    PObject* xlist = args[2];
    fd_set* fdsets[3] = { &rfd, &wfd, &xfd };
    PObject* slist[3] = { rlist, wlist, xlist };
    PObject* tm = args[3];

    if (tm == MAKE_NONE()) {
        ptm = NULL;
    }
    else if (IS_PSMALLINT(tm)) {
        timeout = PSMALLINT_VALUE(tm);
        if (timeout < 0)
            return ERR_TYPE_EXC;
        tms.tv_sec = timeout / 1000;
        tms.tv_usec = (timeout % 1000) * 1000;
        ptm = &tms;
    }
    else
        return ERR_TYPE_EXC;

    for (j = 0; j < 3; j++) {
        tmp = PTYPE(slist[j]);
        if (!IS_OBJ_PSEQUENCE_TYPE(tmp))
            return ERR_TYPE_EXC;
        FD_ZERO(fdsets[j]);
        for (i = 0; i < PSEQUENCE_ELEMENTS(slist[j]); i++) {
            PObject* fd = PSEQUENCE_OBJECTS(slist[j])[i];
            if (IS_PSMALLINT(fd)) {
                //printf("%i -> %i\n",j,PSMALLINT_VALUE(fd));
                FD_SET(PSMALLINT_VALUE(fd), fdsets[j]);
                if (PSMALLINT_VALUE(fd) > sock)
                    sock = PSMALLINT_VALUE(fd);
            }
            else
                return ERR_TYPE_EXC;
        }
    }

    printf("maxsock %i\n", sock);
    RELEASE_GIL();
    tmp = lwip_select((sock + 1), fdsets[0], fdsets[1], fdsets[2], ptm);
    ACQUIRE_GIL();

    printf("result: %i\n", tmp);

    if (tmp < 0) {
        return ERR_IOERROR_EXC;
    }

    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 3);
    for (j = 0; j < 3; j++) {
        tmp = 0;
        for (i = 0; i <= sock; i++) {
            if (FD_ISSET(i, fdsets[j]))
                tmp++;
        }
        PTuple* rtpl = psequence_new(PTUPLE, tmp);
        tmp = 0;
        for (i = 0; i <= sock; i++) {
            //printf("sock %i in %i = %i\n",i,j,FD_ISSET(i, fdsets[j]));
            if (FD_ISSET(i, fdsets[j])) {
                PTUPLE_SET_ITEM(rtpl, tmp, PSMALLINT_NEW(i));
                tmp++;
            }
        }
        PTUPLE_SET_ITEM(tpl, j, rtpl);
    }
    *res = tpl;
    return ERR_OK;
}

#if defined(VHAL_WIFI)

C_NATIVE(esp32_wifi_scan)
{
    C_NATIVE_UNWARN();
    int32_t time;
    int32_t i;
    uint16_t m;
    esp_err_t esp_err;

    if (parse_py_args("i", nargs, args, &time) != 1)
        return ERR_TYPE_EXC;

    RELEASE_GIL();
    wifi_scan_config_t ssconf;
    wifi_ap_record_t* rec;
    memset(&ssconf, 0, sizeof(wifi_scan_config_t));

    esp_err = esp_wifi_start();
    printf("START\n");
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("** %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    esp_err = esp_wifi_scan_start(&ssconf, true);
    if (CHECK_RES()) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }

    esp_err = esp_wifi_scan_get_ap_num(&m);
    if (CHECK_RES()) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }

    *res = ptuple_new(m, NULL);
    rec = gc_malloc(m * sizeof(wifi_ap_record_t));
    esp_err = esp_wifi_scan_get_ap_records(&m, rec);
    if (CHECK_RES()) {
        ACQUIRE_GIL();
        gc_free(rec);
        return ERR_IOERROR_EXC;
    }

    for (i = 0; i < m; i++) {
        PTuple* tpl = ptuple_new(4, NULL);
        PString* ssid = pstring_new(strlen(rec[i].ssid), rec[i].ssid);
        PBytes* bssid = pbytes_new(6, rec[i].bssid);
        int mode = (rec[i].authmode >= WIFI_AUTH_WPA_WPA2_PSK) ? 3 : (int)rec[i].authmode;
        PTUPLE_SET_ITEM(tpl, 0, ssid);
        PTUPLE_SET_ITEM(tpl, 1, PSMALLINT_NEW(mode));
        PTUPLE_SET_ITEM(tpl, 2, PSMALLINT_NEW(rec[i].rssi));
        PTUPLE_SET_ITEM(tpl, 3, bssid);
        PTUPLE_SET_ITEM(*res, i, tpl);
    }
    esp_err = esp_wifi_scan_stop();
    if (CHECK_RES()) {
        ACQUIRE_GIL();
        gc_free(rec);
        return ERR_IOERROR_EXC;
    }

    gc_free(rec);
    ACQUIRE_GIL();

    return ERR_OK;
}

C_NATIVE(esp32_turn_station_on)
{
    C_NATIVE_UNWARN();
    esp_err_t esp_err;

    if (drv.mode != WIFI_MODE_STA) {
        printf("turn off ap\n");
        RELEASE_GIL();
        drv.status = STATUS_STOPPING;
        esp_err = esp_wifi_stop();
        if (!CHECK_RES())
            vosSemWait(drv.link_lock);
        ACQUIRE_GIL();
        if (CHECK_RES())
            return ERR_IOERROR_EXC;
        drv.connected = 0;
        drv.status = STATUS_IDLE;
        drv.mode = WIFI_MODE_STA;
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_turn_station_off)
{
    C_NATIVE_UNWARN();
    esp_err_t esp_err;

    if (drv.mode == WIFI_MODE_STA) {
        printf("turn off station\n");
        RELEASE_GIL();
        drv.status = STATUS_STOPPING;
        esp_err = esp_wifi_stop();
        if (!CHECK_RES())
            vosSemWait(drv.link_lock);
        ACQUIRE_GIL();
        if (CHECK_RES())
            return ERR_IOERROR_EXC;
        drv.connected = 0;
        drv.status = STATUS_IDLE;
        drv.mode = WIFI_MODE_AP;
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(esp32_softap_init)
{
    NATIVE_UNWARN();
    uint8_t* ssid;
    int sidlen, sec, passlen, max_conn;
    uint8_t* password;
    int32_t err;
    esp_err_t esp_err;

    *res = MAKE_NONE();

    if (parse_py_args("sisi", nargs, args,
            &ssid, &sidlen,
            &sec,
            &password, &passlen,
            &max_conn)
        != 4)
        return ERR_TYPE_EXC;

    //printf("args: %s %s %i %i\n", ssid, password, sidlen, passlen);

    drv.mode = WIFI_MODE_AP;
    RELEASE_GIL();
    esp_err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (CHECK_RES()) {
        ACQUIRE_GIL();
        printf("ERR %i\n", esp_err);
        return ERR_IOERROR_EXC;
    }

    wifi_config_t ap_config;
    memset(&ap_config, 0, sizeof(ap_config));
    __memcpy(ap_config.ap.ssid, ssid, sidlen);
    ap_config.ap.ssid_len = sidlen;
    __memcpy(ap_config.ap.password, password, passlen);
    ap_config.ap.password[passlen] = 0;
    ap_config.ap.authmode = (sec <= 2) ? (wifi_auth_mode_t)sec : WIFI_AUTH_WPA_WPA2_PSK;
    ap_config.ap.max_connection = max_conn;
    ap_config.ap.beacon_interval = 1000;

    drv.status = STATUS_APLINKING;
    if (drv.has_link_info) {
        tcpip_adapter_ip_info_t ip_info;
        ip_info.ip = drv.ip;
        ip_info.gw = drv.gw;
        ip_info.netmask = drv.mask;
        tcpip_adapter_dhcps_stop(TCPIP_ADAPTER_IF_AP);
        tcpip_adapter_set_ip_info(TCPIP_ADAPTER_IF_AP, &ip_info);
    }
    tcpip_adapter_dhcps_start(TCPIP_ADAPTER_IF_AP);

    esp_err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("+ERR %x\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    esp_err = esp_wifi_start();
    if (CHECK_RES()) {
        drv.status = STATUS_IDLE;
        ACQUIRE_GIL();
        printf("++ERR %i\n", esp_err);
        return ERR_IOERROR_EXC;
    }
    vosSemWait(drv.link_lock);
    drv.connected = 1;
    drv.status = STATUS_IDLE;
    tcpip_adapter_ip_info_t ip_info;
    tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_AP, &ip_info);
    drv.ip = ip_info.ip;
    drv.gw = ip_info.gw;
    drv.mask = ip_info.netmask;

    ACQUIRE_GIL();

    return ERR_OK;
}

C_NATIVE(esp32_softap_config)
{
    NATIVE_UNWARN();
    NetAddress ip, gw, mask;

    if (parse_py_args("nnn", nargs, args,
            &ip,
            &gw,
            &mask)
        != 3)
        return ERR_TYPE_EXC;

    if (drv.connected)
        return ERR_IOERROR_EXC;

    if (mask.ip == 0) {
        OAL_MAKE_IP(mask.ip, 255, 255, 255, 0);
    }
    if (gw.ip == 0) {
        OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
    }

    drv.ip.addr = ip.ip;
    drv.gw.addr = gw.ip;
    drv.mask.addr = mask.ip;
    drv.has_link_info = 1;

    *res = MAKE_NONE();

    return ERR_OK;
}

C_NATIVE(esp32_softap_get_info)
{
    NATIVE_UNWARN();

    NetAddress addr;
    addr.port = 0;

    PTuple* tpl = psequence_new(PTUPLE, 4);

    addr.ip = drv.ip.addr;
    PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
    addr.ip = drv.mask.addr;
    PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
    addr.ip = drv.gw.addr;
    PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));

    PObject* mac = psequence_new(PBYTES, 6);
    esp_wifi_get_mac(ESP_IF_WIFI_AP, PSEQUENCE_BYTES(mac));
    PTUPLE_SET_ITEM(tpl, 3, mac);
    *res = tpl;

    return ERR_OK;
}

C_NATIVE(esp32_turn_ap_off)
{
    C_NATIVE_UNWARN();
    esp_err_t esp_err;

    if (drv.mode == WIFI_MODE_AP) {
        printf("turn off ap\n");
        RELEASE_GIL();
        drv.status = STATUS_STOPPING;
        esp_err = esp_wifi_stop();
        if (!CHECK_RES())
            vosSemWait(drv.link_lock);
        ACQUIRE_GIL();
        if (CHECK_RES())
            return ERR_IOERROR_EXC;
        drv.connected = 0;
        drv.status = STATUS_IDLE;
        drv.mode = WIFI_MODE_STA;
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

#endif

#define _CERT_NONE 1
#define _CERT_OPTIONAL 2
#define _CERT_REQUIRED 4
#define _CLIENT_AUTH 8
#define _SERVER_AUTH 16

C_NATIVE(esp32_secure_socket)
{
    C_NATIVE_UNWARN();
    int32_t err = ERR_OK;
    int32_t family = DRV_AF_INET;
    int32_t type = DRV_SOCK_STREAM;
    int32_t proto = IPPROTO_TCP;
    int32_t sock;
    int32_t i;
    int32_t ssocknum = 0;
    int32_t ctxlen;
    uint8_t* certbuf = NULL;
    uint16_t certlen = 0;
    uint8_t* clibuf = NULL;
    uint16_t clilen = 0;
    uint8_t* pkeybuf = NULL;
    uint16_t pkeylen = 0;
    uint32_t options = _CLIENT_AUTH | _CERT_NONE;
    uint8_t* hostbuf = NULL;
    uint16_t hostlen = 0;

    PTuple* ctx;
    ctx = (PTuple*)args[nargs - 1];
    nargs--;
    if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3){
      printf("G\n");
        return ERR_TYPE_EXC;
    }
    if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM){
      printf("GG\n");
        return ERR_TYPE_EXC;
    }
    if (family != DRV_AF_INET)
        return ERR_UNSUPPORTED_EXC;
    ctxlen = PSEQUENCE_ELEMENTS(ctx);
    if (ctxlen && ctxlen != 5)
        return ERR_TYPE_EXC;

    if (ctxlen) {
        //ssl context passed
        PObject* cacert = PTUPLE_ITEM(ctx, 0);
        PObject* clicert = PTUPLE_ITEM(ctx, 1);
        PObject* ppkey = PTUPLE_ITEM(ctx, 2);
        PObject* host = PTUPLE_ITEM(ctx, 3);
        PObject* iopts = PTUPLE_ITEM(ctx, 4);
        certbuf = PSEQUENCE_BYTES(cacert);
        certlen = PSEQUENCE_ELEMENTS(cacert);
        clibuf = PSEQUENCE_BYTES(clicert);
        clilen = PSEQUENCE_ELEMENTS(clicert);
        hostbuf = PSEQUENCE_BYTES(host);
        hostlen = PSEQUENCE_ELEMENTS(host);
        pkeybuf = PSEQUENCE_BYTES(ppkey);
        pkeylen = PSEQUENCE_ELEMENTS(ppkey);
        options = PSMALLINT_VALUE(iopts);
    }

    SSLSock* sslsock = NULL;

    RELEASE_GIL();
    vosSemWait(drv.ssl_lock);
    for (i = 0; i < MAX_SSLSOCKS; i++) {
        sslsock = &sslsocks[i];
        if (!sslsock->assigned) {
            ssocknum = SSLSOCK_NUM + i;
            break;
        }
    }
    if (!ssocknum) {
        err = ERR_IOERROR_EXC;
        goto exit;
    }

    sslsock->family = AF_INET;
    sslsock->socktype = (type == DRV_SOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM;
    sslsock->proto = (type == DRV_SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;


    if (!sslsock->initialized) {
        mbedtls_ssl_init(&sslsock->ssl);
        mbedtls_x509_crt_init(&sslsock->cacert);
        mbedtls_x509_crt_init(&sslsock->clicert);
        mbedtls_pk_init(&sslsock->pkey);
        mbedtls_ctr_drbg_init(&sslsock->ctr_drbg);
        mbedtls_ssl_config_init(&sslsock->conf);
        mbedtls_entropy_init(&sslsock->entropy);
        if ((err = mbedtls_ctr_drbg_seed(&sslsock->ctr_drbg, mbedtls_entropy_func, &sslsock->entropy, vhalNfoGetUIDStr(), vhalNfoGetUIDLen())) != 0) {
            printf("-%i\n", err);
            err = ERR_RUNTIME_EXC;
            goto exit;
        }

        if (certlen) {
            err = mbedtls_x509_crt_parse(&sslsock->cacert, certbuf, certlen);
            printf("CERT %i\n",err);
            if (err!=0) {
                err = ERR_VALUE_EXC;
                goto exit;
            }
        }

        if (hostlen && certlen) {
            /* Hostname set here should match CN in server certificate */
            uint8_t *temphost = gc_malloc(hostlen+1);
            __memcpy(temphost,hostbuf,hostlen);
            temphost[hostlen]=0;
            err = mbedtls_ssl_set_hostname(&sslsock->ssl, temphost);
            gc_free(temphost);
            if (err!=0){
                printf("-+%i\n", err);
                err = ERR_RUNTIME_EXC;
                goto exit;
            }
        }

        // ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

        if ((err = mbedtls_ssl_config_defaults(&sslsock->conf,
                 (options&_CLIENT_AUTH) ? MBEDTLS_SSL_IS_SERVER:MBEDTLS_SSL_IS_CLIENT,
                 MBEDTLS_SSL_TRANSPORT_STREAM,
                 MBEDTLS_SSL_PRESET_DEFAULT))
            != 0) {
            printf("--%i\n", err);
            err = ERR_RUNTIME_EXC;
            goto exit;
        }
        mbedtls_ssl_conf_authmode(&sslsock->conf, (options&_CERT_NONE) ? MBEDTLS_SSL_VERIFY_NONE: ((options&_CERT_OPTIONAL) ? MBEDTLS_SSL_VERIFY_OPTIONAL:MBEDTLS_SSL_VERIFY_REQUIRED));
        if (!(options&_CERT_NONE)) mbedtls_ssl_conf_ca_chain(&sslsock->conf, &sslsock->cacert, NULL);
        if (clilen && pkeylen) {
            err = mbedtls_pk_parse_key(&sslsock->pkey,pkeybuf,pkeylen,NULL,0);
            printf("PKEY %i\n",err);
            if (err) {
                err = ERR_VALUE_EXC;
                goto exit;
            }
            err = mbedtls_x509_crt_parse(&sslsock->clicert, clibuf, clilen);
            printf("CCERT %i\n",err);
            if (err) {
                err = ERR_VALUE_EXC;
                goto exit;
            }

            err = mbedtls_ssl_conf_own_cert(&sslsock->conf,&sslsock->clicert,&sslsock->pkey);
            printf("OCERT %i\n",err);
            if (err) {
                err = ERR_VALUE_EXC;
                goto exit;
            }
        }
        mbedtls_ssl_conf_rng(&sslsock->conf, mbedtls_ctr_drbg_random, &sslsock->ctr_drbg);

        if ((err = mbedtls_ssl_setup(&sslsock->ssl, &sslsock->conf)) != 0) {
            printf("---%i\n", err);
            err = ERR_RUNTIME_EXC;
            goto exit;
        }
        sslsock->initialized = 1;
    }

    mbedtls_net_context* netctx = &sslsock->fd;

    mbedtls_net_init(netctx);
    netctx->fd = (int)lwip_socket(sslsock->family, sslsock->socktype, sslsock->proto);
    if (netctx->fd < 0) {
        mbedtls_entropy_free(&sslsock->conf);
        mbedtls_ssl_config_free(&sslsock->conf);
        mbedtls_ctr_drbg_free(&sslsock->ctr_drbg);
        mbedtls_x509_crt_free(&sslsock->cacert);
        mbedtls_x509_crt_free(&sslsock->clicert);
        mbedtls_pk_free(&sslsock->pkey);
        mbedtls_ssl_free(&sslsock->ssl);
        sslsock->initialized = 0;
        err = MBEDTLS_ERR_NET_SOCKET_FAILED;
        goto exit;
    }

    sslsock->assigned = 1;
    err = ERR_OK;
exit:

    ACQUIRE_GIL();
    vosSemSignal(drv.ssl_lock);

    *res = PSMALLINT_NEW(ssocknum);
    return err;
}

int mbedtls_full_close(SSLSock* ssock){

    vosSemWait(drv.ssl_lock);
    mbedtls_ssl_close_notify(&ssock->ssl);
    mbedtls_ssl_session_reset(&ssock->ssl); 
    mbedtls_net_free(&ssock->fd);

    if (ssock->initialized) {
        //destroy and recreate
        mbedtls_entropy_free(&ssock->conf);
        mbedtls_ssl_config_free(&ssock->conf);
        mbedtls_ctr_drbg_free(&ssock->ctr_drbg);
        mbedtls_x509_crt_free(&ssock->cacert);
        mbedtls_x509_crt_free(&ssock->clicert);
        mbedtls_pk_free(&ssock->pkey);
        mbedtls_ssl_free(&ssock->ssl);
        ssock->initialized = 0;
    }
    ssock->assigned=0;
    vosSemSignal(drv.ssl_lock);
    return 0;
}

int mbedtls_full_connect(SSLSock* ssock, const struct sockaddr* name, socklen_t namelen)
{
    int ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    mbedtls_net_context* ctx = &ssock->fd;

    if (lwip_connect_r(ctx->fd, name, namelen) != 0) {
        mbedtls_net_free(ctx);
        lwip_close_r(ctx->fd);
        return MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    mbedtls_ssl_set_bio(&ssock->ssl, ctx, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    while ((ret = mbedtls_ssl_handshake(&ssock->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_ssl_session_reset(&ssock->ssl);
            mbedtls_net_free(ctx);
            printf("FAILED with %i\n",ret);
            return ret;
        }
    }

    // ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    
    // if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    // {
    //     /* In real life, we probably want to close connection if ret != 0 */
    //     ESP_LOGW(TAG, "Failed to verify peer certificate!");
    //     bzero(buf, sizeof(buf));
    //     mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
    //     ESP_LOGW(TAG, "verification info: %s", buf);
    // }
    // else {
    //     ESP_LOGI(TAG, "Certificate verified.");
    // }

    return 0;
}