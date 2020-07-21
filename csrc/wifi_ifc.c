#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/api.h"
#include "lwip/ip_addr.h"
// #include "zerynth_hwcrypto.h"
#include "zerynth.h"
#include "zerynth_sockets.h"

#undef printf
// #define printf(...) vbl_printf_stdout(__VA_ARGS__)
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
        drv.connected = 0;
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
            printf("Reconnecting\n");
            esp_wifi_connect();
        }
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

    // init_socket_api_pointers();
    gzsock_init(NULL);
    // memset(sockinfo,0xff,sizeof(sockinfo));

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

    // init_socket_api_pointers();
    gzsock_init(NULL);
    // memset(sockinfo,0xff,sizeof(sockinfo));

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
    drv.status = STATUS_UNLINKING;
    esp_err = esp_wifi_disconnect();
    if (esp_err != ESP_OK) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }
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
    int32_t sem_status;
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

    sem_status = vosSemWaitTimeout(drv.link_lock, TIME_U(7, SECONDS));

    drv.status = STATUS_IDLE;
    ACQUIRE_GIL();

    if (sem_status == VRES_TIMEOUT) {
        printf("Timeout: Can't get IP addr\n");
        return ERR_TIMEOUT_EXC;
    }

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
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

#endif
