#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/api.h"
#include "lwip/ip_addr.h"
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "zerynth_hwcrypto.h"
#include "zerynth.h"
#include "zerynth_sockets.h"
#include "zerynth_ssl.h"

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

// Number of total WiFi channels following the IEEE 802.11 norm (in Europe)
#define TOTAL_WIFI_CHANNELS 13

/////////////////// Promiscuous mode


/*
 * Some reources to understand formats:
 * - https://en.wikipedia.org/wiki/802.11_Frame_Types
 * - https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
 * - https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/
 * - https://docs.espressif.com/projects/esp-idf/en/v3.2/api-reference/wifi/esp_wifi.html#_CPPv425wifi_promiscuous_filter_t
 * - https://blog.podkalicki.com/wp-content/uploads/2017/01/esp32_promiscuous_pkt_structure.jpeg
*/


/*
 * Sniffer architecture
 *
 * A Ring buffer holds sniffed packets interesting data (hdr, rssi, channel, payload size, payload pointer)
 *
 * Packets are first filtered in the esp32 callback by checking subtypes and direction. If the subfilter passes,
 * they are put into the ring buffer. If it is full, packets starts to be discarded. If there is enough memory from the
 * payload memory pool, the payload is copied into newly allocated memory. Otherwise only the hdr is saved into the ring buffer.
 *
 * Packets are removed from the ring buffer when polled by python. Upon removal from ring buffer, the payload memory is freed.
 *
 * The implementation IS NOT THREAD SAFE = only one Python thread at a time can call the .sniffed() function.
 *
 */


// A MAC PDU structure (addresses change semantic based on to_ds, from_ds)
typedef struct {
	uint8_t protocol:2;
	uint8_t type:2;
	uint8_t subtype:4;
    uint8_t to_ds:1;
    uint8_t from_ds:1;
    uint8_t flags:6;
	uint16_t duration_id;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	uint16_t sequence_ctrl;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

// Wifi packet = PDU + DATA
typedef struct {
	wifi_ieee80211_mac_hdr_t hdr;	// Packet header
	uint8_t payload[0];				// network data ended with 4 bytes csum (CRC32)
} wifi_ieee80211_packet_t;


// Single Ring buffer entry
typedef struct _ring_entry {
	wifi_ieee80211_mac_hdr_t hdr;	// Packet header
    int8_t rssi;					// Packet RSSI
    uint8_t channel;				// Channel the packet was read from
    uint16_t payload_size;			// Size of the frame body of the packet
    uint8_t * payload;				// Actual data of the packet
} RingEntry;


// Sniffer struct
typedef struct _prom_str {
    uint8_t active;         // Sniffer state (active/inactive)
    uint8_t pkt_types;      // Bit mask for packet type filtering
    uint8_t channel;        // Current channel the sniffer is sniffing on
    uint8_t direction;      // Selected directions: 00 -> bit0, 01 -> bit1, 10 -> bit2, 11 -> bit3 (to_ds, from_ds)
    uint16_t channels;      // Bit mask of active channels (channel 1 at bit 1, etc..)
    uint16_t mgmt_subtypes; // Bit mask of which subtypes of mgmt packets to return
    uint16_t ctrl_subtypes; // Bit mask of which subtypes of ctrl packets to return
    uint16_t data_subtypes; // Bit mask of which subtypes of data packets to return

    uint16_t rsize;       // Max packets in ring buffer
    uint16_t rhead;       // Head of ring buffer
    uint16_t ritems;      // Items in ring buffer
    uint16_t hop_time;    // Time in milliseconds to listen on each channel before hopping

    uint32_t current_total_payload_size;    // Memory allocated for payloads
    uint32_t max_total_payload_size;        // Max memory that can be allocated for payloads
    uint32_t skipped_mem;                   // Packets skipped due to ring full
    uint32_t skipped_ctrl;                  // Packets skipped due to ctrl subfilter
    uint32_t skipped_data;                  // Packets skipped due to data subfilter
    uint32_t skipped_mgmt;                  // Packets skipped due to mgmt subfilter
    uint32_t skipped_dir;                   // Packets skipped due to direction subfilter
    uint32_t sniffed;                       // Total packets sniffed since last started

    RingEntry * ring;     	// Ring buffer for packets
    VSemaphore ringsem;		// Ring semaphore
    VSysTimer chtimer;   	// Hop timer

} WifiSniffer;


// Global sniffer object
WifiSniffer sniffer;




// ------ RING BUFFER FUNCTIONS ------
// Get ring element at head of ring buffer
RingEntry * _pop_ring_entry ()
{
    RingEntry * ret = NULL;
    // Wait for a semaphore
    vosSemWait(sniffer.ringsem);

    // If ring buffer is not empty
    if (sniffer.ritems > 0) {
        // Get the item that's at the head of the ring buffer
		ret = &sniffer.ring[sniffer.rhead];

        // One item is gone, update counter
        sniffer.ritems--;

        // Head has to move around the buffer
        sniffer.rhead = (sniffer.rhead + 1) % sniffer.rsize;
    }

    // Let semaphore go
    vosSemSignal(sniffer.ringsem);
    // Return the entry
    return ret;
}


// Return number of remaining elements
int _get_ring_entry_count ()
{
    int r;

    vosSemWait(sniffer.ringsem);
    r = sniffer.ritems;
    vosSemSignal(sniffer.ringsem);

    return r;
}


// Add an element to the buffer
void _add_ring_entry (const wifi_promiscuous_pkt_t * ppkt)
{
    RingEntry * ret = NULL;
    int next = 0;

    // Wait for semaphore
    vosSemWait(sniffer.ringsem);

	// If ring buffer isn't full
	if (sniffer.ritems < sniffer.rsize) {
	    // Move `next` to the next available slot
	    next = (sniffer.rhead + sniffer.ritems) % sniffer.rsize;
	    // One item has been added, update counter
	    sniffer.ritems++;
	    // Get the address of element to be added
	    ret = &sniffer.ring[next];

		// Parse the header off of the payload of the promiscuous packet
		wifi_ieee80211_mac_hdr_t * header_data = (wifi_ieee80211_mac_hdr_t *) ppkt->payload;
		__memcpy(&ret->hdr, header_data, sizeof(wifi_ieee80211_mac_hdr_t));
		// Parse the frame body off of the payload of the promiscuous packet
		wifi_ieee80211_packet_t * hdrp = (wifi_ieee80211_packet_t *) ppkt->payload;
		uint8_t * frame_body = (uint8_t *) hdrp->payload;

		// Set RingEntry's channel
	    ret->channel = ppkt->rx_ctrl.channel;
	    // Set RingEntry's RSSI
	    ret->rssi = ppkt->rx_ctrl.rssi;
	    // Set RingEntry's payload size
	    ret->payload_size = ppkt->rx_ctrl.sig_len;
	    // Prepare payload pointer
	    ret->payload = NULL;

	    // Check if there's enough space in the buffer to store the payload
	    if ((sniffer.max_total_payload_size - sniffer.current_total_payload_size) > ret->payload_size) {
	        // We can allocate memory for the payload
	        if (ret->payload_size && frame_body != NULL) {
				// If payload address is valid
				// Get the memory needed for the payload
				ret->payload = gc_malloc(ret->payload_size * sizeof(uint8_t));
	            // Copy the payload data over
				__memcpy(ret->payload, frame_body, ret->payload_size * sizeof(uint8_t));
	            // Update the space used by the payload
				sniffer.current_total_payload_size += ret->payload_size;
	        }
	    } else {
			sniffer.skipped_mem++;
	    }
	}

    // Release semaphore
    vosSemSignal(sniffer.ringsem);
}


// Free ring buffer element
void _destroy_ring_entry (RingEntry * re)
{
    // If the element isn't NULL, free the frame body memory
    if (re)
		if (re->payload) gc_free(re->payload);
}


// Free ring buffer
void _destroy_ring ()
{
	int i = 0;
	int total_entries = _get_ring_entry_count();

	// Free the entries
	for (i = 0; i < total_entries; i++)
		_destroy_ring_entry(_pop_ring_entry());

	// Free the ring
	gc_free(sniffer.ring);
	sniffer.ring = NULL;
}




// Sniffing callback
void mgmt_pkt_sniffer_handler (void * buff, wifi_promiscuous_pkt_type_t type)
{
    // Ignore packet if sniffer isn't active
    if (!sniffer.active) return;

    // Packet was sniffed, increment counter
    sniffer.sniffed++;
    // Parse packet and packet header from the received buffer
    const wifi_promiscuous_pkt_t * ppkt = (wifi_promiscuous_pkt_t *) buff;
    const wifi_ieee80211_mac_hdr_t * hdr = (wifi_ieee80211_mac_hdr_t *) ppkt->payload;

    // Check direction filter
    uint8_t dir = (hdr->to_ds << 1) | (hdr->from_ds);
    if (!((1 << dir) & sniffer.direction)) {
        // Doesn't comply with given direction, skip the packet
        sniffer.skipped_dir++;
        return;
    }

    // Check type & subtype filters
    if (hdr->type == 0) {
        // Management packet
        if (!((1 << hdr->subtype) & (sniffer.mgmt_subtypes))) {
            // Doesn't comply with management subtypes, skip the packet
            sniffer.skipped_mgmt++;
            return;
        }
    } else if (hdr->type == 1) {
        // Control packet
        if (!((1 << hdr->subtype) & (sniffer.ctrl_subtypes))) {
            // Doesn't comply with control subtypes, skip the packet
            sniffer.skipped_ctrl++;
            return;
        }
    } else if (hdr->type == 2) {
        // Data packet
        if (!((1 << hdr->subtype) & (sniffer.data_subtypes))) {
            // Doesn't comply with data subtypes, skip the packet
            sniffer.skipped_data++;
            return;
        }
    } else {
        // Unknown packet type
        printf("SNIFFER WARNING: Unknown packet type %d.\n", hdr->type);
        return;
    }

	// Add sniffed packet to ring buffer
	_add_ring_entry(ppkt);
}


// Hop to the next channel in the user-defined list
void _hop_next_channel ()
{
    // If channel is not set, set it to 1 by default
    int cur_channel = (sniffer.channel) ? (sniffer.channel) : 1;
    // There are 13 WiFi channels in the IEEE 802.11 norm (for Europe) starting at number 1 (not 0!)
    int i = 1;

    for (i = 1; i <= TOTAL_WIFI_CHANNELS; i++) {
        // Move to the next channel
        cur_channel = (cur_channel % TOTAL_WIFI_CHANNELS) + 1;
        // If the channel is in the user-defined list
		// hop to the next channel
        if (sniffer.channels & (1 << cur_channel)) break;
    }

    // Update the sniffer channel
    sniffer.channel = cur_channel;
    // Set the channel
    esp_wifi_set_channel(sniffer.channel, WIFI_SECOND_CHAN_NONE);
}


// Timer callback
void _hop_timer (void * args)
{
    // Change channel
    if (sniffer.active) _hop_next_channel();
}


// Disable sniffing
esp_err_t _promiscuous_off()
{
    // Turn promiscuous mode off
    esp_err_t esp_err = esp_wifi_set_promiscuous(false);
    // Update the sniffer structure
    sniffer.active = 0;

    // Destroy ring buffer
    if (sniffer.ring) _destroy_ring();

    // Destroy timer
    if (sniffer.chtimer) {
        vosSysLock();
        vosTimerDestroy(sniffer.chtimer);
        vosSysUnlock();
        sniffer.chtimer = NULL;
    }

    return esp_err;
}


// Activate sniffer
C_NATIVE(esp32_promiscuous_on)
{
    NATIVE_UNWARN();
    esp_err_t esp_err;
    int32_t pkt_types, direction, _channels, _mgmt, _ctrl, _data, hop_time, pkt_buffer, max_payloads;

    // Parse python arguments:
    //      pkt_types	 : List of types of packets to be captured (Management, Control, Data)
    //      direction	 : Direction of packets (from_ds 0 or 1, to_ds 0 or 1)
    //      _channels	 : List of channels to be scanned
    //      _mgmt		 : List of management subtypes to be captured
    //      _ctrl		 : List of control subtypes to be captured
    //      _data		 : List of data subtypes to be captured
    //      hop_time	 : Time to spend parsing each channel (in ms)
    //      pkt_buffer	 : Places to be allocated in ring buffer for packets (but not payload data!)
    //      max_payloads : Places to be allocated in ring buffer for actual payload data
    if (parse_py_args("iiiiiiiii", nargs, args,
            &pkt_types, &direction,
            &_channels,
            &_mgmt, &_ctrl, &_data,
            &hop_time,
            &pkt_buffer, &max_payloads)
        != 9)
        return ERR_TYPE_EXC;

    *res = MAKE_NONE();

    // Make sure to turn sniffer off (if it was turned on before)
    esp_err = _promiscuous_off();
    if (CHECK_RES()) return ERR_IOERROR_EXC;

    // Reconfigure sniffing with arguments
    sniffer.pkt_types = pkt_types;
    sniffer.channels = _channels;
    sniffer.direction = direction;
    sniffer.ctrl_subtypes = _ctrl;
    sniffer.mgmt_subtypes = _mgmt;
    sniffer.data_subtypes = _data;
    sniffer.hop_time = hop_time;

    // Initialize stats
    sniffer.sniffed = 0;
    sniffer.skipped_mem = 0;
    sniffer.skipped_data = 0;
    sniffer.skipped_ctrl = 0;
    sniffer.skipped_mgmt = 0;
    sniffer.skipped_dir = 0;

    // Initialize ring
    sniffer.rsize = pkt_buffer;
    sniffer.rhead = 0;
    sniffer.ritems = 0;
    sniffer.current_total_payload_size = 0;
    sniffer.max_total_payload_size = max_payloads;
    sniffer.ring = gc_malloc(sizeof(RingEntry) * sniffer.rsize);

    // Check if ring memory was indeed allocated
    if (!sniffer.ring) return ERR_RUNTIME_EXC;

    // Allocate semaphore
    if (!sniffer.ringsem) sniffer.ringsem = vosSemCreate(1);

    // Allocate hop timer
    if (!sniffer.chtimer) sniffer.chtimer = vosTimerCreate();

    wifi_promiscuous_filter_t filter;
    // Initialize filter to 0
    memset(&filter, 0, sizeof(filter));
    // Configure filters
    if (pkt_types & 1) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    if (pkt_types & 2) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    if (pkt_types & 4) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    // Set filters
    esp_err = esp_wifi_set_promiscuous_filter(&filter);
    if (CHECK_RES()) return ERR_IOERROR_EXC;

    // Set sniffing callback
    esp_err = esp_wifi_set_promiscuous_rx_cb(&mgmt_pkt_sniffer_handler);
    if (CHECK_RES()) return ERR_IOERROR_EXC;

    // Turn sniffer on
    esp_err = esp_wifi_set_promiscuous(true);
    if (CHECK_RES()) return ERR_IOERROR_EXC;
    sniffer.active = 1;

    // Hop to the next user-defined channel
    // (in this case it's the first in the list)
    _hop_next_channel();

    // Setup timer with _hop_timer as callback
    vosSysLock();
    vosTimerRecurrent(sniffer.chtimer, TIME_U(sniffer.hop_time, MILLIS), _hop_timer, NULL);
    vosSysUnlock();

    return ERR_OK;
}


// Return stats on the current sniffer
C_NATIVE(esp32_promiscuous_sniffed_stats)
{
    NATIVE_UNWARN();
    *res = MAKE_NONE();

    // Create a new tuple to hold stats
    PTuple *tpl = ptuple_new(9, NULL);
    // Get number of packets sniffed so far
    PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(sniffer.sniffed));
    // Get number of skipped management packets
    PTUPLE_SET_ITEM(tpl, 1, PSMALLINT_NEW(sniffer.skipped_mgmt));
    // Get number of skipped control packets
    PTUPLE_SET_ITEM(tpl, 2, PSMALLINT_NEW(sniffer.skipped_ctrl));
    // Get number of skipped data packets
    PTUPLE_SET_ITEM(tpl, 3, PSMALLINT_NEW(sniffer.skipped_data));
    // Get number of skipped packets because of their direction
    PTUPLE_SET_ITEM(tpl, 4, PSMALLINT_NEW(sniffer.skipped_dir));
    // Get number of skipped packet payloads because of the buffer being full
    PTUPLE_SET_ITEM(tpl, 5, PSMALLINT_NEW(sniffer.skipped_mem));
    // Get number of packets stored in ring
    PTUPLE_SET_ITEM(tpl, 6, PSMALLINT_NEW(_get_ring_entry_count()));
    // Get total size of all payloads (packet data)
    PTUPLE_SET_ITEM(tpl, 7, PSMALLINT_NEW(sniffer.current_total_payload_size));
    // Get current WiFi channel number
    PTUPLE_SET_ITEM(tpl, 8, PSMALLINT_NEW(sniffer.channel));

    *res = tpl;

    return ERR_OK;
}


// Source for sniff_raw()
C_NATIVE(esp32_promiscuous_sniffed)
{
    NATIVE_UNWARN();
    *res = MAKE_NONE();
    RingEntry * temp_pkt;

    // Release Python lock (mutex)
    RELEASE_GIL();
    int ring_element_count = _get_ring_entry_count();
    int i = 0;

    // Create a new list for the sniffed packets
    PList *tpl = plist_new(ring_element_count, NULL);

    // Put ring elements into list
    for (i = 0; i < ring_element_count; i++) {
		// Get a packet from the ring buffer
        temp_pkt = _pop_ring_entry();

        // Put packet header in a list
        PList * pkt = plist_new(15, NULL);
        PLIST_SET_ITEM(pkt, 0, PSMALLINT_NEW(temp_pkt->hdr.type));
        PLIST_SET_ITEM(pkt, 1, PSMALLINT_NEW(temp_pkt->hdr.subtype));
        PLIST_SET_ITEM(pkt, 2, PSMALLINT_NEW(temp_pkt->hdr.to_ds));
        PLIST_SET_ITEM(pkt, 3, PSMALLINT_NEW(temp_pkt->hdr.from_ds));
        PLIST_SET_ITEM(pkt, 4, PSMALLINT_NEW(temp_pkt->hdr.flags));
        PLIST_SET_ITEM(pkt, 5, PSMALLINT_NEW(temp_pkt->hdr.duration_id));
        PLIST_SET_ITEM(pkt, 6, PSMALLINT_NEW(temp_pkt->hdr.sequence_ctrl));

        // Get adresses into byte objects and put them in the list as well
        PBytes * pa1 = pbytes_new(6, temp_pkt->hdr.addr1);
        PBytes * pa2 = pbytes_new(6, temp_pkt->hdr.addr2);
        PBytes * pa3 = pbytes_new(6, temp_pkt->hdr.addr3);
        PBytes * pa4 = pbytes_new(6, temp_pkt->hdr.addr4);
        PLIST_SET_ITEM(pkt, 7, pa1);
        PLIST_SET_ITEM(pkt, 8, pa2);
        PLIST_SET_ITEM(pkt, 9, pa3);
        PLIST_SET_ITEM(pkt, 10, pa4);

        // Put rest of header items into the list
        PLIST_SET_ITEM(pkt, 11, PSMALLINT_NEW(temp_pkt->rssi));
        PLIST_SET_ITEM(pkt, 12, PSMALLINT_NEW(temp_pkt->channel));
        PLIST_SET_ITEM(pkt, 13, PSMALLINT_NEW(temp_pkt->payload_size));

        // Extract payload from ring buffer element
        PBytes * pl;
        if (temp_pkt->payload)
            pl = pbytes_new(temp_pkt->payload_size, temp_pkt->payload);
        else
            pl = pbytes_new(0, NULL);

        // Put payload into the list
        PLIST_SET_ITEM(pkt, 14, pl);

		// Delete the temporary ring element
        _destroy_ring_entry(temp_pkt);

		// Add packet list to final tuple
        PLIST_SET_ITEM(tpl, i, pkt);
    }

    // Return the packet tuple
    *res = tpl;

    // Acquire Python lock (mutex)
    ACQUIRE_GIL();

    return ERR_OK;

}


// Source for stop_sniffer()
C_NATIVE(esp32_promiscuous_off)
{
    NATIVE_UNWARN();
    *res = MAKE_NONE();

    // Turn sniffer off
    esp_err_t esp_err = _promiscuous_off();
    if (CHECK_RES()) return ERR_IOERROR_EXC;

    return ERR_OK;
}
