#ifndef WSS_PLUGIN_COMMON_H
#define WSS_PLUGIN_COMMON_H

#include <stdint.h>
#include "libwebsockets.h"

#ifndef WSS_PLUGIN_VERSION
#define WSS_PLUGIN_VERSION "0.3.0-SNAPSHOT"
#endif

#ifndef RX_BUFFER_SIZE
#define RX_BUFFER_SIZE 4096
#endif

enum {
    STATE_ESTABLISHED = 1,
    STATE_CLOSED,
};

struct wss_frame_client {
    union {
        struct {
            uint16_t unused;
            uint8_t fop; // fin:1, rsv:3, opcode: 4
            uint8_t mlen; // mask: 1, length: 7
        } f2;
        struct {
            uint8_t fop; // fin:1, rsv:3, opcode: 4
            uint8_t mlen; // mask: 1, length: 7
            uint16_t elen;
        } f4;
    };
    uint32_t mask;
};

struct wss_frame_server {
    uint32_t unused;
    union {
        struct {
            uint16_t unused;
            uint8_t fop; // fin:1, rsv:3, opcode: 4
            uint8_t mlen; // mask: 1, length: 7
        } f2;
        struct {
            uint8_t fop; // fin:1, rsv:3, opcode: 4
            uint8_t mlen; // mask: 1, length: 7
            uint16_t elen;
        } f4;
    };
};

struct wss_tunnel {
    uint8_t wss_channel: 4;
    uint8_t raw_channel: 4;
    uint8_t wss_state: 4;
    uint8_t raw_state: 4;
    uint16_t peer_port; // 2
    uint16_t raw_len; // 2
    uint16_t wss_len; // 2
    union {
        struct wss_frame_client client; // 8
        struct wss_frame_server server; // 8
    };
    unsigned char raw_rx[RX_BUFFER_SIZE];
    unsigned char wss_rx[RX_BUFFER_SIZE];
};

uint16_t get_port(struct lws *wsi);

void run(struct lws_context *context);

void init_log_level(int argc, char **argv);

#endif //WSS_PLUGIN_COMMON_H
