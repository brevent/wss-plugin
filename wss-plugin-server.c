#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libwebsockets.h"
#include "common.h"

struct wss_context {
    struct lws_client_connect_info *cc_info;
};

static int init_ws_info(struct lws_context_creation_info *info) {
    int mux = 1;
    char *end;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");
    if (remote_host != NULL && strchr(remote_host, '|') != NULL) {
        lwsl_err("remote host %s is not supported", remote_host);
        return EINVAL;
    }
    info->vhost_name = remote_host == NULL ? "127.0.0.1" : remote_host;
    info->iface = info->vhost_name;
    info->port = remote_port == NULL ? 0 : (int) strtol(remote_port, &end, 10);
    if (info->port <= 0 || info->port > 65535 || *end != '\0') {
        lwsl_err("remote port %s is not supported", remote_port);
        return EINVAL;
    }
    // mux
    if (options != NULL && (end = strstr(options, "mux=")) != NULL) {
        end += 4;
        mux = (int) strtol(end, NULL, 10);
    }
    lwsl_user("wss server %s:%d", info->iface, info->port);
    if (mux) {
        lwsl_warn("mux %d is unsupported", mux);
    }
    return 0;
}

static int init_raw_info(struct lws_client_connect_info *connect_info) {
    char *end;
    const char *local_host = getenv("SS_LOCAL_HOST");
    const char *local_port = getenv("SS_LOCAL_PORT");
    connect_info->address = local_host == NULL ? "127.0.0.1" : local_host;
    if (local_port == NULL) {
        lwsl_err("local port is not set");
        return EINVAL;
    }
    connect_info->port = (int) strtol(local_port, &end, 10);
    if (connect_info->port <= 0 || connect_info->port > 65535 || *end != '\0') {
        lwsl_err("local port %s is not supported", local_port);
        return EINVAL;
    }
    lwsl_user("raw client %s:%d", connect_info->address, connect_info->port);
    return 0;
}

static uint8_t prepare_wss_data(struct wss_tunnel *wss_tunnel) {
    uint8_t fop;
    fop = 0x82;
    if (wss_tunnel->raw_len < 126) {
        wss_tunnel->server.f2.fop = fop;
        wss_tunnel->server.f2.mlen = (uint8_t) (wss_tunnel->raw_len);
        return 2;
    } else {
        wss_tunnel->server.f4.fop = fop;
        wss_tunnel->server.f4.mlen = 0x7e;
        wss_tunnel->server.f4.elen = ntohs(wss_tunnel->raw_len);
        return 4;
    }
}

static int callback_raw_client(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        // since lws 3.2.0
        case LWS_CALLBACK_RAW_CONNECTED: {
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[raw] connected, however tunnel null");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_ESTABLISHED) {
                lwsl_notice("[raw] connected for peer %d (duplicate)", wss_tunnel->peer_port);
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] connected for peer %d, however tunnel is closed", wss_tunnel->peer_port);
                return -1;
            }
            lwsl_notice("[raw] connected for peer %d", wss_tunnel->peer_port);
            wss_tunnel->raw_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            break;
        }
        case LWS_CALLBACK_RAW_RX: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[raw] received %u from raw, however tunnel is null", (uint16_t) len);
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] received %u from raw for peer %d, however tunnel is closed",
                            (uint16_t) len, wss_tunnel->peer_port);
                return -1;
            }
            if ((wss = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(wss) != wsi) {
                lwsl_warn("[raw] received %u from raw for peer %d, however tunnel is invalid",
                          (uint16_t) len, wss_tunnel->peer_port);
                return -1;
            }
            if (len > RX_BUFFER_SIZE) {
                lwsl_err("[raw] received %u from raw for peer %d, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, RX_BUFFER_SIZE);
                return -1;
            }
            lwsl_notice("[raw] received %u from raw for peer %d", (uint16_t) len, wss_tunnel->peer_port);
            memcpy(wss_tunnel->raw_rx, in, len);
            wss_tunnel->raw_len = (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            lws_callback_on_writable(wss);
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] would send to raw for peer %d, however tunnel is closed", wss_tunnel->peer_port);
                return -1;
            }
            if ((wss = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(wss) != wsi) {
                lwsl_warn("[raw] would send to raw for peer %d, however tunnel is invalid", wss_tunnel->peer_port);
                return -1;
            }
            if (wss_tunnel->wss_len > 0) {
                if (lws_write(wsi, wss_tunnel->wss_rx, wss_tunnel->wss_len, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[raw] cannot send %u to raw for peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[raw] send %u to raw for peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                wss_tunnel->wss_len = 0;
            }
            lws_rx_flow_control(wss, 1);
            break;
        }
        case LWS_CALLBACK_RAW_CLOSE: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[raw] closed");
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] closed for peer %d, tunnel is closed", wss_tunnel->peer_port);
                return -1;
            }
            wss_tunnel->raw_state = STATE_CLOSED;
            if ((wss = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(wss) != wsi) {
                lwsl_warn("[raw] closed for peer %d, however tunnel is invalid", wss_tunnel->peer_port);
                return -1;
            }
            lwsl_notice("[raw] closed for peer %d, would close tunnel, reason: %s",
                        wss_tunnel->peer_port, in == NULL ? "(null)" : (char *) in);
            lws_callback_on_writable(wss);
            break;
        }
        default:
            break;
    }

    return 0;
}

static int callback_wss_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            struct wss_context *wss_context;
            if (wss_tunnel == NULL) {
                return -1;
            }
            wss_tunnel->peer_port = get_port(wsi);
            wss_context = lws_context_user(lws_get_context(wsi));
            wss = lws_client_connect_via_info(wss_context->cc_info);
            if (wss == NULL) {
                lwsl_warn("[wss] new connection from peer %d, cannot connect to raw", wss_tunnel->peer_port);
                return -1;
            }
            lws_set_wsi_user(wss, wss_tunnel);
            lws_set_opaque_parent_data(wsi, wss);
            lws_set_opaque_parent_data(wss, wsi);
            wss_tunnel->wss_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            lwsl_user("[wss] new connection from peer %d ", wss_tunnel->peer_port);
            break;
        }
        case LWS_CALLBACK_RECEIVE: {
            struct lws* raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] received %u from peer %d, however tunnel is null",
                            (uint16_t) len, get_port(wsi));
                return -1;
            }
            if ((raw = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(raw) != wsi) {
                lwsl_warn("[wss] received %u from peer %d, however tunnel is invalid",
                          (uint16_t) len, wss_tunnel->peer_port);
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] received %u from peer %d, however tunnel is closed",
                            (uint16_t) len, wss_tunnel->peer_port);
                return -1;
            }
            if (len > RX_BUFFER_SIZE) {
                lwsl_err("[wss] received %u from peer %d, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, RX_BUFFER_SIZE);
                return -1;
            }
            lwsl_notice("[wss] received %u from peer %d", (uint16_t) len, wss_tunnel->peer_port);
            memcpy(wss_tunnel->wss_rx, in, len);
            wss_tunnel->wss_len = (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            lws_callback_on_writable(raw);
            break;
        }
        case LWS_CALLBACK_SERVER_WRITEABLE: {
            struct lws* raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] wound send, however tunnel is null");
                return -1;
            }
            if ((raw = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(raw) != wsi) {
                lwsl_warn("[wss] would send to peer %d, however tunnel is invalid", get_port(wsi));
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] would send to peer %d, however tunnel is closed", wss_tunnel->peer_port);
                return -1;
            }
            if (wss_tunnel->raw_len > 0) {
                uint8_t pre = prepare_wss_data(wss_tunnel);
                if (lws_write(wsi, wss_tunnel->raw_rx - pre, wss_tunnel->raw_len + pre, LWS_WRITE_RAW) < 0) {
                    lwsl_notice("[wss] cannot send %u to peer %d", wss_tunnel->raw_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[wss] send %u to peer %d", wss_tunnel->raw_len, wss_tunnel->peer_port);
                wss_tunnel->raw_len = 0;
            }
            lws_rx_flow_control(raw, 1);
            break;
        }
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            return -1;
        case LWS_CALLBACK_CLOSED: {
            struct lws *raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] peer %d is closed, however tunnel is null", get_port(wsi));
                return -1;
            }
            wss_tunnel->wss_state = STATE_CLOSED;
            if ((raw = lws_get_opaque_parent_data(wsi)) == NULL || lws_get_opaque_parent_data(raw) != wsi) {
                lwsl_warn("[wss] peer %d is closed, tunnel is invalid", get_port(wsi));
                return -1;
            }
            lws_set_wsi_user(raw, NULL);
            if (wss_tunnel->raw_state != STATE_CLOSED) {
                lwsl_user("[wss] peer %d is closed, would close raw", wss_tunnel->peer_port);
                lws_callback_on_writable(raw);
            } else {
                lwsl_user("[wss] peer %d is closed", wss_tunnel->peer_port);
            }
            break;
        }
        default:
            break;
    }

    return 0;
}

int main(int argc, char **argv) {
    struct lws_context *context;
    struct lws_context_creation_info info;
    const struct lws_protocols protocols[] = {
            {"wss-server", callback_wss_server, sizeof(struct wss_tunnel), RX_BUFFER_SIZE, 0, NULL, 0},
            {"raw-client", callback_raw_client, 0,                         RX_BUFFER_SIZE, 0, NULL, 0},
            {NULL, NULL,                        0,                         0,              0, NULL, 0}
    };
    struct wss_context context_data;
    struct lws_client_connect_info cc_info;

    init_log_level(argc, argv);

    memset(&context_data, 0, sizeof(context_data));
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.gid = (gid_t) -1;
    info.uid = (uid_t) -1;
    info.protocols = protocols;
    info.vhost_name = "context";
    info.user = &context_data;
    info.pt_serv_buf_size = RX_BUFFER_SIZE;
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws_create_context failed");
        return 1;
    }

    memset(&cc_info, 0, sizeof(cc_info));
    if (init_raw_info(&cc_info)) {
        return EXIT_FAILURE;
    }
    info.vhost_name = "raw-client";
    cc_info.context = context;
    cc_info.local_protocol_name = "raw-client";
    cc_info.method = "RAW";
    cc_info.vhost = lws_create_vhost(context, &info);
    if (!cc_info.vhost) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    if (init_ws_info(&info)) {
        return EXIT_FAILURE;
    }
    info.vhost_name = "wss-server";
    // since lws 3.2.0
    info.listen_accept_protocol = "wss-server";
    info.listen_accept_role = "ws";
    if (!lws_create_vhost(context, &info)) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    context_data.cc_info = &cc_info;
    lwsl_user("wss-plugin-server/%s lws/%s started", WSS_PLUGIN_VERSION, lws_get_library_version());
    run(context);

    return 0;
}
