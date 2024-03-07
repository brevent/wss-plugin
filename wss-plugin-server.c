#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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
                lwsl_warn("[raw] connected, however tunnel is null");
                return -1;
            }
            if (wss_tunnel->raw_state != STATE_ESTABLISHED) {
                lwsl_notice("[raw] connected for peer %d", wss_tunnel->peer_port);
            }
            wss_tunnel->raw_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            break;
        }
        case LWS_CALLBACK_RAW_RX: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] received, tunnel is null");
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] received %u from raw for peer %d, however tunnel is closed",
                            (uint16_t) len, wss_tunnel->peer_port);
                return -1;
            }
            if (len + wss_tunnel->raw_len > RX_BUFFER_SIZE) {
                lwsl_err("[raw] received %u from raw for peer %d, pending: %u, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, wss_tunnel->raw_len, RX_BUFFER_SIZE);
                return -1;
            }
            lwsl_notice("[raw] received %u from raw for peer %d", (uint16_t) len, wss_tunnel->peer_port);
            memcpy(wss_tunnel->raw_rx + wss_tunnel->raw_len, in, len);
            wss_tunnel->raw_len += (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            if ((wss = lws_get_opaque_parent_data(wsi)) != NULL) {
                lws_callback_on_writable(wss);
            } else {
                lwsl_warn("[wss] cannot make wss writable for peer %d", wss_tunnel->peer_port);
            }
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE: {
            struct wss_tunnel *wss_tunnel = user;
            if (lws_get_opaque_parent_data(wsi) == NULL) {
                if (set_wsi_closing(wsi)) {
                    lwsl_notice("[raw] would close raw as tunnel is closed");
                }
                return -1;
            }
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] writable, tunnel is null");
                return -1;
            }
            if (wss_tunnel->wss_len > 0) {
                if (lws_write(wsi, wss_tunnel->wss_rx, wss_tunnel->wss_len, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[raw] cannot send %u to raw for peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[raw] send %u to raw for peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                wss_tunnel->wss_len = 0;
                rx_flow_control_endpoint(wsi, 1);
            }
            break;
        }
        case LWS_CALLBACK_RAW_CLOSE:
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            struct wss_tunnel *wss_tunnel = user;
            const char *message = reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR ? "error" : "closed";
            if (lws_get_opaque_parent_data(wsi) == NULL) {
                lwsl_notice("[raw] %s as tunnel is closed", message);
                break;
            }
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] %s, tunnel is null", message);
                break;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                break;
            }
            wss_tunnel->raw_state = STATE_CLOSED;
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[raw] %s for peer %d, tunnel is closed", message, wss_tunnel->peer_port);
                break;
            }
            lwsl_notice("[raw] %s for peer %d, would close tunnel, reason: %s",
                        message, wss_tunnel->peer_port, in == NULL ? "(null)" : (char *) in);
            wss_tunnel->wss_state = STATE_CLOSING;
            callback_on_endpoint_writable(wsi);
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
                lwsl_warn("[wss] established, tunnel is null");
                return -1;
            }
            if (wss_tunnel->wss_state) {
                lwsl_warn("[raw] established, tunnel is initialized");
                return -1;
            }
            wss_tunnel->peer_port = get_port(wsi);
            wss_context = lws_context_user(lws_get_context(wsi));
            wss = lws_client_connect_via_info(wss_context->cc_info);
            if (wss == NULL) {
                wss_tunnel->wss_state = STATE_ERROR;
                lwsl_warn("[wss] new connection from peer %d, cannot connect to raw", wss_tunnel->peer_port);
                lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
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
            struct lws *raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] received, tunnel is null");
                return -1;
            }
            if (len + wss_tunnel->wss_len > RX_BUFFER_SIZE) {
                lwsl_err("[wss] received %u from peer %d, pending: %u, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, wss_tunnel->wss_len, RX_BUFFER_SIZE);
                lws_close_reason(wsi, LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE, NULL, 0);
                return -1;
            }
            lwsl_notice("[wss] received %u from peer %d", (uint16_t) len, wss_tunnel->peer_port);
            memcpy(wss_tunnel->wss_rx + wss_tunnel->wss_len, in, len);
            wss_tunnel->wss_len += (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            if ((raw = lws_get_opaque_parent_data(wsi)) != NULL) {
                lws_callback_on_writable(raw);
            } else {
                lwsl_warn("[wss] cannot make raw writable for peer %d", wss_tunnel->peer_port);
            }
            break;
        }
        case LWS_CALLBACK_SERVER_WRITEABLE: {
            struct lws *raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] writable, tunnel is null");
                return -1;
            }
            if (wss_tunnel->wss_state == STATE_CLOSING) {
                if (set_wsi_closing(wsi)) {
                    lwsl_notice("[wss] would close peer %d as tunnel is closing by raw", wss_tunnel->peer_port);
                }
                lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
                return -1;
            }
            if (wss_tunnel->raw_len > 0) {
                uint8_t pre = prepare_wss_data(wss_tunnel);
                if (lws_write(wsi, wss_tunnel->raw_rx - pre, wss_tunnel->raw_len + pre, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[wss] cannot send %u to peer %d", wss_tunnel->raw_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[wss] send %u to peer %d", wss_tunnel->raw_len, wss_tunnel->peer_port);
                wss_tunnel->raw_len = 0;
                if ((raw = lws_get_opaque_parent_data(wsi)) != NULL) {
                    lws_rx_flow_control(raw, 1);
                } else {
                    lwsl_warn("[wss] cannot make raw readable for peer %d", wss_tunnel->peer_port);
                }
            }
            break;
        }
        case LWS_CALLBACK_CLOSED: {
            struct lws *raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] closed, tunnel is null");
                break;
            }
            if (wss_tunnel->wss_state == STATE_ERROR) {
                lwsl_warn("[wss] peer %d is closed, cannot connect to raw", wss_tunnel->peer_port);
                break;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_warn("[raw] peer %d is closed already", wss_tunnel->peer_port);
                break;
            }
            wss_tunnel->wss_state = STATE_CLOSED;
            if ((raw = lws_get_opaque_parent_data(wsi)) == NULL) {
                lwsl_warn("[wss] peer %d is closed, tunnel is invalid", wss_tunnel->peer_port);
                break;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_user("[wss] peer %d is closed", wss_tunnel->peer_port);
            } else {
                lwsl_user("[wss] peer %d is closed, would close raw", wss_tunnel->peer_port);
                lws_callback_on_writable(raw);
            }
            lws_set_opaque_parent_data(raw, NULL);
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
            {"wss-server", callback_wss_server, sizeof(struct wss_tunnel), 0,              0, NULL, 0},
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
    info.timeout_secs = 30;
    info.pt_serv_buf_size = PT_SERV_BUF_SIZE;
    context = create_context(&info);
    if (!context) {
        lwsl_err("cannot create context");
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
        lwsl_err("cannot create raw-client");
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
        lwsl_err("cannot create wss-server");
        return 1;
    }

    context_data.cc_info = &cc_info;
    lwsl_user("wss-plugin-server/%s lws/%s started, pid: %d, ppid: %d",
              WSS_PLUGIN_VERSION, lws_get_library_version(), getpid(), getppid());
    run(context);

    return 0;
}
