#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "common.h"

#define USER_AGENT_MAX_LENGTH 64
struct wss_context {
    char user_agent[USER_AGENT_MAX_LENGTH];
    int user_agent_length;
    volatile int count;
    struct lws_client_connect_info *cc_info;
};

static int init_ws_info(struct lws_context_creation_info *info, struct lws_client_connect_info *connect_info) {
    char *end;
    int mux = 1;
    const char *cert;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");

    if (remote_host == NULL) {
        lwsl_err("remote host is not set");
        return EINVAL;
    }

    if (strchr(remote_host, '|') != NULL) {
        lwsl_err("remote host %s is not supported", remote_host);
        return EINVAL;
    }

    connect_info->address = remote_host;

    connect_info->port = (int) strtol(remote_port, &end, 10);
    if (connect_info->port <= 0 || connect_info->port > 65535 || *end != '\0') {
        lwsl_err("remote port %s is not supported", remote_host);
        return EINVAL;
    }

    if (strchr(options, '\\') != NULL) {
        lwsl_err("plugin options %s (contains \\) is not supported", options);
        return EINVAL;
    }

    // host
    connect_info->host = strstr(options, "host=");
    if (connect_info->host == NULL) {
        connect_info->host = remote_host;
    } else {
        connect_info->host += 5;
    }
    // path
    connect_info->path = strstr(options, "path=");
    if (connect_info->path == NULL) {
        connect_info->path = "/";
    } else {
        connect_info->path += 5;
    }
    // cert
    if ((cert = strstr(options, "cert=")) != NULL) {
        cert += 5;
    }
    // tls
    if ((end = strstr(options, "tls")) != NULL) {
        end += 3;
        if (*end == '\0' || *end == ';') {
            connect_info->ssl_connection = LCCSCF_USE_SSL;
        }
    }

    // mux
    if ((end = strstr(options, "mux=")) != NULL) {
        end += 4;
        mux = (int) strtol(end, NULL, 10);
    }

    // strip
    if ((end = strstr(connect_info->host, ";")) != NULL) {
        *end = '\0';
    }
    if ((end = strstr(connect_info->path, ";")) != NULL) {
        *end = '\0';
    }
    if (cert != NULL && (end = strstr(cert, ";")) != NULL) {
        *end = '\0';
    }

    lwsl_user("wss client %s:%d (%s://%s%s)", connect_info->address, connect_info->port,
              connect_info->ssl_connection == LCCSCF_USE_SSL ? "wss" : "ws",
              connect_info->host, connect_info->path);
    if (mux) {
        lwsl_warn("mux %d is unsupported", mux);
    }
#ifndef CERT_PEM
#ifdef __APPLE__
#define CERT_PEM "/usr/local/etc/ssl/cert.pem"
#else
#define CERT_PEM "/etc/ssl/cert.pem"
#endif
#endif
    if (connect_info->ssl_connection == LCCSCF_USE_SSL) {
        if (cert != NULL && access(cert, R_OK) == 0) {
            info->client_ssl_ca_filepath = cert;
        } else if (access(CERT_PEM, R_OK) == 0) {
            info->client_ssl_ca_filepath = CERT_PEM;
        }
    }
    return 0;
}

static int init_raw_info(struct lws_context_creation_info *info) {
    char *end;
    const char *local_host = getenv("SS_LOCAL_HOST");
    const char *local_port = getenv("SS_LOCAL_PORT");

    if (local_port == NULL) {
        lwsl_err("local port is not set");
        return EINVAL;
    }

    info->vhost_name = local_host;
    info->iface = local_host;
    info->port = (int) strtol(local_port, &end, 10);
    if (info->port <= 0 || info->port > 65535 || *end != '\0') {
        lwsl_err("local port %s is not supported", local_port);
        return EINVAL;
    }

    lwsl_user("raw server %s:%d", info->iface, info->port);
    return 0;
}

static uint8_t prepare_wss_data(struct wss_tunnel *wss_tunnel) {
    uint8_t fop;
    fop = 0x82;
    wss_tunnel->client.mask = 0;
    if (wss_tunnel->raw_len < 126) {
        wss_tunnel->client.f2.fop = fop;
        wss_tunnel->client.f2.mlen = (uint8_t) (1 << 0x7 | wss_tunnel->raw_len);
        return 6;
    } else {
        wss_tunnel->client.f4.fop = fop;
        wss_tunnel->client.f4.mlen = 0xfe;
        wss_tunnel->client.f4.elen = ntohs(wss_tunnel->raw_len);
        return 8;
    }
}

static int callback_wss_client(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            unsigned char **p = (unsigned char **) in;
            unsigned char *end = *p + len;
            struct wss_context *wss_context = lws_context_user(lws_get_context(wsi));
            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_USER_AGENT,
                                             (unsigned char *) wss_context->user_agent,
                                             wss_context->user_agent_length, p, end)) {
                lwsl_user("cannot add user_agent");
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] established, tunnel is null");
                return -1;
            }
            lwsl_notice("[wss] established for peer %d", wss_tunnel->peer_port);
            wss_tunnel->wss_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            struct lws *raw;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] received, tunnel is null");
                return -1;
            }
            if (len + wss_tunnel->wss_len > RX_BUFFER_SIZE) {
                lwsl_err("[wss] received %u from wss for peer %d, pending: %u, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, wss_tunnel->wss_len, RX_BUFFER_SIZE);
                lws_close_reason(wsi, LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE, NULL, 0);
                return -1;
            }
            lwsl_notice("[wss] received %u from wss for peer %d", (uint16_t) len, wss_tunnel->peer_port);
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
        case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            struct wss_tunnel *wss_tunnel = user;
            if (lws_get_opaque_parent_data(wsi) == NULL) {
                if (set_wsi_closing(wsi)) {
                    lwsl_notice("[wss] would close wss as tunnel is closed");
                }
                lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
                return -1;
            }
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] writable, tunnel is null");
                return -1;
            }
            if (wss_tunnel->raw_len > 0) {
                uint8_t pre = prepare_wss_data(wss_tunnel);
                if (lws_write(wsi, wss_tunnel->raw_rx - pre, wss_tunnel->raw_len + pre, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[wss] cannot send %u to wss for peer %d",
                                wss_tunnel->raw_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[wss] send %u to wss for peer %d", wss_tunnel->raw_len, wss_tunnel->peer_port);
                wss_tunnel->raw_len = 0;
                rx_flow_control_endpoint(wsi, 1);
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_CLOSED:
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            struct wss_tunnel *wss_tunnel = user;
            const char *message = reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR ? "error" : "closed";
            if (lws_get_opaque_parent_data(wsi) == NULL) {
                lwsl_notice("[wss] %s as tunnel is closed", message);
                break;
            }
            if (wss_tunnel == NULL) {
                lwsl_warn("[wss] %s, tunnel is null", message);
                break;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                break;
            }
            wss_tunnel->wss_state = STATE_CLOSED;
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] %s for peer %d, tunnel is closed", message, wss_tunnel->peer_port);
                break;
            }
            lwsl_notice("[wss] %s for peer %d, would close tunnel, reason: %s",
                        message, wss_tunnel->peer_port, in == NULL ? "(null)" : (char *) in);
            wss_tunnel->raw_state = STATE_CLOSING;
            callback_on_endpoint_writable(wsi);
            break;
        }
        default:
            break;
    }

    return 0;
}

static int callback_raw_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_RAW_ADOPT: {
            struct lws *wss;
            struct wss_context *wss_context;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] adopt, tunnel is null");
                return -1;
            }
            if (wss_tunnel->raw_state) {
                lwsl_warn("[raw] adopt, tunnel is initialized");
                return -1;
            }
            wss_tunnel->peer_port = get_port(wsi);
            wss_context = lws_context_user(lws_get_context(wsi));
            wss = lws_client_connect_via_info(wss_context->cc_info);
            if (wss == NULL) {
                wss_tunnel->raw_state = STATE_ERROR;
                lwsl_warn("[raw] new connection from peer %d, cannot connect to wss", wss_tunnel->peer_port);
                return -1;
            }
            lws_set_wsi_user(wss, wss_tunnel);
            lws_set_opaque_parent_data(wsi, wss);
            lws_set_opaque_parent_data(wss, wsi);
            wss_tunnel->raw_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            lwsl_user("[raw] new connection from peer %d, count: %d", wss_tunnel->peer_port, ++wss_context->count);
            break;
        }
        case LWS_CALLBACK_RAW_RX: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] rx, tunnel is null");
                return -1;
            }
            if (len + wss_tunnel->raw_len > RX_BUFFER_SIZE) {
                lwsl_err("[raw] received %u from peer %d, pending: %u, however buffer is only %d",
                         (uint16_t) len, wss_tunnel->peer_port, wss_tunnel->raw_len, RX_BUFFER_SIZE);
                return -1;
            }
            lwsl_notice("[raw] received %u from peer %d", (uint16_t) len, wss_tunnel->peer_port);
            memcpy(wss_tunnel->raw_rx + wss_tunnel->raw_len, in, len);
            wss_tunnel->raw_len += (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            if ((wss = lws_get_opaque_parent_data(wsi)) != NULL) {
                lws_callback_on_writable(wss);
            } else {
                lwsl_warn("[raw] cannot make wss writable for peer %d", wss_tunnel->peer_port);
            }
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] writable, tunnel is null");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSING) {
                if (set_wsi_closing(wsi)) {
                    lwsl_notice("[raw] would close peer %d as tunnel is closing by wss", wss_tunnel->peer_port);
                }
                return -1;
            }
            if (wss_tunnel->wss_len > 0) {
                if (lws_write(wsi, wss_tunnel->wss_rx, wss_tunnel->wss_len, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[raw] cannot send %u to peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                    return -1;
                }
                lwsl_notice("[raw] send %u to peer %d", wss_tunnel->wss_len, wss_tunnel->peer_port);
                wss_tunnel->wss_len = 0;
                if ((wss = lws_get_opaque_parent_data(wsi)) != NULL) {
                    lws_rx_flow_control(wss, 1);
                } else {
                    lwsl_warn("[raw] cannot make wss readable for peer %d", wss_tunnel->peer_port);
                }
            }
            break;
        }
        case LWS_CALLBACK_RAW_CLOSE: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            struct wss_context *wss_context;
            if (wss_tunnel == NULL) {
                lwsl_warn("[raw] closed, tunnel is null");
                break;
            }
            if (wss_tunnel->raw_state == STATE_ERROR) {
                lwsl_warn("[raw] peer %d is closed, cannot connect to wss", wss_tunnel->peer_port);
                break;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_warn("[raw] peer %d is closed already", wss_tunnel->peer_port);
                break;
            }
            wss_tunnel->raw_state = STATE_CLOSED;
            wss_context = lws_context_user(lws_get_context(wsi));
            --wss_context->count;
            if ((wss = lws_get_opaque_parent_data(wsi)) == NULL) {
                lwsl_warn("[raw] peer %d is closed, tunnel is invalid, count: %d",
                          wss_tunnel->peer_port, wss_context->count);
                break;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_user("[raw] peer %d is closed, count: %d", wss_tunnel->peer_port, wss_context->count);
            } else {
                lwsl_user("[raw] peer %d is closed, would close wss, count: %d",
                          wss_tunnel->peer_port, wss_context->count);
                lws_callback_on_writable(wss);
            }
            lws_set_opaque_parent_data(wss, NULL);
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
            {"raw-server", callback_raw_server, sizeof(struct wss_tunnel), RX_BUFFER_SIZE, 0, NULL, 0},
            {"wss-client", callback_wss_client, 0,                         0,              0, NULL, 0},
            {NULL, NULL,                        0,                         0,              0, NULL, 0}
    };
    struct wss_context context_data;
    struct lws_client_connect_info cc_info;

    init_log_level(argc, argv);

    memset(&context_data, 0, sizeof(context_data));
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
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
    if (init_ws_info(&info, &cc_info)) {
        return EXIT_FAILURE;
    }
    info.vhost_name = cc_info.host;
    cc_info.context = context;
    cc_info.local_protocol_name = "wss-client";
    cc_info.vhost = lws_create_vhost(context, &info);
    if (!cc_info.vhost) {
        lwsl_err("cannot create wss-client");
        return 1;
    }

    if (init_raw_info(&info)) {
        return EXIT_FAILURE;
    }
    // since lws 3.2.0
    info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
    info.listen_accept_protocol = "raw-server";
    info.listen_accept_role = "raw-skt";
    info.vhost_name = "raw-server";
    if (!lws_create_vhost(context, &info)) {
        lwsl_err("cannot create raw-server");
        return 1;
    }

    context_data.cc_info = &cc_info;
    context_data.user_agent_length = lws_snprintf(context_data.user_agent, USER_AGENT_MAX_LENGTH,
                                                  "wss-plugin-client/%s lws/%s", WSS_PLUGIN_VERSION,
                                                  lws_get_library_version());
    lwsl_user("%s started, pid: %d, ppid: %d", context_data.user_agent, getpid(), getppid());

    run(context);

    return 0;
}
