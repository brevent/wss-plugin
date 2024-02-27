#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "libwebsockets.h"

#ifndef WSS_PLUGIN_VERSION
#define WSS_PLUGIN_VERSION "0.1.5"
#endif

#define BUF_SIZE 2048

static volatile int interrupted;

static void sigterm_catch(int signal) {
    if (signal == SIGTERM) {
        lwsl_notice("received termination");
        interrupted = 1;
    } else if (signal == SIGINT) {
        lwsl_notice("received interrupt");
        interrupted = 1;
    } else if (signal == SIGUSR1) {
        lwsl_user("received SIGUSR1, change loglevel to debug");
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);
    } else if (signal == SIGUSR2) {
        lwsl_user("received SIGUSR1, change loglevel to info");
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER, NULL);
    }
}

enum {
    STATE_ESTABLISHED = 1,
    STATE_CLOSED,
};

struct wss_frame {
    union {
        struct {
            uint16_t unused;
            uint8_t fin: 1;
            uint8_t rsv: 3;
            uint8_t opcode: 4;
            uint8_t mask: 1;
            uint8_t length: 7;
        } frame7;
        struct {
            uint8_t fin: 1;
            uint8_t rsv: 3;
            uint8_t opcode: 4;
            uint8_t mask: 1;
            uint8_t length: 7;
            uint16_t extend_length;
        } frame23;
        struct {
            uint16_t unused;
            uint8_t fop;
            uint8_t mlen;
        } f2;
        struct {
            uint8_t fop;
            uint8_t mlen;
            uint16_t elen;
        } f4;
    } frame;
    uint32_t mask;
};

struct wss_tunnel {
    uint8_t wss_channel: 4;
    uint8_t raw_channel: 4;
    uint8_t wss_state: 4;
    uint8_t raw_state: 4;
    uint16_t raw_port; // 2
    uint16_t raw_len; // 2
    uint16_t wss_len; // 2
    struct wss_frame frame; // 8
    unsigned char raw_rx[BUF_SIZE];
    unsigned char wss_rx[BUF_SIZE];
};

#define USER_AGENT_MAX_LENGTH 64
struct wss_context {
    char user_agent[USER_AGENT_MAX_LENGTH];
    int user_agent_length;
    volatile int count;
    struct lws_client_connect_info *cc_info;
};

static int init_connect_info(struct lws_context_creation_info *info, struct lws_client_connect_info *connect_info) {
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

    lwsl_user("will connect to %s:%d -> %s://%s%s", connect_info->address, connect_info->port,
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

static int init_local_info(struct lws_context_creation_info *info) {
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

    lwsl_user("listening %s:%d", info->iface, info->port);
    return 0;
}

static int callback_wss_client(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        // remote
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
                lwsl_notice("[wss] connection established, local tunnel is closed");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] connection established, however tunnel on peer %d is closed", wss_tunnel->raw_port);
                return -1;
            }
            lwsl_notice("[wss] connected for peer %d", wss_tunnel->raw_port);
            wss_tunnel->wss_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] connection receive, local tunnel is closed");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] connection receive, however tunnel on peer %d is closed", wss_tunnel->raw_port);
                return -1;
            }
            if (len > BUF_SIZE) {
                lwsl_err("[wss] buffer %d is less than %u for peer %d", BUF_SIZE, (uint16_t) len, wss_tunnel->raw_port);
                return -1;
            }
            lwsl_notice("[wss] receive %u for peer %d", (uint16_t) len, wss_tunnel->raw_port);
            memcpy(wss_tunnel->wss_rx, in, len);
            wss_tunnel->wss_len = (uint16_t) len;
            // block wsi until local buf is empty
            lws_rx_flow_control(wsi, 0);
            lws_callback_on_writable(lws_get_opaque_parent_data(wsi));
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] connection writable, local tunnel is closed");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] connection writable, however tunnel on peer %d is closed", wss_tunnel->raw_port);
                return -1;
            }
            if (wss_tunnel->raw_len > 0) {
                uint8_t pre;
                uint8_t fop;
                wss_tunnel->frame.mask = 0;
                fop = 0x82;
                if (wss_tunnel->raw_len < 126) {
                    wss_tunnel->frame.frame.f2.fop = fop;
                    wss_tunnel->frame.frame.f2.mlen = (uint8_t) (1 << 0x7 | wss_tunnel->raw_len);
                    pre = 6;
                } else {
                    wss_tunnel->frame.frame.f4.fop = fop;
                    wss_tunnel->frame.frame.f4.mlen = 0xfe;
                    wss_tunnel->frame.frame.f4.elen = ntohs(wss_tunnel->raw_len);
                    pre = 8;
                }
               if (lws_write(wsi, wss_tunnel->raw_rx - pre , wss_tunnel->raw_len + pre, LWS_WRITE_RAW) < 0) {
                    lwsl_notice("[wss] cannot write %u to remote for peer %d", wss_tunnel->raw_len,
                                wss_tunnel->raw_port);
                    return -1;
                }
                lwsl_notice("[wss] write %u to remote for peer %d", wss_tunnel->raw_len, wss_tunnel->raw_port);
                wss_tunnel->raw_len = 0;
            }
            lws_rx_flow_control(lws_get_opaque_parent_data(wsi), 1);
            break;
        }
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            return -1;
        case LWS_CALLBACK_CLIENT_CLOSED:
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            struct wss_tunnel *wss_tunnel = user;
            struct lws *raw_server;
            raw_server = lws_get_opaque_parent_data(wsi);
            if (wss_tunnel == NULL) {
                lwsl_notice("[wss] connection closed, local tunnel is closed");
                return -1;
            }
            if (wss_tunnel->raw_state == STATE_CLOSED) {
                lwsl_notice("[wss] connection closed, and tunnel on peer %d is closed", wss_tunnel->raw_port);
                return -1;
            }
            wss_tunnel->wss_state = STATE_CLOSED;
            lwsl_notice("[wss] connection closed, would close tunnel on peer %d, reason: %s",
                        wss_tunnel->raw_port, in == NULL ? "(null)" : (char *) in);
            if (raw_server != NULL) {
                lws_callback_on_writable(raw_server);
            }
            break;
        }
        default:
            break;
    }

    return 0;
}

static uint16_t get_port(struct lws *wsi) {
    socklen_t len;
    struct sockaddr_storage sin, *psin = &sin;
    lws_sockfd_type sockfd = lws_get_socket_fd(wsi);
    if (getpeername(sockfd, (struct sockaddr *) psin, &len) != -1) {
        return (sin.ss_family == AF_INET6) ?
               ntohs(((struct sockaddr_in6 *) psin)->sin6_port) :
               ntohs(((struct sockaddr_in *) psin)->sin_port);
    } else {
        return 0;
    }
}

static int callback_raw_server(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_RAW_ADOPT: {
            struct lws *wss;
            struct wss_tunnel *wss_tunnel = user;
            struct wss_context *wss_context;
            wss_tunnel->raw_port = get_port(wsi);
            wss_context = lws_context_user(lws_get_context(wsi));
            wss_context->cc_info->userdata = wss_tunnel;
            wss = lws_client_connect_via_info(wss_context->cc_info);
            if (wss == NULL) {
                lwsl_warn("[client] cannot connect to remote: %d", wss_tunnel->raw_port);
                return -1;
            }
            lws_set_opaque_parent_data(wsi, wss);
            lws_set_opaque_parent_data(wss, wsi);
            wss_tunnel->raw_state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            lwsl_user("[client] new connection from peer %d, count: %d", wss_tunnel->raw_port, ++wss_context->count);
            break;
        }
        case LWS_CALLBACK_RAW_RX: {
            struct wss_tunnel *wss_tunnel = user;
            lwsl_notice("[client] receive %u from peer %d", (uint16_t) len, wss_tunnel->raw_port);
            memcpy(wss_tunnel->raw_rx, in, len);
            wss_tunnel->raw_len = (uint16_t) len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            lws_callback_on_writable(lws_get_opaque_parent_data(wsi));
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE: {
            struct wss_tunnel *wss_tunnel = user;
            if (wss_tunnel->wss_len > 0) {
                if (lws_write(wsi, wss_tunnel->wss_rx, wss_tunnel->wss_len, LWS_WRITE_RAW) < 0) {
                    lwsl_warn("[client] cannot write %u to peer %d", wss_tunnel->wss_len, wss_tunnel->raw_port);
                    return -1;
                }
                lwsl_notice("[client] write %u to peer %d", wss_tunnel->wss_len, wss_tunnel->raw_port);
                wss_tunnel->wss_len = 0;
            }
            if (wss_tunnel->wss_state == STATE_CLOSED) {
                lwsl_notice("[client] remote connection is closed for client on %d", wss_tunnel->raw_port);
                return -1;
            }
            lws_rx_flow_control(lws_get_opaque_parent_data(wsi), 1);
            break;
        }
        case LWS_CALLBACK_RAW_CLOSE: {
            struct wss_tunnel *wss_tunnel = user;
            struct lws *wss;
            struct wss_context *wss_context = lws_context_user(lws_get_context(wsi));
            --wss_context->count;
            wss_tunnel->raw_state = STATE_CLOSED;
            wss = lws_get_opaque_parent_data(wsi);
            lws_set_wsi_user(wss, NULL);
            lws_set_opaque_parent_data(wss, NULL);
            if (wss_tunnel->wss_state != STATE_CLOSED) {
                lwsl_user("[client] peer %d is closed, would close wss connection, count: %d",
                          wss_tunnel->raw_port, wss_context->count);
                lws_callback_on_writable(wss);
            } else {
                lwsl_user("[client] peer %d is closed, count: %d",
                          wss_tunnel->raw_port, wss_context->count);
            }
            break;
        }
        default:
            break;
    }

    return 0;
}

int main() {
    const char *plugin_options;
    struct lws_context *context;
    struct lws_context_creation_info info;
    const struct lws_protocols protocols[] = {
            {"raw-server", callback_raw_server, sizeof(struct wss_tunnel), 0, 0, NULL, 0},
            {"wss-client", callback_wss_client, 0,                         0, 0, NULL, 0},
            {NULL,         NULL,                0,                         0, 0, NULL, 0}
    };
    struct wss_context context_data;
    struct lws_client_connect_info cc_info;

    // loglevel
    plugin_options = getenv("SS_PLUGIN_OPTIONS");
    if (plugin_options != NULL && strstr(plugin_options, "loglevel=debug") != NULL) {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);
    } else {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER, NULL);
    }

    memset(&context_data, 0, sizeof(context_data));
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.gid = (gid_t) -1;
    info.uid = (uid_t) -1;
    info.protocols = protocols;
    info.vhost_name = "context";
    info.user = &context_data;
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws_create_context failed");
        return 1;
    }

    memset(&cc_info, 0, sizeof(cc_info));
    context_data.cc_info = &cc_info;
    if (init_connect_info(&info, &cc_info)) {
        return EXIT_FAILURE;
    }
    info.vhost_name = cc_info.host;
    cc_info.context = context;
    cc_info.local_protocol_name = "wss-client";
    cc_info.vhost = lws_create_vhost(context, &info);
    if (!cc_info.vhost) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    context_data.user_agent_length = lws_snprintf(context_data.user_agent, USER_AGENT_MAX_LENGTH,
                                                  "wss-plugin/%s lws/%s", WSS_PLUGIN_VERSION,
                                                  lws_get_library_version());

    if (init_local_info(&info)) {
        return EXIT_FAILURE;
    }
    // since lws 3.2.0
    info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
    info.listen_accept_protocol = "raw-server";
    info.listen_accept_role = "raw-skt";
    if (!lws_create_vhost(context, &info)) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    lwsl_user("%s started", context_data.user_agent);
    signal(SIGTERM, sigterm_catch);
    signal(SIGINT, sigterm_catch);
    signal(SIGUSR1, sigterm_catch);
    signal(SIGUSR2, sigterm_catch);
    while (!interrupted) {
        if (lws_service(context, 0) < 0) {
            lwsl_err("lws_service failed");
            break;
        }
    }

    lws_context_destroy(context);

    return 0;
}
