#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "libwebsockets.h"

#ifndef WSS_PLUGIN_VERSION
#define WSS_PLUGIN_VERSION "0.1.4"
#endif

#define USER_AGENT_MAX_LENGTH 64
static char user_agent[USER_AGENT_MAX_LENGTH];
static int user_agent_length;
static struct lws_client_connect_info cc_info;
#define BUF_SIZE 4096

static volatile int count = 0;

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

struct wsi_data_wss {
    int state;
    struct lws *wsi;
    size_t len;
    char pre[LWS_PRE]; /** reserved for wss frame **/
    char buf[BUF_SIZE];
};

struct wsi_data {
    int state;
    struct lws *wsi;
    size_t len;
    char buf[BUF_SIZE];
};

enum {
    STATE_ESTABLISHED = 1,
    STATE_CLOSED,
};

struct wsi_proxy {
    struct wsi_data_wss local;
    struct wsi_data remote;
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
#define USR_LOCAL "/usr/local"
#define CERT_PEM "/etc/ssl/cert.pem"
    if (connect_info->ssl_connection == LCCSCF_USE_SSL) {
        if (cert != NULL && access(cert, R_OK) == 0) {
            info->client_ssl_ca_filepath = cert;
        } else if (access(CERT_PEM, R_OK) == 0) {
            info->client_ssl_ca_filepath = CERT_PEM;
        } else if (access(USR_LOCAL CERT_PEM, R_OK) == 0) {
            info->client_ssl_ca_filepath = USR_LOCAL CERT_PEM;
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

#ifndef ATTR_UNUSED
#define ATTR_UNUSED __attribute__((unused))
#endif
static int callback_proxy(struct lws *wsi, enum lws_callback_reasons reason, ATTR_UNUSED void *user, void *in, size_t len) {
    switch (reason) {
        // remote
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            unsigned char **p = (unsigned char **) in;
            unsigned char *end = *p + len;
            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_USER_AGENT,
                                             (unsigned char *) user_agent, user_agent_length, p, end)) {
                lwsl_user("cannot add user_agent");
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_notice("LWS_CALLBACK_CLIENT_ESTABLISHED, local wsi was closed, wsi: %p", wsi);
                break;
            }
            if (proxy->remote.wsi != wsi || proxy->local.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_CLIENT_ESTABLISHED, no proxy in wsi: %p", wsi);
                break;
            }
            lwsl_notice("LWS_CALLBACK_CLIENT_ESTABLISHED, wsi: %p", wsi);
            proxy->remote.state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_notice("LWS_CALLBACK_CLIENT_RECEIVE, local wsi was closed, wsi: %p", wsi);
                break;
            }
            if (proxy->remote.wsi != wsi || proxy->local.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_CLIENT_RECEIVE, no proxy in wsi: %p", wsi);
                break;
            }
            if (proxy->remote.len && proxy->remote.len + len > BUF_SIZE) {
                lwsl_err("LWS_CALLBACK_CLIENT_RECEIVE, remote buf is full in wsi: %p", wsi);
                return -1;
            }
            lwsl_notice("LWS_CALLBACK_CLIENT_RECEIVE, wsi: %p", wsi);
            memcpy(proxy->remote.buf + proxy->remote.len, in, len);
            proxy->remote.len += len;
            // block wsi until local buf is empty
            lws_rx_flow_control(wsi, 0);
            if (proxy->local.state == STATE_ESTABLISHED) {
                lws_callback_on_writable(proxy->local.wsi);
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_notice("LWS_CALLBACK_CLIENT_WRITEABLE, local wsi was closed, wsi: %p", wsi);
                break;
            }
            if (proxy->remote.wsi != wsi || proxy->local.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_CLIENT_WRITEABLE, no proxy in wsi: %p", wsi);
                break;
            }
            lwsl_notice("LWS_CALLBACK_CLIENT_WRITEABLE, wsi: %p", wsi);
            if (proxy->local.len > 0) {
                int n = lws_write(wsi, (unsigned char *) proxy->local.buf, proxy->local.len, LWS_WRITE_BINARY);
                if (n < 0) {
                    lwsl_warn("write to remote wsi %p failed: %d", wsi, n);
                    return -1;
                }
                proxy->local.len = 0;
            }
            lws_rx_flow_control(proxy->local.wsi, 1);
            break;
        }
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            return -1;
        case LWS_CALLBACK_CLIENT_CLOSED: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_notice("LWS_CALLBACK_CLIENT_CLOSED, local wsi was closed, wsi: %p", wsi);
                break;
            }
            if (proxy->remote.wsi != wsi || proxy->local.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_CLIENT_CLOSED, no proxy in wsi: %p", wsi);
                break;
            }
            if (proxy->remote.state == STATE_CLOSED) {
                lwsl_err("LWS_CALLBACK_CLIENT_CLOSED, was closed, wsi: %p", wsi);
                break;
            }
            proxy->remote.state = STATE_CLOSED;
            if (proxy->local.state != STATE_ESTABLISHED && proxy->remote.len > 0) {
                lwsl_warn("LWS_CALLBACK_CLIENT_CLOSED, wsi: %p, remain %d for local wsi: %p",
                          wsi, (int) proxy->remote.len, proxy->local.wsi);
                break;
            }
            if (proxy->remote.len > 0) {
                lwsl_notice("LWS_CALLBACK_CLIENT_CLOSED, wsi: %p", wsi);
                lws_callback_on_writable(proxy->local.wsi);
            } else {
                lwsl_warn("LWS_CALLBACK_CLIENT_CLOSED, wsi: %p, would close local wsi: %p", wsi, proxy->local.wsi);
                lws_callback_on_writable(proxy->local.wsi);
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_notice("LWS_CALLBACK_CLIENT_CONNECTION_ERROR, local wsi was closed, wsi: %p", wsi);
                break;
            }
            if (proxy->remote.wsi != wsi || proxy->local.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_CLIENT_CONNECTION_ERROR, no proxy in wsi: %p", wsi);
                break;
            }
            proxy->remote.state = STATE_CLOSED;
            if (proxy->local.state == STATE_ESTABLISHED) {
                lwsl_warn("LWS_CALLBACK_CLIENT_CONNECTION_ERROR, wsi: %p, would close local wsi: %p, reason: %s",
                          wsi, proxy->local.wsi, in ? (char *) in : "(null)");
                lws_callback_on_writable(proxy->local.wsi);
            } else {
                lwsl_notice("LWS_CALLBACK_CLIENT_CONNECTION_ERROR, wsi: %p", wsi);
            }
            break;
        }
            // local
        case LWS_CALLBACK_RAW_ADOPT: {
            struct lws *wss;
            struct wsi_proxy *proxy;
            proxy = lws_wsi_user(wsi);
            if (proxy == NULL) {
                lwsl_warn("no user data in wsi: %p", wsi);
                return -1;
            }
            memset(proxy, 0, sizeof(struct wsi_proxy));
            cc_info.userdata = proxy;
            wss = lws_client_connect_via_info(&cc_info);
            if (wss == NULL) {
                lwsl_warn("cannot connect to remote for wsi: %p", wsi);
                return -1;
            }
            proxy->local.wsi = wsi;
            proxy->remote.wsi = wss;
            proxy->local.state = STATE_ESTABLISHED;
            lws_callback_on_writable(wsi);
            lwsl_user("LWS_CALLBACK_RAW_ADOPT, local wsi: %p, remote wsi: %p, count: %d", wsi, wss, ++count);
            break;
        }
        case LWS_CALLBACK_RAW_RX: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL || proxy->local.wsi != wsi || proxy->remote.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_RAW_RX, no proxy in wsi: %p", wsi);
                break;
            }
            if (proxy->local.len && proxy->local.len + len > BUF_SIZE) {
                lwsl_err("LWS_CALLBACK_RAW_RX, local buf is full in wsi: %p", wsi);
                return -1;
            }
            lwsl_notice("LWS_CALLBACK_RAW_RX, local wsi: %p", wsi);
            memcpy(proxy->local.buf + proxy->local.len, in, len);
            proxy->local.len += len;
            // block wsi until buf is empty
            lws_rx_flow_control(wsi, 0);
            lws_callback_on_writable(proxy->remote.wsi);
            break;
        }
        case LWS_CALLBACK_RAW_WRITEABLE: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL || proxy->local.wsi != wsi || proxy->remote.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_RAW_WRITEABLE, no proxy in wsi: %p", wsi);
                break;
            }
            if (proxy->remote.len > 0) {
                int n = lws_write(wsi, (unsigned char *) proxy->remote.buf, proxy->remote.len, LWS_WRITE_RAW);
                if (n < 0) {
                    lwsl_warn("LWS_CALLBACK_RAW_WRITEABLE, write to local wsi failed for wsi: %p", wsi);
                    return -1;
                }
                proxy->remote.len = 0;
            }
            if (proxy->remote.state == STATE_CLOSED) {
                lwsl_user("LWS_CALLBACK_RAW_WRITEABLE, would close local as remote wsi is closed");
                return -1;
            }
            lwsl_notice("LWS_CALLBACK_RAW_WRITEABLE, local wsi: %p", wsi);
            lws_rx_flow_control(proxy->remote.wsi, 1);
            break;
        }
        case LWS_CALLBACK_RAW_CLOSE: {
            struct wsi_proxy *proxy = lws_wsi_user(wsi);
            if (proxy == NULL || proxy->local.wsi != wsi || proxy->remote.wsi == NULL) {
                lwsl_err("LWS_CALLBACK_RAW_CLOSE, no proxy in wsi: %p", wsi);
                break;
            }
            if (proxy->local.state == STATE_CLOSED) {
                lwsl_warn("LWS_CALLBACK_RAW_CLOSE, closed, wsi: %p, proxy local: %p, proxy remote: %p, remain: %d",
                          wsi, proxy->local.wsi, proxy->remote.wsi, (int) proxy->remote.len);
                break;
            }
            proxy->local.state = STATE_CLOSED;
            if (proxy->remote.state == STATE_ESTABLISHED) {
                lws_set_wsi_user(proxy->remote.wsi, NULL);
                lwsl_notice("LWS_CALLBACK_RAW_CLOSE, would close remote wsi: %p", wsi);
                lws_close_reason(proxy->remote.wsi, LWS_CLOSE_STATUS_GOINGAWAY, (unsigned char *) "seeya", 5);
            }
            lwsl_user("LWS_CALLBACK_RAW_CLOSE, local wsi: %p, remote wsi: %p, count: %d",
                      wsi, proxy->remote.wsi, --count);
            break;
        }
        default:
            break;
    }

    return 0;
}

int main() {
    struct lws_context *context;
    struct lws_context_creation_info info;
    const struct lws_protocols protocols[] = {
            {
                    "proxy", callback_proxy, sizeof(struct wsi_proxy), BUF_SIZE, 0, NULL, 0
            },
            { NULL, NULL, 0, 0, 0, NULL, 0 }
    };

    // loglevel
    if (strstr(getenv("SS_PLUGIN_OPTIONS"), "loglevel=debug") != NULL) {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);
    } else {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER, NULL);
    }

    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.gid = (gid_t) -1;
    info.uid = (uid_t) -1;
    info.protocols = protocols;
    info.vhost_name = "context";
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws_create_context failed");
        return 1;
    }

    memset(&cc_info, 0, sizeof cc_info);
    if (init_connect_info(&info, &cc_info)) {
        return EXIT_FAILURE;
    }
    info.vhost_name = cc_info.host;
    cc_info.context = context;
    cc_info.vhost = lws_create_vhost(context, &info);
    if (!cc_info.vhost) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    user_agent_length = snprintf(user_agent, USER_AGENT_MAX_LENGTH, "wss-plugin/%s lws/%s", WSS_PLUGIN_VERSION, lws_get_library_version());

    if (init_local_info(&info)) {
        return EXIT_FAILURE;
    }
    // since lws 3.2.0
    info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
    info.listen_accept_role = "raw-skt";
    if (!lws_create_vhost(context, &info)) {
        lwsl_err("lws_create_vhost failed");
        return 1;
    }

    lwsl_user("%s started", user_agent);
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
