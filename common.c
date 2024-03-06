#include <signal.h>
#include "common.h"

static volatile int interrupted;

static void on_signal(int signal) {
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

uint16_t get_port(struct lws *wsi) {
    socklen_t len;
    struct sockaddr_storage sin;
    len = sizeof(sin);
    if (getpeername(lws_get_socket_fd(wsi), (struct sockaddr *) &sin, &len) == -1) {
        return 0;
    }
    if (sin.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) &sin)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) &sin)->sin_port);
    }
}

struct lws_context *create_context(struct lws_context_creation_info *info) {
    struct lws_context *context;
    info->connect_timeout_secs = 10;
    info->timeout_secs = 30;
    info->pt_serv_buf_size = PT_SERV_BUF_SIZE;
    info->options |= LWS_SERVER_OPTION_LIBUV;
    if ((context = lws_create_context(info)) != NULL) {
        lwsl_user("created context with libuv");
        return context;
    }
    info->options &= (uint64_t) ~LWS_SERVER_OPTION_LIBUV;
    info->options |= LWS_SERVER_OPTION_ULOOP;
    if ((context = lws_create_context(info)) != NULL) {
        lwsl_user("created context with uloop");
        return context;
    }
    info->options &= (uint64_t) ~LWS_SERVER_OPTION_ULOOP;
    return lws_create_context(info);
}

void run(struct lws_context *context) {
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);
    while (!interrupted) {
        if (lws_service(context, 0) < 0) {
            lwsl_err("lws_service failed");
            break;
        }
    }
    lws_context_destroy(context);
}

void init_log_level(int argc, char **argv) {
    const char *plugin_options;

    plugin_options = getenv("SS_PLUGIN_OPTIONS");
    if ((plugin_options != NULL && strstr(plugin_options, "loglevel=debug") != NULL)
        || (argc > 1 && strcmp(argv[1], "-v") == 0)) {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);
    } else {
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER, NULL);
    }
}

int callback_on_endpoint_writable(struct lws *wsi) {
    return lws_callback_on_writable(lws_get_opaque_parent_data(wsi));
}

int rx_flow_control_endpoint(struct lws *wsi, int enable) {
    return lws_rx_flow_control(lws_get_opaque_parent_data(wsi), enable);
}

int set_wsi_closing(struct lws *wsi) {
    if (lws_get_opaque_user_data(wsi) == wsi) {
        return 0;
    }
    lws_set_opaque_user_data(wsi, wsi);
    return 1;
}