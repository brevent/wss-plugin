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
    if (getpeername(lws_get_socket_fd(wsi), (struct sockaddr *) &sin, &len) == -1) {
        return 0;
    }
    if (sin.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) &sin)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) &sin)->sin_port);
    }
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
