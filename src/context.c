#include "context.h"
#include "event_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

// FIXME: auto set BUFFER_SIZE
#define BUFFER_SIZE 4096

const char *get_status_message(unsigned int status) {
    switch (status) {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 102:
            return "Processing";
        case 103:
            return "Early Hints";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 207:
            return "Multi-Status";
        case 208:
            return "Already Reported";
        case 226:
            return "IM Used";
        case 300:
            return "300";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 306:
            return "Switch Proxy";
        case 307:
            return "Temporary Redirect";
        case 308:
            return "Permanent Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Require";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Payload Too Large";
        case 414:
            return "Request-URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Requested Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 418:
            return "I'm a teapot";
        case 421:
            return "Misdirected Request";
        case 422:
            return "Unprocessable Entity";
        case 423:
            return "Locked";
        case 424:
            return "Failed Dependency";
        case 425:
            return "Too Early";
        case 426:
            return "Upgrade Required";
        case 428:
            return "Precondition Required";
        case 429:
            return "Too Many Requests";
        case 431:
            return "Request Header Fields Too Large";
        case 440:
            return "Login Time-out";
        case 451:
            return "Unavailable For Legal Reasons";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        case 506:
            return "Variant Also Negotiates";
        case 507:
            return "Insufficient Storage";
        case 508:
            return "Loop Detected";
        case 510:
            return "Not Extended";
        case 511:
            return "Network Authentication Required";
        default:
            return "Unknown";
    }
}

/**
 * Reset context to receive new request.
 * @param context
 */
void reset_context(http_context_t *context) {
    // call hooks
    if (context->post_response_handler != NULL) {
        context->post_response_handler(context);
    }
    if (context->state != HTTP_CONTEXT_STATE_RESPONSE) {
        // for websocket, do nothing
        return;
    }
    // check limitation
    if (context->server->max_request > 0 && context->requests >= context->server->max_request) {
        // close
        close_context(context);
        return;
    }
    // reset state
    context->state = HTTP_CONTEXT_STATE_WAIT;
    // parser
    llhttp_reset(&context->parser);
    // reset buffer, but not free memory
    context->buffer_ptr = 0;
    // reset request
    context->request.url.len = 0;
    context->request.headers.len = 0;
    context->request.body.len = 0;
    // reset response
    context->response.headers.len = 0;
    context->response.body.len = 0;
    // ev
    ev_io_stop(context->server->loop, &context->watcher);
#if EV_VERSION_MAJOR >= 4 && EV_VERSION_MINOR >= 32
    ev_io_modify(&context->watcher, EV_READ);
#else
    ev_io_set(&context->watcher, context->watcher.fd, EV_READ);
#endif
    ev_io_start(context->server->loop, &context->watcher);
    // write_ptr
    context->write_ptr = 0;
}

/**
 * Free context memory.
 * @param context
 */
static void free_context(http_context_t *context) {
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);
}

// TODO: use pool to store unused context object.
/**
 * Recycle used context to pool.
 * @param context
 */
void recycle_context(http_context_t *context) {
    // just free
    free_context(context);
}


/**
 * Get a new context from pool, or create one. Allocate memory for buffer.
 * @return context
 */
http_context_t *get_new_context() {
    http_context_t *context = (http_context_t *) malloc(sizeof(http_context_t));
    bzero(context, sizeof(http_context_t));
    // init request buffer
    context->buffer = (char *) malloc(BUFFER_SIZE);
    if (context->buffer == NULL) {
        // error, close
        free(context);
        return NULL;
    }
    context->buffer_capacity = BUFFER_SIZE;
    // init request header buffer
    context->request.headers.capacity = 10;
    context->request.headers.fields = malloc(10 * sizeof(http_header_field_t));
    if (context->request.headers.fields == NULL) {
        // error, close
        free(context->buffer);
        free(context);
        return NULL;
    }
    return context;
}

static http_context_t *get_context_from_timer(ev_timer *watcher) {
    return (http_context_t *) ((void *) watcher - offsetof(http_context_t, timer));
}

void timer_cb(struct ev_loop *loop, ev_timer *watcher, int revents) {
    // timeout, check last request time
    http_context_t *context = get_context_from_timer(watcher);
    ev_timer_stop(loop, watcher);
    context->state = HTTP_CONTEXT_STATE_TIMEOUT;
    // TODO: check state, do not close directly
    close_context(context);
}

/**
 * Create new context.
 * @param server
 * @param socket_fd
 * @return
 */
http_context_t *http_create_context(http_server_t *server, int socket_fd) {
    http_context_t *context = get_new_context();
    if (context == NULL) {
        // failed, close
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return NULL;
    }
    context->server = server;
    // init llhttp
    llhttp_init(&context->parser, HTTP_REQUEST, &server->parser_settings);
    // ev
    // timer
    if (server->client_timeout > 0) {
        // not greater than 0 means unlimited
        ev_timer_init(&context->timer, timer_cb, server->client_timeout, 0);
        ev_timer_start(server->loop, &context->timer);
    }
    // socket
    ev_io_init(&context->watcher, watcher_cb, socket_fd, EV_READ);
    ev_io_start(server->loop, &context->watcher);
    return context;
}

/**
 * Close socket, free memory, remove watcher from event loop.
 * @param context
 */
void close_context(http_context_t *context) {
    // clear timer
    if (ev_is_active(&context->timer)) {
        ev_timer_stop(context->server->loop, &context->timer);
    }
    // call hooks
    if (context->server->before_close != NULL) {
        context->server->before_close(context);
    }
    context->state = HTTP_CONTEXT_STATE_CLOSED;
    // unnecessary, for websocket
    if (ev_is_active(&context->watcher)) {
        ev_io_stop(context->server->loop, &context->watcher);
    }
    close(context->watcher.fd);
    recycle_context(context);
}

/**
 * Dispatch context to handler.
 * @param context
 */
void http_dispatch(http_context_t *context) {
    // search url
    http_url_trie_node_t *node = &context->server->url_root;
    http_handler_t handler = node->handler;
    size_t idx = 1;
    while (idx <= context->request.url.len && node != NULL) {
        if (node->handler != NULL) {
            handler = node->handler;
        }
        node = node->children[context->request.url.data[idx] - '%'];
        idx += 1;
    }
    // run handler
    if (handler != NULL) {
        context->state = HTTP_CONTEXT_STATE_HANDLING;
        handler(context);
        if (context->state == HTTP_CONTEXT_STATE_HANDLING) {
            context->state = HTTP_CONTEXT_STATE_PENDING;
        }
    } else {
        // 404
        context->response.status_code = 404;
        http_response(context, NULL);
    }
}
