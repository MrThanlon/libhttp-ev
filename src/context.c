#include "context.h"
#include "event_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

// FIXME: auto set BUFFER_SIZE
#define BUFFER_SIZE 4096

static const char *get_status_message(unsigned int status) {
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
            return "Request Entity Too Large";
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
 * Reset context but not free memory, for recycling context.
 * @param context
 */
static void reset_context(http_context_t *context) {
    context->ready_to_close = 0;
    context->state = HTTP_CONTEXT_STATE_PARSING;
    // reset parser
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
}

/**
 * Free context memory.
 * @param context
 */
void free_context(http_context_t *context) {
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);
}

// TODO: use a better free policy, use lock-free queue
/**
 * Recycle used context to pool.
 * @param context
 */
void recycle_context(http_context_t *context) {
    // just free
    free_context(context);
}


/**
 * Get a new context from pool, or create one. TODO: merge get new and create
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

http_context_t *http_create_context(http_server_t* server, int socket_fd) {
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
    // join loop
    ev_io_init(&context->watcher, tcp_read_cb, socket_fd, EV_READ);
    ev_io_start(server->loop, &context->watcher);
    return context;
}

void close_context(http_context_t *context) {
    context->state = HTTP_CONTEXT_STATE_CLOSED;
    ev_io_stop(context->server->loop, &context->watcher);
    close(context->watcher.fd);
    recycle_context(context);
    /*
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_BODY) && (context->response.body.data != NULL)) {
        free(context->response.body.data);
    }
    if (!(context->flags | HTTP_O_NOT_FREE_RESPONSE_HEADER) && (context->response.headers.fields != NULL)) {
        free(context->response.headers.fields);
    }
    free(context->request.headers.fields);
    free(context->buffer);
    free(context);*/
}


/**
 * Dispatch context to handler. TODO: update
 * @param context
 */
void http_dispatch(http_context_t *context) {
    // search url
    http_url_trie_node_t *node = &context->server->url_root;
    http_handler_t handler = node->handler;
    size_t idx = 1;
    while (idx < context->request.url.len && node != NULL) {
        if (node->handler != NULL) {
            handler = node->handler;
        }
        node = node->children[context->request.url.data[idx] - '%'];
        idx += 1;
    }
    // run handler
    if (handler != NULL) {
        // TODO: multi-threading
        unsigned int status = handler(context);
        if (context->state == HTTP_CONTEXT_STATE_PENDING) {
            // just return
            return;
        }
        if (context->ready_to_close) {
            // already handled, return
            return;
        }
        // TODO: use write callback
        FILE *socket_f = fdopen(context->watcher.fd, "w");
        fprintf(socket_f, "HTTP/1.1 %u %s\r\n", status, get_status_message(status));
        for (size_t i = 0; i < context->response.headers.len; i++) {
            fprintf(socket_f,
                    "%.*s: %.*s\r\n",
                    (int) context->response.headers.fields[i].key.len,
                    context->response.headers.fields[i].key.data,
                    (int) context->response.headers.fields[i].value.len,
                    context->response.headers.fields[i].value.data
            );
        }
        // body
        if (status != 200 && context->response.body.len == 0) {
            // FIXME: default err body
            // Content-Length
            fprintf(socket_f, "Content-Length: %zu\r\n\r\n", strlen(get_status_message(status)));
            fputs(get_status_message(status), socket_f);
        } else {
            // Content-Length
            fprintf(socket_f, "Content-Length: %zu\r\n\r\n", context->response.body.len);
            fwrite(context->response.body.data, context->response.body.len, 1, socket_f);
        }
        fclose(socket_f);
    } else {
        // 404
        write(context->watcher.fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 45);
    }
    context->ready_to_close = 0x7f;
}
