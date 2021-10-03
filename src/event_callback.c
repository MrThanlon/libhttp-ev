#include "event_callback.h"
#include "http.h"
#include "context.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

// FIXME: auto set BUFFER_SIZE
#define BUFFER_SIZE 4096

int set_non_block(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return flags;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) return -1;
    return 0;
}

static void tcp_write_cb(http_context_t *context) {
    // FIXME: one pass write(?)
    if (context->write_ptr < context->buffer_ptr) {
        // write buffer
        context->write_ptr += write(context->watcher.fd,
                                    context->buffer + context->write_ptr,
                                    context->buffer_ptr - context->write_ptr);
    }
    if (context->write_ptr >= context->buffer_ptr &&
        context->write_ptr < context->buffer_ptr + context->response.body.len) {
        // write response
        size_t response_ptr = context->write_ptr - context->buffer_ptr;
        context->write_ptr += write(context->watcher.fd,
                                    context->response.body.data + response_ptr,
                                    context->response.body.len - response_ptr);
    }
    if (context->write_ptr >= context->buffer_ptr + context->response.body.len) {
        // finish
        reset_context(context);
    }
}

static void tcp_read_cb(http_context_t *context) {
    // receiving message
    ssize_t bytes = read(context->watcher.fd,
                         context->buffer + context->buffer_ptr,
                         context->buffer_capacity - context->buffer_ptr);
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, continue
            return;
        }
        // error or close
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        close_context(context);
    } else if (bytes == 0) {
        // client close
        close_context(context);
    } else {
        // received
        // TODO: check header field size
        if (context->buffer_ptr + bytes >= context->server->max_request_size) {
            // exceed
            context->response.status_code = 413;
            http_response(context);
            return;
        }
        if (context->buffer_ptr + bytes >= context->buffer_capacity) {
            // expansion
            context->buffer_capacity += BUFFER_SIZE;
            char *new_buffer = (char *) realloc(context->buffer, context->buffer_capacity);
            if (new_buffer == NULL) {
                // error, close
                if (context->server->err_handler != NULL) {
                    context->server->err_handler(errno);
                }
                close_context(context);
                return;
            }
            context->buffer = new_buffer;
        }
        // execute parser
        context->state = HTTP_CONTEXT_STATE_PARSE;
        enum llhttp_errno err = llhttp_execute(&context->parser, context->buffer + context->buffer_ptr, bytes);
        if (context->state == HTTP_CONTEXT_STATE_CLOSED) {
            close_context(context);
            return;
        }
        if (err == HPE_OK) {
            context->buffer_ptr += bytes;
        } else {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            close_context(context);
        }
    }
}

void watcher_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_context_t *context = (http_context_t *) watcher;
    if (revents & EV_ERROR) {
        if (context->server->err_handler != NULL) {
            context->server->err_handler(errno);
        }
        close_context(context);
        return;
    } else if (revents & EV_READ) {
        tcp_read_cb(context);
    } else {
        tcp_write_cb(context);
    }
}

void tcp_accept_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    if (EV_ERROR & revents) {
        return;
    }
    // accept
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    client_fd = accept(watcher->fd, (struct sockaddr *) &addr, &addr_len);
    if (client_fd < 0) {
        // error
        return;
    }
    http_server_t *server = (http_server_t *) watcher;
    if (errno == ENFILE) {
        // unable to accept, close
        close(client_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return;
    }
    if (server->connections >= server->max_connections) {
        // close
        close(client_fd);
        return;
    }
    if (set_non_block(client_fd)) {
        // failed to set non-block
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        close(client_fd);
        return;
    }
    // operate context
    http_context_t *context = http_create_context(server, client_fd);
    if (context == NULL) {
        // err
        return;
    }
    server->connections += 1;
    if (server->before_parse != NULL) {
        server->before_parse(context);
    }
}