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

void tcp_read_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_context_t *context = (http_context_t *) watcher;
    if (EV_ERROR & revents) {
        // error, close
        close_context(context);
        return;
    }
    // receiving message
    ssize_t bytes = read(watcher->fd,
                         context->buffer + context->buffer_ptr,
                         context->buffer_capacity - context->buffer_ptr);
    /*recv(watcher->fd,
         context->buffer + context->buffer_ptr,
         context->buffer_capacity - context->buffer_ptr,
         0);*/
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
#if DEBUG
        puts("client close");
#endif
        close_context(context);
    } else {
        // received
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
        enum llhttp_errno err = llhttp_execute(&context->parser, context->buffer + context->buffer_ptr, bytes);
        if (err == HPE_OK) {
            context->buffer_ptr += bytes;
            if (context->ready_to_close) {
#if DEBUG
                static size_t counts = 0;
                counts += 1;
                printf("context over, %zu request\n", counts);
#endif
                close_context(context);
            }
        } else {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            close_context(context);
        }
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
    if (set_non_block(client_fd)) {
        // failed to set non-block
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        close(client_fd);
        return;
    }
    // operate context, TODO: set timer
    http_create_context(server, client_fd);
}