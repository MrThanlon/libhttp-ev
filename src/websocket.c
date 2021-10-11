#include "websocket.h"
#include "context.h"
#include <unistd.h>
#include <errno.h>
#include <nettle/base64.h>
#include <nettle/sha.h>

void ws_cb(struct ev_loop *loop, ev_io *watcher, int revents) {
    http_ws_t *ws = (http_ws_t *) watcher;
    if ((revents & EV_ERROR) ||
        ((revents & EV_READ) && wslay_event_recv(ws->context)) ||
        ((revents & EV_WRITE) && wslay_event_send(ws->context))) {
        // error
        if (ws->server->err_handler != NULL) {
            ws->server->err_handler(errno);
        }
        // close ws
        ev_io_stop(loop, watcher);
        close_context(ws->http_context);
        // call hook
        if (ws->handlers->on_close != NULL) {
            ws->handlers->on_close(ws);
        }
        free(ws);
        return;
    }
    int events = 0;
    if (wslay_event_want_read(ws->context)) {
        events |= EV_READ;
    }
    if (wslay_event_want_write(ws->context)) {
        events |= EV_WRITE;
    }
    ev_io_stop(loop, watcher);
    if (events == 0) {
        // close
        close_context(ws->http_context);
        // call hook
        if (ws->handlers->on_close != NULL) {
            ws->handlers->on_close(ws);
        }
        free(ws);
        return;
    }
#if EV_VERSION_MAJOR >= 4 && EV_VERSION_MINOR >= 32
    ev_io_modify(watcher, events);
#else
    ev_io_set(watcher, watcher->fd, events);
#endif
    ev_io_start(loop, watcher);
}

/*
 * Upgrade: websocket
 * Connection: Upgrade
 * Sec-WebSocket-Accept: %s(28 chars)
 */
http_header_field_t ws_header_fields[3] = {
        {
                .key={.len=7, .data=(unsigned char *) "Upgrade"},
                .value={.len=9, .data=(unsigned char *) "websocket"}
        },
        {
                .key={.len=10, .data=(unsigned char *) "Connection"},
                .value={.len=7, .data=(unsigned char *) "Upgrade"}
        },
        {
                .key={.len=20, .data=(unsigned char *) "Sec-WebSocket-Accept"},
                .value={.len=28, .data=NULL}
        }
};
http_headers_t ws_headers = {
        .len = 3,
        .capacity = 0,
        .fields = ws_header_fields
};

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf,
                             size_t len, int flags, void *user_data) {
    http_ws_t *ws = (http_ws_t *) user_data;
    ssize_t bytes = read(ws->watcher.fd, buf, len);
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    } else if (bytes == 0) {
        // EOF
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        bytes = -1;
    }
    return bytes;
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data,
                             size_t len, int flags, void *user_data) {
    http_ws_t *ws = (http_ws_t *) user_data;
    ssize_t bytes = write(ws->watcher.fd, data, len);
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    }
    return bytes;
}

/**
 * Websocket write message to client.
 * @param ws
 * @param opcode
 * @param message
 * @param len
 */
void http_ws_write(http_ws_t *ws, uint8_t opcode, const uint8_t *message, size_t len) {
    struct wslay_event_msg msg = {
            .opcode=opcode, .msg=message, .msg_length=len
    };
    ev_io_stop(ws->server->loop, &ws->watcher);
#if EV_VERSION_MAJOR >= 4 && EV_VERSION_MINOR >= 32
    ev_io_modify(&ws->watcher, EV_READ | EV_WRITE);
#else
    ev_io_set(&ws->watcher, ws->watcher.fd, EV_READ | EV_WRITE);
#endif
    ev_io_start(ws->server->loop, &ws->watcher);
    wslay_event_queue_msg(ws->context, &msg);
}

static void on_msg_recv_callback(wslay_event_context_ptr ctx,
                                 const struct wslay_event_on_msg_recv_arg *arg,
                                 void *user_data) {
    // call user handler
    http_ws_t *ws = (http_ws_t *) user_data;
    if (!wslay_is_ctrl_frame(arg->opcode) && ws->handlers->on_message != NULL) {
        ws->handlers->on_message(ws, arg->opcode, arg->msg, arg->msg_length);
    }
}

struct wslay_event_callbacks ws_callbacks = {
        recv_callback,
        send_callback,
        NULL,
        NULL,
        NULL,
        NULL,
        on_msg_recv_callback
};

static void ws_post_response(http_context_t *context) {
    // find handlers based on url
    http_url_trie_node_t *node = &context->server->url_root;
    http_ws_handlers_t *handlers = NULL;
    size_t idx = 1;
    while (idx <= context->request.url.len && node != NULL) {
        if (node->ws_handlers != NULL) {
            handlers = node->ws_handlers;
        }
        node = node->children[context->request.url.data[idx] - '%'];
        idx += 1;
    }
    if (handlers == NULL) {
        // FIXME: should be 404, match url before response
        close_context(context);
        return;
    }
    // generate ws context
    http_ws_t *ws = malloc(sizeof(http_ws_t));
    if (ws == NULL) {
        // error
        close_context(context);
        return;
    }
    ws->handlers = handlers;
    ws->server = context->server;
    ws->http_context = context;
    // copy template
    memcpy(&ws->callbacks, &ws_callbacks, sizeof(struct wslay_event_callbacks));
    if (wslay_event_context_server_init(&ws->context, &ws->callbacks, ws)) {
        // error, close
        close_context(context);
        return;
    }
    // ev
    // reset timer
    if (ev_is_active(&context->timer)) {
        ev_timer_stop(context->server->loop, &context->timer);
    }
    /*
    if (context->server->ws_timeout > 0) {
        ev_timer_init(&ws->timer, timer_cb, context->server->ws_timeout, 0);
    }*/
    // use ws_cb
    int fd = context->watcher.fd;
    ev_io_init(&ws->watcher, ws_cb, fd, EV_READ);
    ev_io_stop(context->server->loop, &context->watcher);
    ev_io_start(ws->server->loop, &ws->watcher);
    // call on_connection hooks
    if (handlers->on_connection != NULL) {
        handlers->on_connection(ws);
    }
    // set state, FIXME: use another way
    context->state = HTTP_CONTEXT_STATE_PENDING;
    // free headers
    free(context->response.headers.fields[2].value.data);
}

int ws_handshake(http_context_t *context) {
    // TODO: handshake, create ws
    // TODO: match url
    // find header field
    http_header_field_t *fields = context->request.headers.fields;
    int success = 0;
    const char *key = NULL;
    for (size_t i = 0; i < context->request.headers.len; i++) {
        if (fields[i].key.len == 10 &&
            fields[i].value.len == 7 &&
            memcmp(fields[i].key.data, "Connection", 10) == 0 &&
            memcmp(fields[i].value.data, "Upgrade", 7) == 0) {
            // Connection: Upgrade
            success += 1;
        } else if (fields[i].key.len == 7 &&
                   fields[i].value.len == 9 &&
                   memcmp(fields[i].key.data, "Upgrade", 7) == 0 &&
                   memcmp(fields[i].value.data, "websocket", 9) == 0) {
            success += 1;
        } else if (fields[i].key.len == 17 &&
                   fields[i].value.len == 24 &&
                   memcmp(fields[i].key.data, "Sec-WebSocket-Key", 17) == 0) {
            // Sec-WebSocket-Key: xxx(24 chars)
            success += 1;
            key = (const char *) fields[i].value.data;
        }
    }
    if (success < 3) {
        // bad request, TODO: response
        return -1;
    }
    // generate headers
    // copy headers from template
    memcpy(&context->response.headers, &ws_headers, sizeof(http_headers_t));
    unsigned char *accept_key = malloc(28);
    if (accept_key == NULL) {
        // error
        return -1;
    }
    context->response.headers.fields[2].value.data = accept_key;
    // create accept key
    unsigned char key_src[60], sha1buf[20];
    const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    memcpy(key_src, key, 24);
    memcpy(key_src + 24, WS_GUID, 36);
    // sha1
    struct sha1_ctx sha1ctx;
    sha1_init(&sha1ctx);
    sha1_update(&sha1ctx, 60, key_src);
    sha1_digest(&sha1ctx, SHA1_DIGEST_SIZE, sha1buf);
    // base64
    struct base64_encode_ctx base64ctx;
    base64_encode_init(&base64ctx);
    base64_encode_raw((char *) accept_key, 20, sha1buf);
    // response
    context->response.status_code = 101;
    context->response.body.len = 0;
    http_response(context, ws_post_response);
    return 0;
}