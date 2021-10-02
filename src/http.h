//
// Created by Ziyi Huang on 2021/9/21.
//

#ifndef TEST_C_HTTP_H
#define TEST_C_HTTP_H

#include <ev.h>
#include <llhttp.h>
#include <semaphore.h>
#include <pthread.h>

typedef struct http_string_s http_string_t;
typedef struct http_header_field_s http_header_field_t;
typedef struct http_headers_s http_headers_t;
typedef struct http_response_s http_response_t;
typedef struct http_request_s http_request_t;
typedef struct http_url_trie_node_s http_url_trie_node_t;
typedef struct http_server_s http_server_t;
typedef enum llhttp_method http_method_t;
typedef struct http_context_s http_context_t;
typedef struct http_fd_queue_s http_fd_queue_t;
typedef struct http_fd_queue_node_s http_fd_queue_node_t;

typedef unsigned int (*http_handler_t)(http_context_t *context);

typedef void (*http_err_handler)(int err);

struct http_string_s {
    size_t len;
    unsigned char *data;
};

struct http_header_field_s {
    http_string_t key;
    http_string_t value;
};

struct http_headers_s {
    size_t len;
    size_t capacity;
    http_header_field_t *fields;
};

struct http_request_s {
    http_method_t method;
    http_string_t url;
    http_headers_t headers;
    http_string_t body;
};

struct http_response_s {
    http_headers_t headers;
    http_string_t body;
};

typedef enum {
    HTTP_CONTEXT_STATE_PARSING = 0,
    HTTP_CONTEXT_STATE_HANDLING,
    HTTP_CONTEXT_STATE_PENDING,
    HTTP_CONTEXT_STATE_RESPONSE,
    HTTP_CONTEXT_STATE_CLOSED,
    HTTP_CONTEXT_STATE_TIMEOUT
} http_context_state_t;

struct http_context_s {
    ev_io watcher;
    ev_timer timer;
    llhttp_t parser;
    http_server_t *server;
    http_request_t request;
    http_response_t response;
    http_context_state_t state;
    ev_io write_watcher;
    size_t write_ptr;
    char *buffer;
    size_t buffer_ptr;
    size_t buffer_capacity;
    char ready_to_close;
    int flags;
};

struct http_url_trie_node_s {
    // code for 37(%) to 126(~)
    http_url_trie_node_t *children[89];
    http_handler_t handler;
};

// TODO: bind address, limit size
struct http_server_s {
    ev_io tcp_watcher;
    struct ev_loop *loop;
    int socket_fd;
    http_url_trie_node_t url_root;
    llhttp_settings_t parser_settings;
    http_err_handler err_handler;
    // settings
    int port;
    // limit
    int max_connections;
    int max_context;
    size_t client_timeout;
    size_t max_url_len;
    size_t max_headers_size;
    size_t max_body_size;
};

http_server_t *http_create_server(void);
int http_register_url(http_server_t *server, const char *url, http_handler_t handler);
int http_server_run_multi_process(http_server_t *server, int process);
int http_server_run_multi_thread(http_server_t *server, int threads);
int http_server_run_single_process(http_server_t *server);
unsigned int http_send_file(http_context_t *context, const char *path, const char *index);
void http_complete(http_context_t *context);
void http_set_async(http_context_t *context);

#endif //TEST_C_HTTP_H
