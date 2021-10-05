//
// Created by Ziyi Huang on 2021/9/21.
//

#include "http.h"
#include "parser.h"
#include "context.h"
#include "event_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stddef.h>
#include <errno.h>
#include <netinet/in.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pthread.h>

#if __APPLE__

#include <sys/uio.h>

#elif __linux__

#include <sys/sendfile.h>
#include <sys/prctl.h>

#endif

// FIXME: auto set buffer size
#define BUFFER_SIZE 4096
#define DEBUG 0

/**
 * Close connection.
 * @param context
 */
void http_close_connection(http_context_t *context) {
    // context->state = HTTP_CONTEXT_STATE_CLOSED;
    close_context(context);
}

/**
 * Response to client.
 * @param context
 */
void http_response(http_context_t *context, http_handler_t handler) {
    if (context->flags & HTTP_CONTEXT_FLAG_CHUNKED) {
        // error: should use write_chunk(), TODO: handler error
        return;
    }
    context->state = HTTP_CONTEXT_STATE_RESPONSE;
    // generate headers string
    if (context->response.status_code > 511) {
        context->response.status_code = 500;
    }
    const char *status_message = get_status_message(context->response.status_code);
    size_t status_message_len = strlen(status_message);
    if (context->response.status_code != 200 && context->response.body.len == 0) {
        // TODO: use custom error page
        context->response.body.data = (unsigned char *) status_message;
        context->response.body.len = status_message_len;
    }
    // check headers len, "HTTP/1.1 xxx xxx\r\n" + "Content-Length: xxx\r\n"
    size_t headers_len = 15 + status_message_len + 18 + (size_t) log10((double) context->response.body.len);
    // keep-alive
    if (context->server->max_request != 0) {
        // "Connection: keep-alive\r\n"
        headers_len += 24;
        if (context->server->max_request > 0) {
            // "Keep-Alive: timeout=xx, max=xx\r\n"
            headers_len += 28 +
                           (size_t) log10((double) context->server->max_request) +
                           (size_t) log10((double) context->server->client_timeout);
        }
    } else {
        // "Connection: close\r\n"
        headers_len += 19;
    }
    // TODO: Accept-Ranges
    for (size_t i = 0; i < context->response.headers.len; i++) {
        headers_len += context->response.headers.fields[i].key.len +
                       context->response.headers.fields[i].value.len + 4;
    }
    if (context->buffer_capacity < headers_len) {
        // expansion
        context->buffer_capacity = headers_len;
        char *new_buffer = realloc(context->buffer, headers_len);
        if (new_buffer == NULL) {
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            close_context(context);
            return;
        }
        context->buffer = new_buffer;
    }
    // first line and Content-Length
    context->buffer_ptr = sprintf(context->buffer,
                                  "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\n",
                                  context->response.status_code,
                                  status_message,
                                  context->response.body.len);
    // keep-alive
    if (context->server->max_request != 0) {
        // "Connection: keep-alive\r\n"
        memcpy(context->buffer + context->buffer_ptr, "Connection: keep-alive\r\n", 24);
        context->buffer_ptr += 24;
        if (context->server->max_request > 0) {
            // "Keep-Alive: timeout=xx, max=xx\r\n"
            context->buffer_ptr += sprintf(context->buffer + context->buffer_ptr,
                                           "Keep-Alive: timeout=%d, max=%d",
                                           context->server->client_timeout,
                                           context->server->max_request);
        }
    } else {
        // "Connection: close\r\n"
        memcpy(context->buffer + context->buffer_ptr, "Connection: close\r\n", 19);
        context->buffer_ptr += 19;
    }
    // header fields
    for (size_t i = 0; i < context->response.headers.len; i++) {
        memcpy(context->buffer + context->buffer_ptr,
               context->response.headers.fields[i].key.data,
               context->response.headers.fields[i].key.len);
        context->buffer_ptr += context->response.headers.fields[i].key.len;
        memcpy(context->buffer + context->buffer_ptr, ": ", 2);
        context->buffer_ptr += 2;
        memcpy(context->buffer + context->buffer_ptr,
               context->response.headers.fields[i].value.data,
               context->response.headers.fields[i].value.len);
        context->buffer_ptr += context->response.headers.fields[i].value.len;
        memcpy(context->buffer + context->buffer_ptr, "\r\n", 2);
        context->buffer_ptr += 2;
    }
    // last CRLF
    memcpy(context->buffer + context->buffer_ptr, "\r\n", 2);
    context->buffer_ptr += 2;
    // handler
    context->post_response_handler = handler;
    // ev
    ev_io_init(&context->watcher, watcher_cb, context->watcher.fd, EV_WRITE);
    ev_io_start(context->server->loop, &context->watcher);
}

/**
 * Response with Transfer-Encoding: chunked
 * @param context
 * @param chunk

void http_write_chunk(http_context_t *context, http_string_t chunk) {
    context->flags |= HTTP_CONTEXT_FLAG_CHUNKED;
    if (context->state != HTTP_CONTEXT_STATE_RESPONSE) {
        // TODO: write headers
        context->state = HTTP_CONTEXT_STATE_RESPONSE;
    }
    char buffer[10];
    // to hex str
    int len = sprintf(buffer, "%zX\r\n", chunk.len);
    write(context->watcher.fd, buffer, len);
    write(context->watcher.fd, chunk.data, chunk.len);
    write(context->watcher.fd, "\r\n", 2);
} */

/**
 * Register a handler to URL.
 * @param server
 * @param url
 * @param handler
 * @return
 */
int http_register_url(http_server_t *server, const char *url, http_handler_t handler) {
    // url[0] must be '/'
    if (url[0] != '/') {
        return -1;
    }
    // insert to trie node
    http_url_trie_node_t *node = &server->url_root;
    size_t idx = 1;
    while (url[idx] >= '%' && url[idx] <= '~') {
        char offset = (char) (url[idx] - '%');
        if (node->children[offset] == NULL) {
            // new node
            node->children[offset] = malloc(sizeof(http_url_trie_node_t));
            if (node->children[offset] == NULL) {
                // error
                if (server->err_handler != NULL) {
                    server->err_handler(errno);
                }
                return errno;
            }
            bzero(node->children[offset], sizeof(http_url_trie_node_t));
        }
        node = node->children[offset];
        idx += 1;
    }
    node->handler = handler;
    return 0;
}

/**
 * Register a websocket handler to URL. FIXME: duplicate code
 * @param server
 * @param url
 * @param handler
 * @return
 */
int http_register_ws(http_server_t *server, const char *url, http_ws_handlers_t *handlers) {
    // url[0] must be '/'
    if (url[0] != '/') {
        return -1;
    }
    // insert to trie node
    http_url_trie_node_t *node = &server->url_root;
    size_t idx = 1;
    while (url[idx] >= '%' && url[idx] <= '~') {
        char offset = (char) (url[idx] - '%');
        if (node->children[offset] == NULL) {
            // new node
            node->children[offset] = malloc(sizeof(http_url_trie_node_t));
            if (node->children[offset] == NULL) {
                // error
                if (server->err_handler != NULL) {
                    server->err_handler(errno);
                }
                return errno;
            }
            bzero(node->children[offset], sizeof(http_url_trie_node_t));
        }
        node = node->children[offset];
        idx += 1;
    }
    node->ws_handlers = handlers;
    return 0;
}


struct trie_node {
    // 0-9a-z
    struct trie_node *child[36];
    const char *text;
};

/**
 * Build trie node.
 * @param root
 * @param pat
 * @param text
 */
static void build_trie(struct trie_node *root, const char *pat, const char *text) {
    struct trie_node *ptr = root;
    for (int i = 0; pat[i] != '\0'; i++) {
        char c = pat[i];
        if (c <= '9') {
            c -= '0';
        } else {
            // c = c - 'a' + 10;
            c -= 'a' - 10;
        }
        if (ptr->child[c] == NULL) {
            // new node
            ptr->child[c] = (struct trie_node *) malloc(sizeof(struct trie_node));
            bzero(ptr->child[c], sizeof(struct trie_node));
        }
        ptr = ptr->child[c];
    }
    ptr->text = text;
}

/**
 * Get MIME type string from postfix.
 * @param postfix_name
 * @return MIME type string.
 */
static const char *get_mime_string(const char *postfix_name) {
    // generate trie
    static struct trie_node *root = NULL;
    if (root == NULL) {
        root = (struct trie_node *) malloc(sizeof(struct trie_node));
        bzero(root, sizeof(struct trie_node));
        build_trie(root, "html", "text/html");
        build_trie(root, "htm", "text/html");
        build_trie(root, "shtml", "text/html");
        build_trie(root, "css", "text/css");
        build_trie(root, "js", "text/javascript");
        build_trie(root, "txt", "text/plain");
        build_trie(root, "gif", "image/gif");
        build_trie(root, "png", "image/png");
        build_trie(root, "jpg", "image/jpeg");
        build_trie(root, "jpeg", "image/jpeg");
        build_trie(root, "tif", "image/tiff");
        build_trie(root, "tiff", "image/tiff");
        build_trie(root, "svg", "image/svg+xml");
        build_trie(root, "mp3", "audio/mpeg");
        build_trie(root, "ogg", "audio/ogg");
        build_trie(root, "3gp", "video/3gpp");
        build_trie(root, "3gpp", "video/3gpp");
        build_trie(root, "mp4", "video/mp4");
        build_trie(root, "mpg", "video/mpeg");
        build_trie(root, "mpeg", "video/mpeg");
        build_trie(root, "webm", "video/webm");
        build_trie(root, "mov", "video/quicktime");
        build_trie(root, "woff", "application/font-woff");
        build_trie(root, "rss", "application/rss+xml");
        build_trie(root, "pdf", "application/pdf");
        build_trie(root, "xml", "application/xml");
        build_trie(root, "json", "application/json");
    }
    // match
    struct trie_node *ptr = root;
    for (size_t i = 0; postfix_name[i] != '\0'; i++) {
        char c = postfix_name[i];
        if (c <= '9' && c >= '0') {
            c -= '0';
        } else if (c >= 'a' && c <= 'z') {
            // c = c - 'a' + 10;
            c -= 'a' - 10;
        } else if (c >= 'A' && c <= 'Z') {
            c -= 'A' - 10;
        } else {
            // application/octet-stream for unknown
            return "application/octet-stream";
        }
        ptr = ptr->child[c];
        if (ptr == NULL) {
            return "application/octet-stream";
        }
    }
    return ptr->text;
}

static void free_response(http_context_t *context) {
    free(context->response.body.data);
}

/**
 * Handle static directories, return 404 if not found.
 * @param context
 * @param path Must be absolute path, `/a/b/c` for example.
 * @param index Default index, `index.html` for example, NULL if not used.
 */
void http_send_dir(http_context_t *context, const char *path, const char *index) {
    // simplify URL path
    const char *cur = ".";
    const char *fa = "..";
    const size_t STACK_MAX = PATH_MAX / 2;
    size_t stack_head[STACK_MAX];
    size_t stack_len[STACK_MAX];
    size_t stack_ptr = 0;
    size_t st = 1;
    unsigned char *url = context->request.url.data;
    for (size_t i = 1; i <= context->request.url.len; i++) {
        if (url[i] != '/' && url[i - 1] == '/') {
            // start dir
            st = i;
        } else if ((url[i] == '/' && url[i - 1] != '/') || (i == context->request.url.len)) {
            // end
            if (i - st == 2 && url[st] == '.' && url[st + 1] == '.') {
                // return to father, pop
                stack_ptr = stack_ptr > 0 ? stack_ptr - 1 : 0;
            } else if (i - st == 1 && url[st] == '.') {
                // current, do nothing
            } else {
                // push
                stack_head[stack_ptr] = st;
                stack_len[stack_ptr++] = i - st;
            }
        }
    }
    // generate path string
    char real_path[PATH_MAX];
    size_t path_ptr = 0;
    // push default path
    for (; path[path_ptr] != '\0'; path_ptr++) {
        if (path_ptr >= PATH_MAX) {
            // too long
            context->response.status_code = 400;
            http_response(context, NULL);
            return;
        }
        real_path[path_ptr] = path[path_ptr];
    }
    // append url path
    for (size_t i = 0; i < stack_ptr; i++) {
        real_path[path_ptr++] = '/';
        if (path_ptr + stack_len[i] >= PATH_MAX) {
            context->response.status_code = 400;
            http_response(context, NULL);
            return;
        }
        memcpy(real_path + path_ptr, url + stack_head[i], stack_len[i]);
        path_ptr += stack_len[i];
    }
    real_path[path_ptr] = '\0';
    // check file and get length
    struct stat file_stat;
    if (stat(real_path, &file_stat)) {
        context->response.status_code = 404;
        http_response(context, NULL);
        return;
    }
    if (S_ISREG(file_stat.st_mode)) {
        // file, do nothing
    } else if (S_ISDIR(file_stat.st_mode)) {
        // directories, append index and retry
        if (real_path[path_ptr - 1] != '/') {
            real_path[path_ptr++] = '/';
            if (path_ptr >= PATH_MAX) {
                context->response.status_code = 404;
                http_response(context, NULL);
                return;
            }
        }
        if (index == NULL) {
            // forbidden
            context->response.status_code = 403;
            http_response(context, NULL);
            return;
        }
        // append index
        for (size_t i = 0; index[i] != '\0'; i++) {
            real_path[path_ptr++] = index[i];
            if (path_ptr >= PATH_MAX) {
                context->response.status_code = 400;
                http_response(context, NULL);
                return;
            }
        }
        if (stat(real_path, &file_stat)) {
            context->response.status_code = 403;
            http_response(context, NULL);
            return;
        }
    } else {
        // not found
        context->response.status_code = 404;
        http_response(context, NULL);
        return;
    }
    int fd = open(real_path, O_RDONLY);
    if (fd < 0) {
        context->response.status_code = 404;
        http_response(context, NULL);
        return;
    }
    // get MIME for Content-Type
    size_t postfix_dot = path_ptr;
    for (; postfix_dot >= 0 && real_path[postfix_dot] != '.' && real_path[postfix_dot] != '/'; postfix_dot--);
    postfix_dot += 1;

#if __APPLE__ || __linux__
    // use sendfile, it will handle all context, send header
    char headers_str[100];
    size_t headers_len = sprintf(
            headers_str,
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lld\r\n\r\n",
            get_mime_string(real_path + postfix_dot),
            file_stat.st_size);
    size_t headers_ptr = 0;
    do {
        headers_ptr += write(context->watcher.fd, headers_str + headers_ptr, headers_len - headers_ptr);
    } while (headers_ptr < headers_len);
    reset_context(context);
#endif

    // macOS and linux `sendfile` is different.
#if __APPLE__
    off_t file_len = file_stat.st_size;
    off_t file_ptr = 0;
    struct sf_hdtr hdtr = {
            .headers = NULL,
            .hdr_cnt = 0,
            .trailers = NULL,
            .trl_cnt = 0
    };
    do {
        int err = sendfile(fd, context->watcher.fd, file_ptr, &file_len, &hdtr, 0);
        if (err != 0 && err != EAGAIN) {
            // error
            close(fd);
            if (context->server->err_handler != NULL) {
                context->server->err_handler(err);
            }
            context->response.status_code = 500;
            return;
        }
        file_ptr += file_len;
        file_len = file_stat.st_size - file_len;
    } while (file_ptr < file_stat.st_size);
#elif __linux__
    size_t file_len = file_stat.st_size;
    off_t file_ptr = 0;
    do {
        int err = sendfile(context->watcher.fd, fd, &file_ptr, file_len);
        if (err != 0 && err != EAGAIN) {
            close(fd);
            if (context->server->err_handler != NULL) {
                context->server->err_handler(err);
            }
            context->response.status_code = 400;
            return;
        }
        file_len -= file_ptr;
    } while (file_ptr < file_stat.st_size);
    reset_context(context);
#else
    // Normal use sysio
    // set Content-Type
    static http_header_field_t *content_type = NULL;
    if (content_type == NULL) {
        content_type = (http_header_field_t *) malloc(sizeof(http_header_field_t));
        content_type->key.data = (unsigned char *) "Content-Type";
        content_type->key.len = strlen("Content-Type");
    }
    const char* content_type_str = get_mime_string(real_path + postfix_dot);
    content_type->value.data = (unsigned char *) content_type_str;
    content_type->value.len = strlen(content_type_str);
    context->response.headers.len = 1;
    context->response.headers.fields = content_type;
    // read all to context body
    if (context->response.body.data == NULL) {
        context->response.body.data = (unsigned char *) malloc(file_stat.st_size);
    } else if (context->response.body.len < file_stat.st_size) {
        context->response.body.data = (unsigned char *) realloc(context->response.body.data, file_stat.st_size);
    }
    // TODO: handle error
    context->response.body.len = file_stat.st_size;
    read(fd, context->response.body.data, file_stat.st_size);
    http_response(context, free_response);
#endif
}

/**
 * Create a new server with default settings.
 * @return *server
 */
http_server_t *http_create_server(void) {
    http_server_t *server = malloc(sizeof(http_server_t));
    memset(server, 0, sizeof(http_server_t));
    if (server == NULL) {
        return NULL;
    }
    server->loop = EV_DEFAULT;
    llhttp_settings_init(&server->parser_settings);
    server->parser_settings.on_url = url_cb;
    server->parser_settings.on_header_field = header_field_cb;
    server->parser_settings.on_header_value = header_value_cb;
    server->parser_settings.on_body = body_cb;
    server->parser_settings.on_message_complete = message_complete_cb;
    server->err_handler = NULL;
    server->before_parse = NULL;
    server->before_dispatch = NULL;
    server->before_close = NULL;
    // default settings
    server->port = 80;
    server->max_connections = 100;
    server->max_request = 10;
    server->client_timeout = 30;
    server->max_request_size = 1048576; // 1M
    return server;
}

http_server_t *this_process_server = NULL;
char this_process_is_master = 0;

static void sig_handler(int sig) {
    if (this_process_server != NULL) {
        close(this_process_server->socket_fd);
    }
    if (this_process_is_master) {
#if __APPLE__
        // kill all child process
        kill(0, sig);
#elif __linux__
        // do nothing, child process will handle
#endif
    }
    exit(sig);
}

/**
 * Open a socket and bind to listen.
 * @param server
 * @return Return socket file descriptor fd if successful,
 * otherwise the value -1 is returned and the global variable errno is set to indicate the error.
 */
static int http_server_listen(http_server_t *server) {
    // open socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // bind
    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr))) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return -1;
    }
    // listen
    if (listen(socket_fd, server->max_connections + 1)) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return -1;
    }
    if (set_non_block(socket_fd)) {
        close(socket_fd);
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return -1;
    }
    return socket_fd;
}

/**
 * Spawn new child process to run server.
 * @param server
 * @return child process id
 */
int http_spawn_process(http_server_t *server) {
    int pid = fork();
    if (pid < 0) {
        // err
        if (server->err_handler != NULL) {
            server->err_handler(pid);
        }
        return -1;
    } else if (pid == 0) {
        // child process
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
#if __linux__
        prctl(PR_SET_PDEATHSIG, SIGINT);
#endif
        // run loop
        ev_io_init(&server->tcp_watcher, tcp_accept_cb, server->socket_fd, EV_READ);
        ev_io_start(server->loop, &server->tcp_watcher);
        // run loop
        ev_run(server->loop, 0);
        close(server->socket_fd);
        exit(-1);
    }
    return pid;
}

/**
 * Run server in multi-process mode.
 * Note: it will kill all child process before exit.
 * @param server Server instance
 * @param process Number of processes
 * @return errno
 */
int http_server_run_multi_process(http_server_t *server, int process) {
    if (process <= 0) {
        return -1;
    }
    server->socket_fd = http_server_listen(server);
    if (server->socket_fd < 0) {
        return errno;
    }
    // create process group for killing
    if (setpgid(0, 0)) {
        if (server->err_handler != NULL) {
            server->err_handler(errno);
        }
        return errno;
    }
    // handle signal
    this_process_server = server;
    this_process_is_master = 1;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    // spawn
    for (unsigned int i = 0; i < process; i++) {
        if (http_spawn_process(server) < 0) {
            goto clean;
        }
    }
    // wait child process exit and spawn new process
    while (1) {
        pid_t child_pid = -1;
        pid_t exit_pid = wait(&child_pid);
        if (exit_pid < 0) {
            goto clean;
        }
        if (http_spawn_process(server) < 0) {
            goto clean;
        }
    }
    // clean job
    clean:
    close(server->socket_fd);
    if (server->err_handler != NULL) {
        server->err_handler(errno);
    }
    // kill all child process and return errno
    kill(0, SIGINT);
    return errno;
}


void *thread_job(void *s) {
    // create new server, copy original
    http_server_t server;
    memcpy(&server, s, sizeof(http_server_t));
    // create new loop
    server.loop = ev_loop_new(0);
    ev_io_init(&server.tcp_watcher, tcp_accept_cb, server.socket_fd, EV_READ);
    ev_io_start(server.loop, &server.tcp_watcher);
    ev_run(server.loop, 0);
    return NULL;
}

/**
 * Run server in multi-thread mode.
 * @param server Server instance
 * @param threads Number of threads
 * @return
 */
int http_server_run_multi_thread(http_server_t *server, int threads) {
    if (threads <= 0) {
        return -1;
    }
    server->socket_fd = http_server_listen(server);
    if (server->socket_fd < 0) {
        return errno;
    }
    pthread_t t[threads];
    for (int i = 0; i < threads; i++) {
        int ret = pthread_create(&t[i], NULL, thread_job, server);
        if (ret) {
            if (server->err_handler != NULL) {
                server->err_handler(ret);
            }
            // cancel
            for (int j = 0; j < i; j++) {
                pthread_cancel(t[j]);
            }
            return ret;
        }
    }
    return pthread_join(t[0], NULL);
}

/**
 * Run server in single-process mode.
 * @param server
 * @return errno
 */
int http_server_run_single_process(http_server_t *server) {
    server->socket_fd = http_server_listen(server);
    if (server->socket_fd < 0) {
        return errno;
    }
    // handle signal
    this_process_server = server;
    this_process_is_master = 0;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    // join loop
    ev_io_init(&server->tcp_watcher, tcp_accept_cb, server->socket_fd, EV_READ);
    ev_io_start(server->loop, &server->tcp_watcher);
    // run loop
    ev_run(server->loop, 0);
    close(server->socket_fd);
    return -1;
}
