//
// Created by Ziyi Huang on 2021/9/21.
//

#include "http.h"
#include "parser.h"
#include "context.h"
#include "event_callback.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stddef.h>
#include <errno.h>
#include <netinet/in.h>
#include <limits.h>
#include <sys/stat.h>

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
 * Call this to indicate handle finished.
 * @param context
 */
void http_complete(http_context_t *context) {
    context->state = HTTP_CONTEXT_STATE_RESPONSE;
    // TODO: generate header string
    // TODO: use callback to write response
    close_context(context);
}

/**
 * Set context async mode.
 * @param context
 */
void http_set_async(http_context_t *context) {
    context->state = HTTP_CONTEXT_STATE_PENDING;
}

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
        }
        node = node->children[offset];
        idx += 1;
    }
    node->handler = handler;
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

/**
 * Handle static directories, return 404 if not found.
 * @param context
 * @param path Must be absolute path, `/a/b/c` for example.
 * @param index Default index, `index.html` for example, NULL if not used.
 * @return status code
 */
unsigned int http_send_file(http_context_t *context, const char *path, const char *index) {
    // simplify URL path
    const char *cur = ".";
    const char *fa = "..";
    const size_t STACK_MAX = PATH_MAX / 2;
    size_t stack_head[STACK_MAX];
    size_t stack_len[STACK_MAX];
    size_t stack_ptr = 0;
    size_t st = 1;
    unsigned char *url = context->request.url.data;
    // FIXME: edge condition
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
            return 400;
        }
        real_path[path_ptr] = path[path_ptr];
    }
    // append url path
    for (size_t i = 0; i < stack_ptr; i++) {
        real_path[path_ptr++] = '/';
        if (path_ptr + stack_len[i] >= PATH_MAX) {
            return 400;
        }
        memcpy(real_path + path_ptr, url + stack_head[i], stack_len[i]);
        path_ptr += stack_len[i];
    }
    real_path[path_ptr] = '\0';
    // check file and get length
    struct stat file_stat;
    if (stat(real_path, &file_stat)) {
        // not found
        return 404;
    }
    if (S_ISREG(file_stat.st_mode)) {
        // file, do nothing
    } else if (S_ISDIR(file_stat.st_mode)) {
        // directories, append index and retry
        if (real_path[path_ptr - 1] != '/') {
            real_path[path_ptr++] = '/';
            if (path_ptr >= PATH_MAX) {
                return 404;
            }
        }
        if (index == NULL) {
            // forbidden
            return 403;
        }
        // append index
        for (size_t i = 0; index[i] != '\0'; i++) {
            real_path[path_ptr++] = index[i];
            if (path_ptr >= PATH_MAX) {
                return 400;
            }
        }
        if (stat(real_path, &file_stat)) {
            return 403;
        }
    } else {
        // not found
        return 404;
    }
    int fd = open(real_path, O_RDONLY);
    if (fd < 0) {
        return 404;
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
    context->ready_to_close = 0x7f;
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
            return 500;
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
            return 500;
        }
        file_len -= file_ptr;
    } while (file_ptr < file_stat.st_size);
    context->ready_to_close = 0x7f;
#else
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
    if (context->response.body.len < file_stat.st_size) {
        context->response.body.data = (unsigned char *) realloc(context->response.body.data, file_stat.st_size);
    }
    context->response.body.len = file_stat.st_size;
    read(fd, context->response.body.data, file_stat.st_size);
#endif
    close(fd);
    return 200;
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
    // default settings
    server->port = 80;
    server->max_connections = 100;
    server->max_context = 100;
    server->max_url_len = 4096;
    server->max_headers_size = 102400; // 100K
    server->max_body_size = 1048576; // 1M
    return server;
}

http_server_t *this_process_server = NULL;
char this_process_is_master = 0;

static void sig_handler(int sig) {
    if (this_process_server != NULL) {
        // FIXME: should use ev_break()
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
    http_server_t *server = (http_server_t *) s;
    // create new loop
    struct ev_loop *loop = ev_loop_new(0);
    ev_io tcp_watcher;
    ev_io_init(&tcp_watcher, tcp_accept_cb, server->socket_fd, EV_READ);
    ev_io_start(loop, &tcp_watcher);
    ev_run(loop, 0);
    return NULL;
}

/**
 * TODO: Run server in multi-thread mode.
 * @param server Server instance
 * @param threads Number of threads
 * @return
 */
int http_server_run_multi_thread(http_server_t *server, int threads) {
    server->socket_fd = http_server_listen(server);
    if (server->socket_fd < 0) {
        return errno;
    }
    // TODO: pthread_create()
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
    // TODO: wait
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
