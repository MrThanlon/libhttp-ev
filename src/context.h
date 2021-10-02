#ifndef HTTP_EV_CONTEXT_H
#define HTTP_EV_CONTEXT_H

#include "http.h"

void http_dispatch(http_context_t *context);
http_context_t *get_new_context();
void recycle_context(http_context_t *context);
void close_context(http_context_t *context);
http_context_t *http_create_context(http_server_t* server, int socket_fd);

#endif //HTTP_EV_CONTEXT_H
