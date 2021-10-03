#ifndef HTTP_EV_CONTEXT_H
#define HTTP_EV_CONTEXT_H

#include "http.h"

const char *get_status_message(unsigned int status);
void reset_context(http_context_t *context);
void http_dispatch(http_context_t *context);
http_context_t *get_new_context();
void recycle_context(http_context_t *context);
void close_context(http_context_t *context);
http_context_t *http_create_context(http_server_t* server, int socket_fd);

#endif //HTTP_EV_CONTEXT_H
