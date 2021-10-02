#include "http.h"
#include "context.h"
#include <stdlib.h>
#include <errno.h>

http_context_t *get_context_from_parser(llhttp_t *parser) {
    return (http_context_t *) ((void *) parser - offsetof(http_context_t, parser));
}

int url_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    context->request.url.data = (unsigned char *) at;
    context->request.url.len = length;
    context->request.method = parser->method;
    return 0;
}

int header_field_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    http_headers_t *headers = &context->request.headers;
    if (headers->len >= headers->capacity) {
        // expansion
        headers->capacity += 10;
        http_header_field_t *new_fields = (http_header_field_t *)
                realloc(headers->fields, headers->capacity * sizeof(http_header_field_t));
        if (new_fields == NULL) {
            // error, close
            if (context->server->err_handler != NULL) {
                context->server->err_handler(errno);
            }
            context->ready_to_close = 0x7f;
            return -1;
        }
        headers->fields = new_fields;
    }
    headers->fields[headers->len].key.data = (unsigned char *) at;
    headers->fields[headers->len].key.len = length;
    headers->len += 1;
    return 0;
}

int header_value_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    http_headers_t *headers = &context->request.headers;
    headers->fields[headers->len - 1].value.data = (unsigned char *) at;
    headers->fields[headers->len - 1].value.len = length;
    return 0;
}

int body_cb(llhttp_t *parser, const char *at, size_t length) {
    http_context_t *context = get_context_from_parser(parser);
    context->request.body.data = (unsigned char *) at;
    context->request.body.len = length;
    return 0;
}

int message_complete_cb(llhttp_t *parser) {
    http_dispatch(get_context_from_parser(parser));
    return 0;
}
