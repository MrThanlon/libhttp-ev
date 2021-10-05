#ifndef HTTP_EV_PARSER_H
#define HTTP_EV_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

http_context_t *get_context_from_parser(llhttp_t *parser);
int url_cb(llhttp_t *parser, const char *at, size_t length);
int header_field_cb(llhttp_t *parser, const char *at, size_t length);
int header_value_cb(llhttp_t *parser, const char *at, size_t length);
int body_cb(llhttp_t *parser, const char *at, size_t length);
int message_complete_cb(llhttp_t *parser);

#ifdef __cplusplus
};
#endif

#endif //HTTP_EV_PARSER_H
