#include <gtest/gtest.h>
#include "http.h"
#include "parser.h"

TEST(http, http_create_server) {
    http_server_t *server = http_create_server();
    ASSERT_EQ(server->loop, EV_DEFAULT);
    ASSERT_EQ(server->port, 80);
}

TEST(parser, get_context_from_parser) {
    http_context_t context;
    ASSERT_EQ(get_context_from_parser(&context.parser), &context);
}
