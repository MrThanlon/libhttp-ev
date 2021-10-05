#ifndef HTTP_EV_WEBSOCKET_H
#define HTTP_EV_WEBSOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http.h"
#include "ev.h"

int ws_handshake(http_context_t* context);

#ifdef __cplusplus
};
#endif

#endif //HTTP_EV_WEBSOCKET_H
