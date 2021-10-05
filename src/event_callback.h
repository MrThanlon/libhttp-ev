#ifndef HTTP_EV_EVENT_CALLBACK_H
#define HTTP_EV_EVENT_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ev.h>

int set_non_block(int fd);
void watcher_cb(struct ev_loop *loop, ev_io *watcher, int revents);
void tcp_accept_cb(struct ev_loop *loop, ev_io *watcher, int revents);

#ifdef __cplusplus
};
#endif

#endif //HTTP_EV_EVENT_CALLBACK_H
