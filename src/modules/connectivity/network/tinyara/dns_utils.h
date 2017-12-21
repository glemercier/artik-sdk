#ifndef DNS_UTILS_H_
#define DNS_UTILS_H_

#include <stdbool.h>
#include <sys/socket.h>

typedef bool (*dns_lookup_callback)(void *arg, struct sockaddr *addr, socklen_t addrlen);

bool dns_foreach_nameserver(dns_lookup_callback callback, void *user_data);
bool dns_add_nameserver(struct sockaddr *sockaddr, socklen_t addrlen);

#endif /* DNS_UTILS_H_ */
