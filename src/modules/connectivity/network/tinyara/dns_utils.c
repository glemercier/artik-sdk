#include "dns_utils.h"

#include <net/lwip/dns.h>

bool dns_foreach_nameserver(dns_lookup_callback callback, void *user_data)
{
	int i = 0;

	for (; i < DNS_MAX_SERVERS; i++) {
		const ip_addr_t *dns_ip = dns_getserver(i);
		struct sockaddr addr;
		socklen_t addrlen;

		if (dns_ip == IP_ADDR_ANY)
			return true;

		if (IP_IS_V4_VAL(*dns_ip)) {
			struct sockaddr_in *addr_ipv4 = (struct sockaddr_in *)&addr;

			addr_ipv4->sin_family = AF_INET;
			inet_addr_from_ip4addr(&addr_ipv4->sin_addr, &dns_ip->u_addr.ip4);
			addrlen = sizeof(struct sockaddr_in);
		} else if (IP_IS_V6_VAL(*dns_ip)) {
			struct sockaddr_in6 *addr_ipv6 = (struct sockaddr_in6 *)&addr;

			addr_ipv6->sin6_family = AF_INET6;
			inet6_addr_from_ip6addr(&addr_ipv6->sin6_addr, &dns_ip->u_addr.ip6);
			addrlen = sizeof(struct sockaddr_in6);
		} else {
			return false;
		}

		if (!callback(user_data, &addr, addrlen))
			return false;
	}

	return true;
}

bool dns_add_nameserver(struct sockaddr *sockaddr, socklen_t addrlen)
{
	int i = 0;
	ip_addr_t dns_addr;

	for (; i < DNS_MAX_SERVERS; i++) {
		const ip_addr_t *ip = dns_getserver(i);

		if (ip != IP_ADDR_ANY)
			continue;

		if (sockaddr->sa_family == AF_INET) {
			struct sockaddr_in *addr_ipv4 = (struct sockaddr_in *)sockaddr;

			dns_addr.type = IPADDR_TYPE_V4;
			inet_addr_to_ip4addr(&dns_addr.u_addr.ip4, &addr_ipv4->sin_addr);
		} else if (sockaddr->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr_ipv6 = (struct sockaddr_in6 *)sockaddr;

			dns_addr.type = IPADDR_TYPE_V6;
			inet6_addr_to_ip6addr(&dns_addr.u_addr.ip6, &addr_ipv6->sin6_addr);
		} else {
			return false;
		}

		dns_setserver(i, &dns_addr);
		return true;
	}

	return false;
}
