#ifndef _IPV4_UTIL_HH_
#define _IPV4_UTIL_HH_

#include <netinet/in.h>

namespace ipv4_util {

bool is_ipv4(const sockaddr_storage &sa);
const in_addr &get_inaddr(const sockaddr_storage &sa);
in_addr &get_inaddr(sockaddr_storage &sa);
sockaddr_storage init4(const in_addr &a);

bool is_in4addr_loopback(const in_addr &a);
bool is_in4addr_any(const in_addr &a);
bool is_in4addr_broadcast(const in_addr &a);
bool is_in4addr_multicast(const in_addr &a);
bool is_in4addr_private(const in_addr &a);

bool is_in4addr_multicast_unspec(const in_addr &a);
bool is_in4addr_multicast_allhosts(const in_addr &a);
bool is_in4addr_multicast_allrouters(const in_addr &a);
bool is_in4addr_multicast_maxlocalgroup(const in_addr &a);

bool is_in4addr_class_a(const in_addr &a);
bool is_in4addr_class_b(const in_addr &a);
bool is_in4addr_class_c(const in_addr &a);
bool is_in4addr_class_d(const in_addr &a);

size_t count_leading_1(const in_addr &a);
in_addr get_netmask(size_t prefix);

}

inline bool ipv4_util::is_ipv4(const sockaddr_storage &sa)
{
    return sa.ss_family == AF_INET;
}

inline const in_addr &ipv4_util::get_inaddr(const sockaddr_storage &sa)
{
    return reinterpret_cast<const sockaddr_in *>(&sa)->sin_addr;
}

inline in_addr &ipv4_util::get_inaddr(sockaddr_storage &sa)
{
    return reinterpret_cast<sockaddr_in *>(&sa)->sin_addr;
}

inline sockaddr_storage ipv4_util::init4(const in_addr &a)
{
    sockaddr_storage sa;
    memset(&sa, 0, sizeof(sa));
    sa.ss_family = AF_INET;
    auto &dst = get_inaddr(sa);
    dst = a;
    return sa;
}

inline bool ipv4_util::is_in4addr_loopback(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_LOOPBACK);
}

inline bool ipv4_util::is_in4addr_multicast(const in_addr &a)
{
    return IN_MULTICAST(htonl(a.s_addr));
}

inline bool ipv4_util::is_in4addr_any(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_ANY);
}

inline bool ipv4_util::is_in4addr_broadcast(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_BROADCAST);
}

inline bool ipv4_util::is_in4addr_multicast_unspec(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_UNSPEC_GROUP);
}

inline bool ipv4_util::is_in4addr_multicast_allhosts(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_ALLHOSTS_GROUP);
}

inline bool ipv4_util::is_in4addr_multicast_allrouters(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_ALLRTRS_GROUP);
}

inline bool ipv4_util::is_in4addr_multicast_maxlocalgroup(const in_addr &a)
{
    return a.s_addr == ntohl(INADDR_MAX_LOCAL_GROUP);
}

inline bool ipv4_util::is_in4addr_class_a(const in_addr &a)
{
    return IN_CLASSA(htonl(a.s_addr));
}

inline bool ipv4_util::is_in4addr_class_b(const in_addr &a)
{
    return IN_CLASSB(htonl(a.s_addr));
}

inline bool ipv4_util::is_in4addr_class_c(const in_addr &a)
{
    return IN_CLASSC(htonl(a.s_addr));
}

inline bool ipv4_util::is_in4addr_class_d(const in_addr &a)
{
    return IN_CLASSD(htonl(a.s_addr));
}

/*
rfc1918
     10.0.0.0        -   10.255.255.255  (10/8 prefix)
     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
*/
inline bool ipv4_util::is_in4addr_private(const in_addr &a)
{
    if((a.s_addr & htonl(0xff000000)) == htonl(0x0a000000))
        return true;

    if((a.s_addr & htonl(0xffff0000)) == htonl(0xc0a80000))
        return true;

    if((a.s_addr & htonl(0xfff00000)) == htonl(0xac100000))
        return true;

    return false;
}

/* TODO
// "Example: For broadcasting a packet to an entire IPv4 subnet using
// the private IP address space 172.16.0.0/12, which has the subnet
// mask 255.240.0.0, the broadcast address is 172.16.0.0 |
// 0.15.255.255 = 172.31.255.255."

const in_addr &get_inaddr(const sockaddr_storage &sa)
{
    return reinterpret_cast<const sockaddr_in *>(&sa)->sin_addr;
}

const in_addr_t &get_inaddr_t(const sockaddr_storage &sa)
{
    return reinterpret_cast<const sockaddr_in *>(&sa)->sin_addr.s_addr;
}

inline bool is_v4_bcast(const sockaddr_storage &sa)
{
    if(sa.ss_family != AF_INET)
        return false;

    const in_addr *sa4 = &reinterpret_cast<const sockaddr_in *>(&sa)->sin_addr;
    return 
}

inline bool is_netmask(const in_addr &addr)
{
    // 1 or more leading 1bits, followed by 0 or more 0bits, but no more one bits
}

inline in_addr cidr_to_netmask(size_t cidr_prefix)
{

}

inline size_t netmask_to_cidr(const in_addr &netmask)
{

}

inline bool match_subnets(const in_addr &subnet, const in_addr &ip, const in_addr &netmask)
{
    return (ip & netmask) == (subnet & netmask);
}

inline in_addr calculate_subnet_address(const in_addr &broadaddr, const in_addr_t &netmask)
{
    return (broadaddr & netmask);
}
*/

inline size_t ipv4_util::count_leading_1(const in_addr &a)
{
    return bit_util::count_leading_1(ntohl(a.s_addr));
}

inline in_addr ipv4_util::get_netmask(size_t prefix)
{
    static const std::array<uint32_t, 33> le_mask32 = {
        0x00000000, 0x80000000, 0xc0000000, 0xe0000000,
        0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,

        0xff000000, 0xff800000, 0xffc00000, 0xffe00000,
        0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,

        0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000,
        0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,

        0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0,
        0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,
        0xffffffff,
    };
    in_addr a;
    a.s_addr = htonl(le_mask32[prefix % 32]);
    return a;
}

#endif

