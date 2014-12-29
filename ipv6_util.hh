#ifndef _IPV6_UTIL_HH_
#define _IPV6_UTIL_HH_

#include <netinet/in.h>
#include "bit_util.hh"

namespace ipv6_util {

bool is_ipv6(const sockaddr_storage &sa);
const in6_addr &get_in6addr(const sockaddr_storage &sa);
in6_addr &get_in6addr(sockaddr_storage &sa);
sockaddr_storage init6(const in6_addr &a);

typedef uint8_t sa6_8_t[16];
typedef uint16_t sa6_16_t[8];
typedef uint32_t sa6_32_t[4];

sa6_8_t &get_in6addr8(in6_addr &sa);
sa6_16_t &get_in6addr16(in6_addr &sa);
sa6_32_t &get_in6addr32(in6_addr &sa);
const sa6_8_t &get_in6addr8(const in6_addr &sa);
const sa6_16_t &get_in6addr16(const in6_addr &sa);
const sa6_32_t &get_in6addr32(const in6_addr &sa);

bool is_in6addr_unspecified(const in6_addr &a);
bool is_in6addr_loopback(const in6_addr &a);
bool is_in6addr_linklocal(const in6_addr &a);
bool is_in6addr_sitelocal(const in6_addr &a);
bool is_in6addr_v4mapped(const in6_addr &a);
bool is_in6addr_v4compat(const in6_addr &a);
bool is_in6addr_nat64(const in6_addr &a);
bool is_in6addr_discardprefix(const in6_addr &a);
bool is_in6addr_teredotunneling(const in6_addr &a);
bool is_in6addr_orchid(const in6_addr &a);
bool is_in6addr_orchidv2(const in6_addr &a);
bool is_in6addr_doc(const in6_addr &a);
bool is_in6addr_multicast(const in6_addr &a);
// multicast scope field tests
bool is_in6addr_multicast_nodelocal(const in6_addr &a);
bool is_in6addr_multicast_linklocal(const in6_addr &a);
bool is_in6addr_multicast_sitelocal(const in6_addr &a);
bool is_in6addr_multicast_orglocal(const in6_addr &a);
bool is_in6addr_multicast_global(const in6_addr &a);
bool is_in6addr_multicast_unicastprefixbased(const in6_addr &a);
bool is_in6addr_multicast_adminlocal(const in6_addr &a);
bool is_in6addr_multicast_unassigned(const in6_addr &a);
bool is_in6addr_multicast_rendezvouspointflag(const in6_addr &a);

bool is_in6addr_multicast_solicitednode(const in6_addr &a);
// flag field
bool is_in6addr_multicast_wellknown(const in6_addr &a);

bool is_in6addr_unicast_local(const in6_addr &a);
bool is_in6addr_global_unicast(const in6_addr &a);
bool is_in6addr_ietf_reserved(const in6_addr &a);
bool is_in6addr_equal(const in6_addr &a, const in6_addr &b);

bool is_in6addr_6to4(const in6_addr &a);
bool is_in6addr_unicast(const in6_addr &a);

bool is_in6addr_subnet_router_anycast(const in6_addr &a, size_t prefix);

bool contains_eui64(const in6_addr &a);

typedef std::array<uint8_t, 6> mac48_t;
typedef std::array<uint8_t, 8> eui64_t;
void mac48_from_eui64(mac48_t &mac, const eui64_t &eui64);
void eui64_from_mac48(eui64_t &eui64, const mac48_t &mac);
mac48_t mac48_from_i6(const in6_addr &a);

in6_addr calculate_subnet_address(const in6_addr &a, size_t prefix);

// leading 1 e.g. in a netmask 1110...
size_t count_leading_1(const in6_addr &a);
// trailing 0 e.g. in router anycast addr.
size_t count_trailing_0(const in6_addr &a);
in6_addr get_netmask(size_t prefix);

// return idx to longest segment, or 8 if no segment is 0
size_t idx16_longest_all0_hextet(const in6_addr &a);
}


inline bool ipv6_util::is_ipv6(const sockaddr_storage &sa)
{
    return sa.ss_family == AF_INET6;
}

inline sockaddr_storage ipv6_util::init6(const in6_addr &a)
{
    sockaddr_storage sa;
    memset(&sa, 0, sizeof(sa));
    sa.ss_family = AF_INET6;
    auto &dst = get_in6addr32(get_in6addr(sa));
    const auto &src = get_in6addr32(a);
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    return sa;
}

inline const in6_addr &ipv6_util::get_in6addr(const sockaddr_storage &sa)
{
    return reinterpret_cast<const sockaddr_in6 *>(&sa)->sin6_addr;
}

inline in6_addr &ipv6_util::get_in6addr(sockaddr_storage &sa)
{
    return reinterpret_cast<sockaddr_in6 *>(&sa)->sin6_addr;
}

inline ipv6_util::sa6_8_t &ipv6_util::get_in6addr8(in6_addr &a)
{
    return a.s6_addr;
}

inline ipv6_util::sa6_16_t &ipv6_util::get_in6addr16(in6_addr &a)
{
    return a.s6_addr16;
}

inline ipv6_util::sa6_32_t &ipv6_util::get_in6addr32(in6_addr &a)
{
    return a.s6_addr32;
}

inline const ipv6_util::sa6_8_t &ipv6_util::get_in6addr8(const in6_addr &a)
{
    return a.s6_addr;
}

inline const ipv6_util::sa6_16_t &ipv6_util::get_in6addr16(const in6_addr &a)
{
    return a.s6_addr16;
}

inline const ipv6_util::sa6_32_t &ipv6_util::get_in6addr32(const in6_addr &a)
{
    return a.s6_addr32;
}

inline bool ipv6_util::is_in6addr_unspecified(const in6_addr &a)
{
    return IN6_IS_ADDR_UNSPECIFIED(&a);
}

inline bool ipv6_util::is_in6addr_loopback(const in6_addr &a)
{
    return IN6_IS_ADDR_LOOPBACK(&a);
}

inline bool ipv6_util::is_in6addr_linklocal(const in6_addr &a)
{
    // prefix: fe80::/10
    return IN6_IS_ADDR_LINKLOCAL(&a);
}

inline bool ipv6_util::is_in6addr_sitelocal(const in6_addr &a)
{
    // fec0::/10
    return IN6_IS_ADDR_SITELOCAL(&a);
}

inline bool ipv6_util::is_in6addr_v4mapped(const in6_addr &a)
{
    // ::ffff/96
    return IN6_IS_ADDR_V4MAPPED(&a);
}

inline bool ipv6_util::is_in6addr_v4compat(const in6_addr &a)
{
    return IN6_IS_ADDR_V4COMPAT(&a);
}

inline bool ipv6_util::is_in6addr_nat64(const in6_addr &a)
{
    // 64:ff9b::/96
    return ((const uint32_t *)(&a))[0] == htonl(0x0064ff9b)
        && ((const uint32_t *)(&a))[1] == 0
        && ((const uint32_t *)(&a))[2] == 0;
}

inline bool ipv6_util::is_in6addr_discardprefix(const in6_addr &a)
{
    // 100::/64
    return ((const uint32_t *)(&a))[0] == htonl(0x01000000)
        && ((const uint32_t *)(&a))[1] == 0;
}

inline bool ipv6_util::is_in6addr_teredotunneling(const in6_addr &a)
{
    // 2001::/32
    return ((const uint32_t *)(&a))[0] == htonl(0x20010000);
}

inline bool ipv6_util::is_in6addr_orchid(const in6_addr &a)
{
    // 2001:10::/28
    return (((const uint32_t *)(&a))[0] & htonl(0xfffffff0)) == htonl(0x20010010);
}

inline bool ipv6_util::is_in6addr_orchidv2(const in6_addr &a)
{
    // 2001:20::/28
    return (((const uint32_t *)(&a))[0] & htonl(0xfffffff0)) == htonl(0x20010020);
}

inline bool ipv6_util::is_in6addr_doc(const in6_addr &a)
{
    // 2001:db8::/32
    return ((const uint32_t *)(&a))[0] == htonl(0x20010db8);
}

inline bool ipv6_util::is_in6addr_multicast(const in6_addr &a)
{
    // ff00::/8
    return IN6_IS_ADDR_MULTICAST(&a);
}

inline bool ipv6_util::is_in6addr_multicast_nodelocal(const in6_addr &a)
{
    return IN6_IS_ADDR_MC_NODELOCAL(&a);
}

inline bool ipv6_util::is_in6addr_multicast_linklocal(const in6_addr &a)
{
    return IN6_IS_ADDR_MC_LINKLOCAL(&a);
}

inline bool ipv6_util::is_in6addr_multicast_sitelocal(const in6_addr &a)
{
    return IN6_IS_ADDR_MC_SITELOCAL(&a);
}

inline bool ipv6_util::is_in6addr_multicast_orglocal(const in6_addr &a)
{
    return IN6_IS_ADDR_MC_ORGLOCAL(&a);
}

inline bool ipv6_util::is_in6addr_multicast_global(const in6_addr &a)
{
    return IN6_IS_ADDR_MC_GLOBAL(&a);
}

inline bool ipv6_util::is_in6addr_multicast_unicastprefixbased(const in6_addr &a)
{
    return is_in6addr_multicast(a) && (((const uint8_t *)(&a))[1] & 0xf) == 0x3;
}

inline bool ipv6_util::is_in6addr_multicast_adminlocal(const in6_addr &a)
{
    return is_in6addr_multicast(a) && (((const uint8_t *)(&a))[1] & 0xf) == 0x4;
}

inline bool ipv6_util::is_in6addr_multicast_unassigned(const in6_addr &a)
{
    const uint8_t v = (((const uint8_t *)(&a))[1] & 0xf);
    return is_in6addr_multicast(a)
        && (v == 0x6 || v == 0x8 || v == 0x9 || v == 0xa || v == 0xb || v == 0xc || v == 0xd
            || v == 0x0 || v == 0xf);
}

inline bool ipv6_util::is_in6addr_multicast_rendezvouspointflag(const in6_addr &a)
{
    return is_in6addr_multicast(a) && (((const uint8_t *)(&a))[1] & 0xf) == 0x7;
}

bool ipv6_util::is_in6addr_multicast_wellknown(const in6_addr &a)
{
    return is_in6addr_multicast(a) && (((const uint8_t *)(&a))[1] & 0xf0) == 0x0;
}

inline bool ipv6_util::is_in6addr_multicast_solicitednode(const in6_addr &a)
{
    return ((const uint32_t *)(&a))[0] == htonl(0xff020000)
        && ((const uint32_t *)(&a))[1] == 0x0
        && ((const uint32_t *)(&a))[2] == htonl(0x00000001)
        && (((const uint32_t *)(&a))[3] & htonl(0xff000000)) == htonl(0xff000000);
}

inline bool ipv6_util::is_in6addr_unicast_local(const in6_addr &a)
{
    // checks for prefix: fc00::/7
    // 0xfc: 1111 1100
    return (((const uint32_t *)(&a))[0] & htonl(0xfe000000)) == htonl(0xfc000000);
}

inline bool ipv6_util::is_in6addr_global_unicast(const in6_addr &a)
{
    // prefix: 2000::/3
    return (((const uint32_t *)(&a))[0] & htonl(0xe0000000)) == htonl(0x20000000);
}

inline bool ipv6_util::is_in6addr_ietf_reserved(const in6_addr &a)
{
// 0100::/8
// 0200::/7
// 0400::/6
// 0800::/5
// 1000::/4
// 4000::/3
// 6000::/3
// 8000::/3
// a000::/3
// c000::/3
// e000::/4
// f000::/5
// f800::/6
// fe00::/9

    const auto mask9 = htonl(0xff800000);
    const auto mask8 = htonl(0xff000000);
    const auto mask7 = htonl(0xfe000000);
    const auto mask6 = htonl(0xfc000000);
    const auto mask5 = htonl(0xf8000000);
    const auto mask4 = htonl(0xf0000000);
    const auto mask3 = htonl(0xe0000000);
    const auto val = ((const uint32_t *)(&a))[0];
    return (val & mask8) == htonl(0x01000000)
        || (val & mask7) == htonl(0x02000000)
        || (val & mask6) == htonl(0x04000000)
        || (val & mask5) == htonl(0x08000000)
        || (val & mask4) == htonl(0x10000000)
        || (val & mask3) == htonl(0x40000000)
        || (val & mask3) == htonl(0x60000000)
        || (val & mask3) == htonl(0x80000000)
        || (val & mask3) == htonl(0xa0000000)
        || (val & mask3) == htonl(0xc0000000)
        || (val & mask4) == htonl(0xe0000000)
        || (val & mask5) == htonl(0xf0000000)
        || (val & mask6) == htonl(0xf8000000)
        || (val & mask9) == htonl(0xfe000000);
}

bool ipv6_util::is_in6addr_6to4(const in6_addr &a)
{
    // 6to4: 2002::16
    return (((const uint32_t *)(&a))[0] & htonl(0xffff0000)) == htonl(0x20020000);
}

inline bool ipv6_util::is_in6addr_equal(const in6_addr &a, const in6_addr &b)
{
    return IN6_ARE_ADDR_EQUAL(&a, &b);
}

inline bool ipv6_util::is_in6addr_unicast(const in6_addr &a)
{
    return !is_in6addr_multicast(a);
}

bool ipv6_util::is_in6addr_subnet_router_anycast(const in6_addr &a, size_t prefix)
{
//    std::cout << "is_in6addr_subnet_router_anycast: \"" << socket_util::ntop(init6(a))
//              << "\"/" << prefix << " -> leading 0: " << ipv6_util::count_trailing_0(a)<< "\n";
    return ipv6_util::count_trailing_0(a) >= 128 - prefix;
}

inline bool ipv6_util::contains_eui64(const in6_addr &a)
{

/*
    std::cout << "in contains_eui64:"
              << "\n11: " << socket_debug::dump_bin(sa6->s6_addr[11])
              << "\n12: " << socket_debug::dump_bin(sa6->s6_addr[12])
              << "\n0xfe: " << socket_debug::dump_bin(0xfe)
              << "\n0xff: " << socket_debug::dump_bin(0xff)
              << "\n";
*/
// TODO: needs conversion
    return a.s6_addr[11] == 0xff && a.s6_addr[12] == 0xfe;
}

inline void ipv6_util::mac48_from_eui64(ipv6_util::mac48_t &mac, const ipv6_util::eui64_t &eui64)
{
// TODO: needs conversion
    mac[0] = eui64[0];
    mac[1] = eui64[1];
    mac[2] = eui64[2];
    mac[3] = eui64[5];
    mac[4] = eui64[6];
    mac[5] = eui64[7];
    // invert 7th bit in network byte order
    mac[0] ^= 1 << 1;
}

inline void ipv6_util::eui64_from_mac48(ipv6_util::eui64_t &eui64, const ipv6_util::mac48_t &mac)
{
// TODO: needs conversion
    eui64[0] = mac[0];
    eui64[1] = mac[1];
    eui64[2] = mac[2];
    eui64[3] = 0xff;
    eui64[4] = 0xfe;
    eui64[5] = mac[3];
    eui64[6] = mac[4];
    eui64[7] = mac[5];
    eui64[0] ^= 1 << 1;
}

ipv6_util::mac48_t ipv6_util::mac48_from_i6(const in6_addr &a)
{
// TODO: needs conversion
    mac48_t mac;
    mac[0] = a.s6_addr[8];
    mac[1] = a.s6_addr[9];
    mac[2] = a.s6_addr[10];
    mac[3] = a.s6_addr[13];
    mac[4] = a.s6_addr[14];
    mac[5] = a.s6_addr[15];
    mac[0] ^= 1 << 1;

//    for(auto i = 0; i < 16; i++) std::cout << "mac48_from_i6 a[" << i << "]: " << socket_debug::dump_bin(a.s6_addr[i]) << "\n";

    return mac;
}

inline in6_addr ipv6_util::calculate_subnet_address(const in6_addr &a, size_t prefix)
{
    /*
      32bit of ip: abcd:efgh::
      be 32bit:    gggghhhh eeeeffff ccccdddd aaaabbbb
      le 32bit:    aaaabbbb ccccdddd eeeeffff gggghhhh
    */

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

    in6_addr subnet_addr;
    sa6_32_t &dst32 = get_in6addr32(subnet_addr);
    const sa6_32_t &src32 = get_in6addr32(a);
    if(prefix < 32) {
        dst32[0] = src32[0] & htonl(le_mask32[prefix % 32]);
        dst32[1] = dst32[2] = dst32[3] = 0;
    } else if(prefix < 64) {
        dst32[0] = src32[0];
        dst32[1] = src32[1] & htonl(le_mask32[prefix % 32]);
        dst32[2] = dst32[3] = 0;
    } else if(prefix < 96) {
        dst32[0] = src32[0];
        dst32[1] = src32[1];
        dst32[2] = src32[2] & htonl(le_mask32[prefix % 32]);
        dst32[3] = 0;
    } else if(prefix < 128) {
        dst32[0] = src32[0];
        dst32[1] = src32[1];
        dst32[2] = src32[2];
        dst32[3] = src32[3] & htonl(le_mask32[prefix % 32]);
    } else if(prefix == 128) {
        dst32[0] = src32[0];
        dst32[1] = src32[1];
        dst32[2] = src32[2];
        dst32[3] = src32[3];
    }

    return subnet_addr;
}

inline size_t ipv6_util::count_leading_1(const in6_addr &a)
{
    size_t cnt = bit_util::count_leading_1(ntohl(get_in6addr32(a)[0]));
    if(cnt < 32)
        return cnt;
    cnt += bit_util::count_leading_1(ntohl(get_in6addr32(a)[1]));
    if(cnt < 64)
        return cnt;
    cnt += bit_util::count_leading_1(ntohl(get_in6addr32(a)[2]));
    if(cnt < 96)
        return cnt;
    cnt += bit_util::count_leading_1(ntohl(get_in6addr32(a)[3]));
    return cnt;
}

inline size_t ipv6_util::count_trailing_0(const in6_addr &a)
{
    size_t cnt = bit_util::count_trailing_0(ntohl(get_in6addr32(a)[3]));
    if(cnt < 32)
        return cnt;
    cnt += bit_util::count_trailing_0(ntohl(get_in6addr32(a)[2]));
    if(cnt < 64)
        return cnt;
    cnt += bit_util::count_trailing_0(ntohl(get_in6addr32(a)[1]));
    if(cnt < 96)
        return cnt;
    cnt += bit_util::count_trailing_0(ntohl(get_in6addr32(a)[0]));
    return cnt;
}

/* test:
    for(size_t i = 0; i < 129; i++) {
        const auto a = ipv6_util::get_netmask(i);
        const auto c = ipv6_util::count_leading_1(a);
        std::cout << socket_debug::dump_bin(ipv6_util::get_in6addr32(a)[0]) << " "
              << socket_debug::dump_bin(ipv6_util::get_in6addr32(a)[1]) << " "
              << socket_debug::dump_bin(ipv6_util::get_in6addr32(a)[2]) << " "
              << socket_debug::dump_bin(ipv6_util::get_in6addr32(a)[3]) << " -> " << c << "\n";
    }
*/

inline in6_addr ipv6_util::get_netmask(size_t prefix)
{
    in6_addr a;
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

    if(prefix < 32) {
        get_in6addr32(a)[0] = htonl(le_mask32[prefix % 32]);
        get_in6addr32(a)[1] = 0;
        get_in6addr32(a)[2] = 0;
        get_in6addr32(a)[3] = 0;
    } else if(prefix < 64) {
        get_in6addr32(a)[0] = 0xffffffff;
        get_in6addr32(a)[1] = htonl(le_mask32[prefix % 32]);
        get_in6addr32(a)[2] = 0;
        get_in6addr32(a)[3] = 0;
    } else if(prefix < 96) {
        get_in6addr32(a)[0] = 0xffffffff;
        get_in6addr32(a)[1] = 0xffffffff;
        get_in6addr32(a)[2] = htonl(le_mask32[prefix % 32]);
        get_in6addr32(a)[3] = 0;
    } else if(prefix < 128) {
        get_in6addr32(a)[0] = 0xffffffff;
        get_in6addr32(a)[1] = 0xffffffff;
        get_in6addr32(a)[2] = 0xffffffff;
        get_in6addr32(a)[3] = htonl(le_mask32[prefix % 32]);
    } else {
        get_in6addr32(a)[0] = 0xffffffff;
        get_in6addr32(a)[1] = 0xffffffff;
        get_in6addr32(a)[2] = 0xffffffff;
        get_in6addr32(a)[3] = 0xffffffff;
    }
    return a;
}

size_t ipv6_util::idx16_longest_all0_hextet(const in6_addr &a)
{
    const auto &a16 = get_in6addr16(a);

    size_t idx = 0;
    size_t count = 0;
    for(size_t i = 0; i < 8; i++) {
        if(a16[i] != 0)
            continue;

        size_t saved_idx = i;
        size_t newcount = 0;
        for(; i < 8 && a16[i] == 0; i++)
            newcount++;
        if(newcount > count) {
            idx = saved_idx;
            count = newcount;
        }
    }

    return count ? idx : 8;
}

#endif
