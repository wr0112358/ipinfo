/*

Missing:
 o ipv4 stuff: bit print and address types, see ipv4_util.hh
   http://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses
 o multicast groups
 o port to bsds, some of the socket stuff won't be available, like AF_PACKET
 o accept /proc/net/igmp6 address format
 o zoneids
 o integrate ipv6_util::idx16_longest_all0_hextet
 o registered address space: http://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.txt

*/

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>

#include "bit_util.hh"
#include "ipinfo_util.hh"
#include "ipv6_util.hh"
#include "ipv4_util.hh"
#include "ip_util.hh"

struct config_type {
    struct record_type {
        // addr parsed from above args. address family stored in addr.ss_family
        sockaddr_storage addr;
        uint8_t prefix;
        // parser recognised a valid address
        bool valid;

        // starting here, all filled by collect_information
        enum addr_type {
            // unique address attributes
            IPV4_UNKNOWN,
            IPV4_LOOPBACK,
            IPV4_ANY,
            IPV4_BROADCAST,
            IPV4_PRIVATE,
            IPV4_MULTICAST,

            IPV6_UNKNOWN,
            IPV6_UNSPECIFIED,
            IPV6_LOOPBACK,
            IPV6_MULTICAST,
            IPV6_V4MAPPED,
            IPV6_V4COMPAT,
            IPV6_NAT64,

            IPV6_ULA,
            IPV6_GLOBAL_UNICAST,
            IPV6_LINK_LOCAL,
            IPV6_IETF_RESERVED,
            IPV6_DEPRECATED_SITE_LOCAL,
        } type;

        enum addr_attr {
            // address attributes of which more than 1 can exist

            // IPV4_SUBNET_BROADCAST,

            // all-0 and all-1 subnetid is valid, but show a comment about them
            // IPV6_ALL_ZERO_SUBNET_ID,
            // IPV6_ALL_ONE_SUBNET_ID,
            // IPV6_ALL_ZERO_INTERFACE_ID,
            // IPV6_ALL_ONE_INTERFACE_ID,

            // eui64 bit pattern was recognized in the ipv6 address
            CONTAINS_EUI64,

            // record_type::subnet contains sth
            SUBNET_FILLED,

            ROUTER_ANYCAST,
            SOLICITED_NODE_MULTICAST,

            // special global unicast address types
            IPV6_DISCARDPREFIX,
            IPV6_TEREDO,
            IPV6_ORCHID,
            IPV6_ORCHIDV2,
            IPV6_DOC,
            IPV6_6TO4,
        };

        std::vector<addr_attr> attrs;

        // calculated, if a prefix was specified and the specified address is an unicast address
        sockaddr_storage subnet;
    };

    struct local_if {
        std::string ifname;
        std::array<uint8_t, 6> mac48;
        struct if_ip {
            int af;
            sockaddr_storage ifaddr;
            sockaddr_storage ifnetmask;
        };
        std::vector<record_type> if_records;
    };

    std::vector<record_type> records;
    std::vector<local_if> local_ifs;

    struct output_config_type {
        bool print_local_ifs{false};
        bool use_colors{false};
        uint8_t verbosity{0};
        util::color_type error_color{ util::RED };
        util::color_type info_color{ util::NO_COLOR };
        util::color_type addr_color{ util::BLUE };
        util::color_type subnet_color{ util::CYAN };
    } output_config;
};

bool collect_ip6_addr_info(config_type::record_type &addr_record)
{
    const auto &a = ipv6_util::get_in6addr(addr_record.addr);
    if(ipv6_util::is_in6addr_unspecified(a))
        addr_record.type = config_type::record_type::IPV6_UNSPECIFIED;
    else if(ipv6_util::is_in6addr_loopback(a))
        addr_record.type = config_type::record_type::IPV6_LOOPBACK;
    else if(ipv6_util::is_in6addr_unicast_local(a))
        addr_record.type = config_type::record_type::IPV6_ULA;
    else if(ipv6_util::is_in6addr_global_unicast(a))
        addr_record.type = config_type::record_type::IPV6_GLOBAL_UNICAST;
    else if(ipv6_util::is_in6addr_linklocal(a))
        addr_record.type = config_type::record_type::IPV6_LINK_LOCAL;
    else if(ipv6_util::is_in6addr_multicast(a))
        addr_record.type = config_type::record_type::IPV6_MULTICAST;
    else if(ipv6_util::is_in6addr_v4mapped(a))
        addr_record.type = config_type::record_type::IPV6_V4MAPPED;
    else if(ipv6_util::is_in6addr_v4compat(a))
        addr_record.type = config_type::record_type::IPV6_V4COMPAT;
    else if(ipv6_util::is_in6addr_nat64(a))
        addr_record.type = config_type::record_type::IPV6_NAT64;
    else if(ipv6_util::is_in6addr_sitelocal(a))
        addr_record.type = config_type::record_type::IPV6_DEPRECATED_SITE_LOCAL;
    else if(ipv6_util::is_in6addr_ietf_reserved(a))
        addr_record.type = config_type::record_type::IPV6_IETF_RESERVED;
    else
        addr_record.type = config_type::record_type::IPV6_UNKNOWN;

    if(ipv6_util::contains_eui64(a))
        addr_record.attrs.push_back(config_type::record_type::CONTAINS_EUI64);

    if(ipv6_util::is_in6addr_subnet_router_anycast(a, addr_record.prefix))
        addr_record.attrs.push_back(config_type::record_type::ROUTER_ANYCAST);

    if(addr_record.type == config_type::record_type::IPV6_GLOBAL_UNICAST) {
        // special global unicast addresses
        if(ipv6_util::is_in6addr_6to4(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_6TO4);
        else if(ipv6_util::is_in6addr_discardprefix(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_DISCARDPREFIX);
        else if(ipv6_util::is_in6addr_teredotunneling(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_TEREDO);
        else if(ipv6_util::is_in6addr_orchid(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_ORCHID);
        else if(ipv6_util::is_in6addr_orchidv2(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_ORCHIDV2);
        else if(ipv6_util::is_in6addr_doc(a))
            addr_record.attrs.push_back(config_type::record_type::IPV6_DOC);
    }

    // prefix specified and unicast?
    if(addr_record.prefix > 0 && ipv6_util::is_in6addr_unicast(a)) {
        addr_record.subnet = ipv6_util::init6(ipv6_util::calculate_subnet_address(a, addr_record.prefix));
        addr_record.attrs.push_back(config_type::record_type::SUBNET_FILLED);
    }
    if(addr_record.type == config_type::record_type::IPV6_MULTICAST) {
        if(ipv6_util::is_in6addr_multicast_solicitednode(a))
            addr_record.attrs.push_back(config_type::record_type::SOLICITED_NODE_MULTICAST);
        // do scope tests here?
    }

    return true;
}

bool collect_ip4_addr_info(config_type::record_type &addr_record)
{
    const auto &addr = ipv4_util::get_inaddr(addr_record.addr);
    if(ipv4_util::is_in4addr_loopback(addr))
        addr_record.type = config_type::record_type::IPV4_LOOPBACK;
    else if(ipv4_util::is_in4addr_any(addr))
        addr_record.type = config_type::record_type::IPV4_ANY;
    else if(ipv4_util::is_in4addr_broadcast(addr))
        addr_record.type = config_type::record_type::IPV4_BROADCAST;
    else if(ipv4_util::is_in4addr_multicast(addr))
        addr_record.type = config_type::record_type::IPV4_MULTICAST;
    else if(ipv4_util::is_in4addr_private(addr))
        addr_record.type = config_type::record_type::IPV4_PRIVATE;
    else
        addr_record.type = config_type::record_type::IPV4_UNKNOWN;

    return true;
}

bool collect_information(std::vector<config_type::record_type> &records)
{
    for(auto &addr_record: records) {
        if(addr_record.addr.ss_family == AF_INET)
            collect_ip4_addr_info(addr_record);
        else if(ipv6_util::is_ipv6(addr_record.addr))
            collect_ip6_addr_info(addr_record);
        else
            std::cerr << "address type not supported: "
                      << ip_util::ai_family_to_string(addr_record.addr.ss_family) << ".\n";
    }

    return true;
}

sockaddr_storage convert(const sockaddr &addr)
{
    sockaddr_storage dst;
    std::memset(&dst, 0, sizeof(dst));
    if(addr.sa_family == AF_INET) {
        auto dstp = reinterpret_cast<void *>(&reinterpret_cast<sockaddr_in *>(&dst)->sin_addr);
        std::memcpy(dstp, reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr),
                    sizeof(sockaddr_in));
        dst.ss_family = addr.sa_family;
    } else if(addr.sa_family == AF_INET6) {
        auto dstp = reinterpret_cast<void *>(&reinterpret_cast<sockaddr_in6 *>(&dst)->sin6_addr);
        std::memcpy(dstp, reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(&addr)->sin6_addr),
                    sizeof(sockaddr_in6));
        dst.ss_family = addr.sa_family;
    }
    return dst;
}

// taken from the book: IPv6 Fundamentals: A Straightforward Approach to Understanding IPv6
// maybe print only for prefix sizes 56 and 64?
std::string ipv6_314_rule(const sockaddr_storage &sa, const config_type::output_config_type &output_config)
{
    const in6_addr *sa6 = &reinterpret_cast<const sockaddr_in6 *>(&sa)->sin6_addr;
    return std::string(util::ct(output_config.info_color, "global routing prefix: "))
        + std::string(util::ct(output_config.addr_color, ip_util::to_hex_string(ntohs(sa6->s6_addr16[0])) + ":"
                               + ip_util::to_hex_string(ntohs(sa6->s6_addr16[1]))
                               + ":" + ip_util::to_hex_string(ntohs(sa6->s6_addr16[2])) + ":"))
        + std::string(util::ct(output_config.info_color, ", subnet id: "))
        + std::string(util::ct(output_config.addr_color, ip_util::to_hex_string(ntohs(sa6->s6_addr16[3]))))
        + std::string(util::ct(output_config.info_color, ", interface id: "))
        + std::string(util::ct(output_config.addr_color, ip_util::to_hex_string(ntohs(sa6->s6_addr16[4]))
                               + ":" + ip_util::to_hex_string(ntohs(sa6->s6_addr16[5]))
                               + ":" + ip_util::to_hex_string(ntohs(sa6->s6_addr16[6]))
                               + ":" + ip_util::to_hex_string(ntohs(sa6->s6_addr16[7]))));
}

void print_ula_info(const sockaddr_storage &sa, const config_type::output_config_type &output_config,
                           const std::string &print_prefix)
{
    std::cout << print_prefix << " | 7 bits prefix | L bit "
        "| 40 bits pseudo-random global id | 16 bits subnet id | 64 bits interface id|\n";
    //   -> global id == last 40 bits of SHA1(EUI64 + NTP-64-bit time_stamp)
}

void print_ip6_addr(const sockaddr_storage &sa, uint8_t prefix,
                    const config_type::output_config_type &output_config,
                    const std::string &print_prefix)
{
    using namespace util;
    if(output_config.verbosity > 1) {
        if(prefix) {
            if(prefix == 128)
                std::cout << ct(output_config.info_color, print_prefix
                                + "A prefix size of 128 can address exactly one host.\n");
            else if(prefix == 127)
                std::cout << ct(output_config.info_color, print_prefix
                                + "A prefix size of 127 is typically chosen for securyity reasons.(RFC 6164)\n");
            else if(prefix % 4 != 0)
                std::cout << ct(output_config.error_color, print_prefix
                                + "o A prefix size not dividible by 4 means subnetting was not done on nibble\n"
                                + print_prefix + "  boundaries.\n");

            

            if(prefix > 64)
                std::cout << ct(output_config.info_color, print_prefix
                                + "A prefix size >64 disables SLAAC since EUI64 uses 64bit interface ids.\n");
        }
    }


    // from obsolete RFC 2374: General note on unicast addresses: the
    // first 16 bits are the TLA, the next 8 bits must be zero, then
    // 24 bits of NLA (48 bits total), 16 bits of SLA (64 bits total),
    // and 64 bits for the interface. (obsoleted by RFC 3587)
    // ->TLA/NLA removed. SLA is now the subnet id

    // global routing prefix | subnet id | interface id
    // subnet prefix                     | interface id

    // print binary digits
    if(output_config.verbosity > 0 && !prefix) {
        const auto &sa6 = ipv6_util::get_in6addr(sa);
        std::cout << print_prefix;
        for(size_t i = 0, i16 = 0; i < 16; i++) {
//            if(ipv6_util::get_in6addr16(sa6)[i16] == 0)
//                std::cout << "0";
//            else
            std::cout << ip_util::dump_bin(ipv6_util::get_in6addr8(sa6)[i]);
            if(i % 2 && i != 15)
                std::cout << " : ";
            else if(i != 15)
                std::cout << " ";

            if(i%2)
                i16++;
        }
        std::cout << "\n";
    } else if(output_config.verbosity > 0 && prefix) {
        // same as above, but with color
        std::cout << "\n" <<  print_prefix << ct(output_config.subnet_color, "subnet prefix") << " "
                  << "interface id" << "\n";
        const auto &sa6 = ipv6_util::get_in6addr(sa);
        std::cout << print_prefix;
        size_t bit_count = 0;
        for(size_t i = 0; i < 16; i++) {
            const std::string bin = ip_util::dump_bin(ipv6_util::get_in6addr8(sa6)[i]);
            bit_count += 8;
            if((prefix < bit_count)
               && ((size_t(prefix) + 8) >= bit_count)) {
                bool once = true;
                for(size_t j = bin.length(); j >= 1; j--)
                    if((prefix + j - 1) < bit_count) {
                        if(!output_config.use_colors && once) {
                            std::cout << "^";
                            once = false;
                        }
                        std::cout << std::string(1, bin[bin.length() - j]);
                    } else {
                        std::cout << ct(output_config.subnet_color, bin[bin.length() - j]);
                    }

            } else if(prefix >= bit_count){
                std::cout << ct(output_config.subnet_color, std::move(bin));
            } else if(prefix < bit_count){
                std::cout << bin;
            }

            if(i % 2 && i != 15)
                std::cout << " : ";
            else if(i != 15)
                std::cout << " ";
        }
        std::cout << "\n";
    }
    //std::cout << "idx16_longest_all0_segment: " << ipv6_util::idx16_longest_all0_hextet(ipv6_util::get_in6addr(sa)) << "\n";
}

void print_ip4_addr(const sockaddr_storage &sa, uint8_t prefix,
                   const config_type::output_config_type &output_config, const std::string &print_prefix)
{
    if(output_config.verbosity > 1){
        if(prefix == 31)
            std::cout << print_prefix << "a prefix size of 31 is typically chosen for securyity reasons.";
    }
}

void print_ip_addr(const sockaddr_storage &sa, uint8_t prefix,
                   const config_type::output_config_type &output_config, const std::string &print_prefix)
{
    switch(sa.ss_family) {
    case AF_INET:
        print_ip4_addr(sa, prefix, output_config, print_prefix);
        break;
    case AF_INET6:
        print_ip6_addr(sa, prefix, output_config, print_prefix);
        break;
    default:
        std::cout << "\taddress family unhandled\n";
        break;
    }
}

std::tuple<bool, std::vector<config_type::local_if> > fill_if_info()
{
    std::vector<config_type::local_if> ifs;
    ifaddrs *ifap;
    if(getifaddrs(&ifap) == -1) {
        std::cerr << "getifaddrs: " << ip_util::error_string(errno) << "\n";
        return std::make_tuple(false, ifs);
    }

    for(ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr == nullptr)
            continue;

        // AF_PACKET contains link layer address
        if(ifa->ifa_addr->sa_family == AF_PACKET) {
            bool have = false;
            for(auto &parsed_if: ifs)
                if(parsed_if.ifname == ifa->ifa_name) {
                    memcpy(&parsed_if.mac48[0], &reinterpret_cast<sockaddr_ll *>(ifa->ifa_addr)->sll_addr[0], 6);
                    have = true;
                }
            if(have)
                continue;
            config_type::local_if current_if;
            current_if.ifname.assign(ifa->ifa_name);
            memcpy(&current_if.mac48[0], &reinterpret_cast<sockaddr_ll *>(ifa->ifa_addr)->sll_addr[0], 6);
            ifs.push_back(current_if);
            continue;
        }

        if(ifa->ifa_addr->sa_family != AF_INET6 && ifa->ifa_addr->sa_family != AF_INET)
            continue;

        config_type::record_type record;
        record.addr = convert(*ifa->ifa_addr);
        if(ifa->ifa_addr->sa_family == AF_INET)
            record.prefix = ipv4_util::count_leading_1(ipv4_util::get_inaddr(convert(*ifa->ifa_netmask)));
        else if(ifa->ifa_addr->sa_family == AF_INET6)
            record.prefix = ipv6_util::count_leading_1(ipv6_util::get_in6addr(convert(*ifa->ifa_netmask)));
        //std::cout << ">>netmask("<<ip_util::ntop(convert(*ifa->ifa_netmask))<<") -> prefix("<<(uint32_t)record.prefix<<")<<\n";

        // is there already an entry for this interface?
        bool have = false;
        for(auto &parsed_if: ifs)
            if(parsed_if.ifname == ifa->ifa_name) {
                parsed_if.if_records.push_back(record);

                have = true;
                break;
            }

        if(have)
            continue;

        config_type::local_if current_if;
        current_if.ifname.assign(ifa->ifa_name);
        current_if.if_records.push_back(record);
        ifs.push_back(current_if);
    }

    freeifaddrs(ifap);
    return std::make_tuple(true, ifs);
}

/*
// o calculate for prefixes the range of the subnet prefixes and display. e.g.: fe80::/10 -> "fe80 to febf" + bitpattern
in6_addr init6(uint32_t h1, uint32_t h2, uint32_t h3, uint32_t h4)
{
    using namespace ipv6_util;
    in6_addr a;
    get_in6addr32(a)[0] = htonl(h1);
    get_in6addr32(a)[1] = htonl(h2);
    get_in6addr32(a)[2] = htonl(h3);
    get_in6addr32(a)[3] = htonl(h4);
    return a;
}

in6_addr init6(uint16_t h1, uint16_t h2, uint16_t h3, uint16_t h4,
                         uint16_t h5, uint16_t h6, uint16_t h7, uint16_t h8)
{
    using namespace ipv6_util;
    in6_addr a;
    get_in6addr16(a)[0] = htons(h1);
    get_in6addr16(a)[1] = htons(h2);
    get_in6addr16(a)[2] = htons(h3);
    get_in6addr16(a)[3] = htons(h4);
    get_in6addr16(a)[4] = htons(h5);
    get_in6addr16(a)[5] = htons(h6);
    get_in6addr16(a)[6] = htons(h7);
    get_in6addr16(a)[7] = htons(h8);
    return a;
}

std::string multicast_prefix_range_string(const sockaddr_storage &addr, size_t prefix)
{
    const auto fe80 = init6(0xfe800000, 0, 0, 0);
    const auto fe801 = init6(0xfe800000, 0, 0, 0x1);
    const auto fe801b = init6(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
    std::cout << "init6debug: fe80 -> " << ip_util::ntop(ipv6_util::init6(fe80)) << "\n";
    std::cout << "init6debug: fe801 -> " << ip_util::ntop(ipv6_util::init6(fe801)) << "\n";
    std::cout << "init6debug: fe801b -> " << ip_util::ntop(ipv6_util::init6(fe801b)) << "\n";
    -> set (128 - prefix) trailing bits to zero
    -> set (128 - prefix) trailing bits to one
    -> stringify both addresses and cut them on next hextet boundary after prefix
    return "";
}
*/

std::string multicast_wellknown_string(const sockaddr_storage &addr)
{
    // TODO: tests should include 0 hextets
    using namespace ipv6_util;
    const auto &a = get_in6addr(addr);
    if(is_in6addr_multicast_nodelocal(a)) {
       if(get_in6addr32(a)[3] == htonl(0x00000001))
           return "node local all nodes address";
       else if(get_in6addr32(a)[3] == htonl(0x00000002))
           return "node local all routers address";
   } else if(is_in6addr_multicast_linklocal(a)) {
       if(get_in6addr32(a)[3] == htonl(0x00000001))
           return "link local all nodes address";
       else if(get_in6addr32(a)[3] == htonl(0x00000002))
           return "link local all routers address";
       else if(get_in6addr32(a)[3] == htonl(0x00000003))
           return "unassigned";
       else if(get_in6addr32(a)[3] == htonl(0x00000004))
           return "link local DVMRP routers address";
       else if(get_in6addr32(a)[3] == htonl(0x00000005))
           return "link local OSPFIGP address";
       else if(get_in6addr32(a)[3] == htonl(0x00000006))
           return "link local OSPFIGP designated routers address";
       else if(get_in6addr32(a)[3] == htonl(0x00000007))
           return "link local ST routers address";
       else if(get_in6addr32(a)[3] == htonl(0x00000008))
           return "link local ST hosts address";
       else if(get_in6addr32(a)[3] == htonl(0x00000009))
           return "link local RIP routers address";
       else if(get_in6addr32(a)[3] == htonl(0x0000000a))
           return "link local EIGRP routers address";
       else if(get_in6addr32(a)[3] == htonl(0x0000000b))
           return "link local mobile-agents address";
       else if(get_in6addr32(a)[3] == htonl(0x0000000d))
           return "link local all PIM routers address";
       else if(get_in6addr32(a)[3] == htonl(0x0000000e))
           return "link local RSVP-ENCAPSULATION address";
       else if(get_in6addr32(a)[3] == htonl(0x00010001))
           return "link local link name address";
       else if(get_in6addr32(a)[3] == htonl(0x00010002))
           return "link local all-dhcp-agents address";
    } else if(is_in6addr_multicast_sitelocal(a)) {
       if(get_in6addr32(a)[3] == htonl(0x00000002))
           return "site local all routers address";
       else if(get_in6addr32(a)[3] == htonl(0x00010003))
           return "site local all dhcp-servers address";
       else if(get_in6addr32(a)[3] == htonl(0x00010004))
           return "site local all dhcp-relays address";
       else if(get_in6addr32(a)[3] >= htonl(0x00011000)
               && get_in6addr32(a)[3] <= htonl(0x000113ff))
           return "site local all service location address";
    }

    // TODO All scope multicast addresses rfc 2375
    return "n/a possibly all scope address";
}

std::string multicast_scope_string(const sockaddr_storage &addr)
{
    using namespace ipv6_util;
    const auto &a = get_in6addr(addr);
    if(is_in6addr_multicast_nodelocal(a))
        return "node local";
    else if(is_in6addr_multicast_linklocal(a))
        return "link local";
    else if(is_in6addr_multicast_sitelocal(a))
        return "site local";
    else if(is_in6addr_multicast_orglocal(a))
        return "orc local";
    else if(is_in6addr_multicast_global(a))
        return "global";
    else if(is_in6addr_multicast_unicastprefixbased(a))
        return "unicast prefix based";
    else if(is_in6addr_multicast_adminlocal(a))
        return "admin local";
    else if(is_in6addr_multicast_unassigned(a))
        return "unassigned";
    else if(is_in6addr_multicast_rendezvouspointflag(a))
        return "rendezvous point flag";
    return "unknown";
}

std::string multicast_v4string(const sockaddr_storage &addr)
{
    using namespace ipv4_util;
    const auto &a = get_inaddr(addr);
    if(is_in4addr_multicast_unspec(a))
        return "unspecified";
    else if(is_in4addr_multicast_allhosts(a))
        return "all hosts";
    else if(is_in4addr_multicast_allrouters(a))
        return "all routers";
    else if(is_in4addr_multicast_maxlocalgroup(a))
        return "max local group";
    return "transient group";
}

std::string v4_class_string(const sockaddr_storage &addr)
{
    using namespace ipv4_util;
    const auto &a = get_inaddr(addr);
    if(is_in4addr_class_a(a))
        return "class A";
    else if(is_in4addr_class_b(a))
        return "class B";
    else if(is_in4addr_class_c(a))
        return "class C";
    else if(is_in4addr_class_d(a))
        return "class D";
    return "unknown class";
}

void print_addr_type_info(config_type::record_type::addr_type type,
                          const std::vector<config_type::record_type::addr_attr> &attrs,
                          const sockaddr_storage &addr, const config_type::output_config_type &output_config,
                          const sockaddr_storage &subnet,
                          const std::string &print_prefix)
{
    using namespace util;
    switch(type) {
    case config_type::record_type::IPV4_UNKNOWN:
        std::cout << ct(output_config.error_color, print_prefix
                        + "o ipv4 address type not recognised.\n");
        break;
    case config_type::record_type::IPV4_LOOPBACK:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o loopback address.\n");
        break;
    case config_type::record_type::IPV4_ANY:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o any address, all 0.\n");
        break;
    case config_type::record_type::IPV4_BROADCAST:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o broadcast address, all 1.\n");
        break;
    case config_type::record_type::IPV4_PRIVATE:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o private address(RFC 1918).\n");
        break;
    case config_type::record_type::IPV4_MULTICAST:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o multicast address: " + multicast_v4string(addr) + ".\n");
        break;
    case config_type::record_type::IPV6_UNKNOWN:
        std::cout << ct(output_config.error_color, print_prefix
                        + "o ipv6 address type not recognised.\n");
        break;
    case config_type::record_type::IPV6_UNSPECIFIED:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o unspecified address.\n");
        break;
    case config_type::record_type::IPV6_LOOPBACK:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o loopback address.\n");
        break;
    case config_type::record_type::IPV6_MULTICAST:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o " + (ipv6_util::is_in6addr_multicast_wellknown(ipv6_util::get_in6addr(addr)) ? "permanent" : "transient")
                        + " multicast address. prefix ff00::/8. scope: "
                        + multicast_scope_string(addr) + "\n"
                        + print_prefix + "  | ff | 4bits-flag | 4bits-scope | 112 bits group id |.\n");
        if(ipv6_util::is_in6addr_multicast_wellknown(ipv6_util::get_in6addr(addr)))
            std::cout << ct(output_config.info_color, print_prefix
                            + "  IANA assigned multiast address: " + multicast_wellknown_string(addr) + "\n");
        break;
    case config_type::record_type::IPV6_V4MAPPED:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o ipv4 mapped v6 address. prefix: ::ffff/96(RFC 4291)\n");

/*
 o ::/80 embedded v4 space
   v4compat | 80 0-bits | 16 0-bits | globally unique v4 addr | -> deprecated
   v4mapped | 80 0-bits | 16 1-bits | v4 addr that must not be globally unique | -> rfc 4291
*/

        break;
    case config_type::record_type::IPV6_V4COMPAT:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o deprecated IPv4-compatible IPv6 address: | 80 0-bits | 16 0-bits | globally unique v4 addr |\n");
        break;
    case config_type::record_type::IPV6_NAT64:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o nat64 rfcs 6146, 6052. prefix: 63::ff9b::/96. low 32bits are the ipv4 addr.\n");
        break;
    case config_type::record_type::IPV6_ULA:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o unique local address(ULA)(RFC 4193). prefix fc00::/7\n");
        print_ula_info(addr, output_config, print_prefix);
        break;
    case config_type::record_type::IPV6_GLOBAL_UNICAST:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o aggregatable global unicast address. prefix 2000::/3. 2000: to 3fff:\n");
        break;
    case config_type::record_type::IPV6_LINK_LOCAL:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o link local unicast address. prefix fe80::/10\n"
                        + print_prefix
                        + "o not routed, used for Neighbour Discovery\n"
                        + print_prefix
                        + "o dynamic assignment with EUI64 or random number or manual assignment.\n");
        break;
    case config_type::record_type::IPV6_IETF_RESERVED:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o IETF reserved address.\n");
        break;
    case config_type::record_type::IPV6_DEPRECATED_SITE_LOCAL:
        std::cout << ct(output_config.info_color, print_prefix
                        + "o IETF reserved address or site-local address(deprecated).\n");
        break;
    }

    if(output_config.verbosity > 1 &&type == config_type::record_type::IPV6_GLOBAL_UNICAST) {
        std::cout << ct(output_config.info_color, print_prefix + "o 314-rule: ")
                  << ipv6_314_rule(addr, output_config) << "\n";
    }

    if(ipv4_util::is_ipv4(addr))
        std::cout << ct(output_config.error_color, print_prefix
                        + "o " + v4_class_string(addr) + ".\n");

    // v6 unicast address
    if(ipv6_util::is_ipv6(addr) && type != config_type::record_type::IPV6_MULTICAST) {
        std::cout << ct(output_config.info_color, print_prefix + "o all addresses not in range ")
                  << ct(output_config.addr_color, "ff00::/8")
                  << ct(output_config.info_color, " are unicast addresses. A unicast\n"
                        + print_prefix + "  address can also be used as anycast address.\n");
        
    }

    for(const auto &attr: attrs) {
        switch(attr) {
            case config_type::record_type::CONTAINS_EUI64:
                {
                const auto mac = ipv6_util::mac48_from_i6(ipv6_util::get_in6addr(addr));
                const std::string macstr("\n" + print_prefix + "  mac: "
                                         + ip_util::to_hex_string((int)mac[0]) + ":"
                                         + ip_util::to_hex_string((int)mac[1]) + ":"
                                         + ip_util::to_hex_string((int)mac[2]) + ":"
                                         + ip_util::to_hex_string((int)mac[3]) + ":"
                                         + ip_util::to_hex_string((int)mac[4]) + ":"
                                         + ip_util::to_hex_string((int)mac[5]) + "\n");
                std::cout << ct(output_config.info_color, print_prefix
                                + "o interface id contains an EUI64 unique identifier(RFC 2373). "
                                "Address was\n" + print_prefix + "  most likely automatically assigned with SLAAC.")
                          << ct(output_config.addr_color, std::move(macstr)) << "\n";
                    
                break;
                }
        case config_type::record_type::SUBNET_FILLED:
            std::cout << ct(output_config.info_color, print_prefix + "o subnet is: "
                            + std::string(ct(output_config.addr_color, ip_util::ntop(subnet)))
                            + "\n");
            break;
        case config_type::record_type::ROUTER_ANYCAST:
            if(type != config_type::record_type::IPV6_MULTICAST)
                std::cout << ct(output_config.info_color, print_prefix
                                + "o has the format of a router anycast address(RFC 4291):\n"
                                + print_prefix + "  | n-bits subnet | 128-n 0-bits |\n");
            break;
        case config_type::record_type::SOLICITED_NODE_MULTICAST:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o solicited node multicast address(RFC 4291)(prefix ff02:0:0:0:0:1:ff00::/104) "
                            + "for the node with the 24 low order bits: "
                            + ip_util::dump_bin(ipv6_util::get_in6addr8(ipv6_util::get_in6addr(addr))[13])
                            + " "
                            + ip_util::dump_bin(ipv6_util::get_in6addr8(ipv6_util::get_in6addr(addr))[14])
                            + " "
                            + ip_util::dump_bin(ipv6_util::get_in6addr8(ipv6_util::get_in6addr(addr))[15])
                            +"\n")
                      << ct(output_config.info_color, print_prefix
                            + "  one solicited-node multicast address per unicast/anycast address.\n")
                      << ct(output_config.info_color, print_prefix
                            + "  used for DAD and NDP algorithms.\n");
            break;
        case config_type::record_type::IPV6_6TO4:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o 6to4 address.\n");
            break;
        case config_type::record_type::IPV6_DISCARDPREFIX:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o discard prefix rfc 6666.\n");
            break;
        case config_type::record_type::IPV6_TEREDO:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o teredo tunneling address rfc 4380.\n");
            break;
        case config_type::record_type::IPV6_ORCHID:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o ORCHID (Overlay Routable Cryptographic Hash Identifiers) deprecated prefix.\n");
            break;
        case config_type::record_type::IPV6_ORCHIDV2:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o ORCHID (Overlay Routable Cryptographic Hash Identifiers).\n");
            break;
        case config_type::record_type::IPV6_DOC:
            std::cout << ct(output_config.info_color, print_prefix
                            + "o documentation prefix.\n");
            break;

        }
    }
}

void print_record(const config_type::record_type &record,
                  config_type::output_config_type output_config, const std::string &print_prefix)
{
    print_addr_type_info(record.type, record.attrs, record.addr, output_config, record.subnet, print_prefix);
    std::cout << "\n";
    print_ip_addr(record.addr, record.prefix, output_config, print_prefix);
}

bool print_information(const config_type &config)
{
    if(config.output_config.verbosity == 3) {
        // provide some special information
        // print bitmasks:
        std::cout << "often used bitmasks:\n";
        const std::vector<uint8_t> masks({ 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff });
        const std::vector<uint16_t> masks16({ 0xff80, 0xffc0, 0xffe0, 0xfff0,
                    0xfff8, 0xfffc, 0xfffe, 0xffff });
        for(const auto &mask: masks)
            std::cout << "0x" << ip_util::to_hex_string((unsigned)mask)
                      << " = " << ip_util::dump_bin(mask)
                      << " = /" << bit_util::count_leading_1(bit_util::pad32_trailing_0(mask)) << "\n";
        for(const auto &mask: masks16)
            std::cout << "0x" << ip_util::to_hex_string((unsigned)mask)
                      << " = " << ip_util::dump_bin(mask)
                      << " = /" << bit_util::count_leading_1(bit_util::pad32_trailing_0(mask)) << "\n";
    }

    if(!config.local_ifs.empty())
        std::cout << "\n########################################"
            "########################################\n";
    using namespace util;
    for(const auto &ifinfo: config.local_ifs) {
        std::array<uint8_t, 8> eui64;
        std::array<uint8_t, 6> remaced;
        ipv6_util::eui64_from_mac48(eui64, ifinfo.mac48);
        ipv6_util::mac48_from_eui64(remaced, eui64);

        std::cout << "\n\"" << ifinfo.ifname << "\": mac: "
                  << util::ct(config.output_config.addr_color,
                              ip_util::to_hex_string((int)ifinfo.mac48[0]) + ":"
                              + ip_util::to_hex_string((int)ifinfo.mac48[1]) + ":"
                              + ip_util::to_hex_string((int)ifinfo.mac48[2]) + ":"
                              + ip_util::to_hex_string((int)ifinfo.mac48[3]) + ":"
                              + ip_util::to_hex_string((int)ifinfo.mac48[4]) + ":"
                              + ip_util::to_hex_string((int)ifinfo.mac48[5]))
                  << " -> eui64(mac): "
                  << util::ct(config.output_config.addr_color,
                              ip_util::to_hex_string((int)eui64[0])
                              + ip_util::to_hex_string((int)eui64[1]) + ":"
                              + ip_util::to_hex_string((int)eui64[2])
                              + ip_util::to_hex_string((int)eui64[3]) + ":"
                              + ip_util::to_hex_string((int)eui64[4])
                              + ip_util::to_hex_string((int)eui64[5]) + ":"
                              + ip_util::to_hex_string((int)eui64[6])
                              + ip_util::to_hex_string((int)eui64[7]))
                  << "\n{";

        for(const auto &ifaddr: ifinfo.if_records) {
            std::cout << "\n  \"" << util::ct(config.output_config.addr_color, ip_util::ntop(ifaddr.addr)) << "\" -> " << " {\n";
            print_record(ifaddr, config.output_config, "    ");
            std::cout << "  }\n";
        }

        std::cout << "}\n";
    }

    if(!config.local_ifs.empty())
        std::cout << "\n########################################"
            "########################################\n";
    for(const auto &ip: config.records) {
        std::cout << "\n\"" << util::ct(config.output_config.addr_color, ip_util::ntop(ip.addr)
                                        + (ip.prefix ? "/" + std::to_string(ip.prefix) : ""))
                  << "\" -> " << " {\n";

        if(!ip.valid) {
            std::cout << ct(config.output_config.error_color,
                            "  invalid address detected)") << "\n}\n";
            std::cout << "dbg: .prefix = \"" << std::to_string(ip.prefix) << "\"" << "\n"
                      << "dbg: .addr_arg = \"" << ip_util::ntop(ip.addr) << "\"" << "\n"
                      << "dbg: .af = \"" << ip_util::ai_family_to_string(ip.addr.ss_family) << "\"\n}\n";
            continue;
        }

        print_record(ip, config.output_config, "  ");
        std::cout << "}\n";
    }

    return true;
}

// quick hack addr checker
std::tuple<bool, config_type::record_type> parse_iparg(const std::string &ip)
{
    size_t digits = 0;
    size_t alphas = 0;
    size_t dots = 0;
    size_t colons = 0;
    size_t cidr = 0;
    size_t zone_id = 0;
    for(size_t i = 0; i < ip.length(); i++) {
        if(isdigit(ip[i]))
            digits++;
        else if(isalpha(ip[i]))
            alphas++;
        else if(ip[i] == '.')
            dots++;
        else if(ip[i] == ':')
            colons++;
        else if(ip[i] == '/') {
            cidr = i;
            break;
        } else if(ip[i] == '%') {
            zone_id = i;
            break;
        }
    }

    config_type::record_type arg;
    int af = AF_UNSPEC;

    if(!alphas && !colons && dots == 3)
        af = AF_INET;
    else if((alphas || digits) && !dots && colons)
        af = AF_INET6;
    else
        // assume v4 mapped ..
        af = AF_INET6;

    std::string addr_arg(ip);
    std::string cidr_arg;

    if(zone_id) {
        if(cidr && (zone_id < cidr)) {
            std::cerr << "invalid argument: zone-id must come after prefix\n";
            return std::make_tuple(false, arg);
        }
        addr_arg = addr_arg.substr(0, zone_id);
        std::cerr << "zone-ids <ip6-address>%<zone_id>(RFC 4007) not supported. ignored.\n";
    }

    if(cidr) {
        using namespace util;
        cidr_arg = addr_arg.substr(cidr + 1, addr_arg.length() - cidr);
        const auto pprefix = std::strtoul(cidr_arg.c_str(), nullptr, 10);
        if(errno == ERANGE
           || (af == AF_INET && !bit_util::in_region<0, 32>(pprefix))
           || (af == AF_INET6 && !bit_util::in_region<0, 128>(pprefix))) {
            std::cerr << "invalid prefix specified: " << cidr_arg << "\n";
            return std::make_tuple(false, arg);
        }

        arg.prefix = pprefix;
        addr_arg = addr_arg.substr(0, cidr);
    } else {
        arg.prefix = 0;
    }

    std::memset(&arg.addr, 0, sizeof(arg.addr));

    const auto ret = ip_util::pton(af, addr_arg, arg.addr);
    arg.valid = af == arg.addr.ss_family && ret;
    if(!ret)
        std::cerr << "invalid argument: \"" << addr_arg << "\"\n";
    return std::make_tuple(ret, arg);
}

bool parse_args(int argc, char *argv[], config_type &config)
{
    for(int i = 1; i < argc; i++) {
        const std::string ai(argv[i]);
        if(ai[1] == '\0') {
            std::cerr << "invalid argument: '-'\n";
            return false;
        }
        if(ai[0] == '-' && ai[1] != '-') {
            for(size_t i = 1; i < ai.length(); i++) {
                switch(ai[i]) {
                case 'c':
                    config.output_config.use_colors = true;
                    break;
                case 'l':
                    config.output_config.print_local_ifs = true;
                    break;
                case 'v':
                    config.output_config.verbosity++;
                    break;
                default:
                    std::cerr << "invalid argument: '-" << ai[i] << "'\n";
                    return false;
                }
            }
            continue;
        } else if(ai[0] == '-' && ai[1] == '-') {
            // longopts
            if(ai == "--color") {
                config.output_config.use_colors = true;
            } else if(ai == "--localifs") {
                config.output_config.print_local_ifs = true;
            } else {
                std::cerr << "invalid argument: \"" << ai << "\"\n";
                return false;
            }
        }

        const auto parsed_ip = parse_iparg(ai);
        if(!std::get<0>(parsed_ip))
            return false;

        config.records.emplace_back(std::get<1>(parsed_ip));
    }
    if(config.output_config.print_local_ifs)
        config.local_ifs = std::get<1>(fill_if_info());

    if(config.records.empty() && config.local_ifs.empty()) {
        std::cerr << "Nothing to do.\n";
        return false;
    }

    if(!config.output_config.use_colors) {
        config.output_config.error_color = util::NO_COLOR;
        config.output_config.info_color = util::NO_COLOR;
        config.output_config.addr_color = util::NO_COLOR;
        config.output_config.subnet_color = util::NO_COLOR;
    }

    return true;
}

void usage(int argc, char *argv[])
{
    std::cerr << "ipinfo 0.1\n"
              << "Usage: " << argv[0] << "[OPTION]\n"
              << "\t-c, --color\tattempts to improve readability by colorizing output."
              << "\n\t\t\tmesses up shell redirects.\n"
              << "\t-l, --localifs\tprint local interface addresses\n"
              << "\t-v\t\tincrease verbosity, can be specified  up to 3 times\n";
}

int main(int argc, char *argv[])
{
    config_type config;
    if(!parse_args(argc, argv, config)) {
        usage(argc, argv);
        return -1;
    }

    if(!collect_information(config.records)) {
        usage(argc, argv);
        return -1;
    }
    for(auto &iface: config.local_ifs)
        if(!collect_information(iface.if_records)) {
            usage(argc, argv);
            return -1;
        }

    if(!print_information(config)) {
        usage(argc, argv);
        return -1;
    }

    return 0;
}
