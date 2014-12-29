CC=g++
CXXFLAGS=-std=c++1y -Wall -Werror -O3
LDFLAGS=
INCLUDES=

.PHONY: all clean

all: ipinfo

sources := ipinfo.cc
objects := ipinfo.o
headers := bit_util.hh ipinfo_util.hh ip_util.hh ipv4_util.hh ipv6_util.hh

ipinfo: $(objects) $(headers)
	$(CC) $(CXXFLAGS) -o $@ $(objects) $(LDFLAGS)

.cc.o:
	$(CC) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o ipinfo

install: ipinfo
	cp ipinfo /opt/usr/bin

uninstall:
	rm -f /opt/usr/bin/ipinfo

FLAGS=-vvv

test_color: FLAGS=-cvvv
test_color: test

test_nocolor: FLAGS=-vvv
test_nocolor: test

test: test_local test_invalid test_v4mapped test_v4translated test_different_subnets test_different_subnets_dbg  test_special_v6

test_local:
	./ipinfo $(FLAGS) 192.168.2.207/24 192.168.2.207 \
		fdb5:a065:3e15::f97/128 fdb5:a065:3e15::f97 \
		fdb5:a065:3e15:0:222:1dff:fe12:345/64 fdb5:a065:3e15:0:222:1dff:fe12:345 \
		fe80::5054:ff:fec6:cb2d/64 fe80::5054:ff:fec6:cb2d \
		ff02::1 ff02::5

test_invalid:
	./ipinfo $(FLAGS) 0:0:0:0:0:0:0:D4CC:65D2

test_v4mapped:
	./ipinfo $(FLAGS) ::FFFF:212.204.101.210 \
			::FFFF:D4CC:65D2

test_v4translated:
	./ipinfo $(FLAGS) 0:0:0:0:FFFF:0:D4CC:65D2 \
			::FFFF:0:212.204.101.210 \
			::FFFF:0:D4CC:65D2

test_different_subnets:
	./ipinfo $(FLAGS) 2001:0db8:0123:4567:89ab:cdef:1234:5678/127 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/128 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/72 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/65 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/63 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/12 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/13

test_different_subnets_dbg:
	./ipinfo $(FLAGS) 2001:0db8:0123:4567:89ab:cdef:1234:5678/1 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/2 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/3 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/4 \
			2001:0db8:0123:4567:89ab:cdef:1234:5678/5 \

test_special_v6:
	./ipinfo $(FLAGS) ::1/128 ::1 ::/128 ::

test_v4_mcast:
	./ipinfo $(FLAGS) 239.255.255.250 224.0.0.0 224.0.1.129 239.255.255.255 223.255.255.0 240.0.0.0 \
		224.0.0.1 224.0.0.2 224.0.0.255

test_v4_private:
	./ipinfo $(FLAGS) 10.0.0.0 9.255.255.255 10.255.255.255 11.0.0.0 \
			172.16.0.0 172.31.255.255 172.15.255.255 172.32.0.0 \
			192.168.0.0 192.168.255.255 192.167.255.255 192.169.0.0

test_v6_reserved:
	./ipinfo $(FLAGS) \
		0100::/8 \
		0200::/7 \
		0400::/6 \
		0800::/5 \
		1000::/4 \
		4000::/3 \
		6000::/3 \
		8000::/3 \
		a000::/3 \
		c000::/3 \
		e000::/4 \
		f000::/5 \
		f800::/6 \
		fe00::/9

test_6to4:
	./ipinfo -vvvc \
		2002:c000:0204::/48 \
		2002:192.0.2.4::/48

test_zone_ids1:
	./ipinfo -vvvc \
			2001:0db8:0123:4567:89ab:cdef:1234:5678%em0

test_zone_ids2:
	./ipinfo -vvvc \
			2001:0db8:0123:4567:89ab:cdef:1234:5678%1

test_solicited_node:
	./ipinfo -vvvc \
		ff02:0:0:0:0:1:ff00::/104 \
		ff02:0:0:0:0:1:ff00:aa/104 \
		ff02:0:0:0:0:1:ffaa:aa/104 \
		ff02:0:0:0:0:1:ffbb:bb

test_nat64:
	./ipinfo -vvvc \
		64:ff9b::192.0.2.1 \
		64:ff9b::1 \
		64:ff9b::

test_special_v6_2:
	./ipinfo -vvvc \
		2001:: \
		2001:db8:: \
		2001:20:: \
		2001:10:: \

FLAGS=-vv

showoff_color: FLAGS=-cvvv
showoff_color: showoff

showoff:
	./ipinfo $(FLAGS) \
		2001:0db8:0123:4567:89ab:cdef:1234:5678/13 \
		fe80::5054:ff:fec6:cb2d/64 \
		ff02::2

showoff2_color: FLAGS=-cvvv
showoff2_color: showoff2

showoff2:
	./ipinfo $(FLAGS) -l
