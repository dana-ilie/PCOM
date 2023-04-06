from collections import namedtuple, OrderedDict
import sys

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP, checksum

import info


ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"


def error(msg, *args):
    print("-- {}".format(msg), *args, file=sys.stderr)


def dump_packets(packets):
    print("###################################")
    print("All packets:\n")
    for p in packets:
        error("Packet\n{}".format(p.show(dump=True)))

    print("###################################")


def check_nothing(testname, packets):
    """Verify a machine received 0 packages. Used as a default."""
    if len(packets) != 0:
        error("Excess packets")
        dump_packets(packets)
        return False

    return True


def valid_arp_req(host, packet, addr):
    if ARP not in packet:
        return False

    a = packet[ARP]
    if not a.get_field("op").i2repr(a, a.op) == "who-has":
        return False

    if a[ARP].hwsrc != addr:
        return False

    return True


def valid_arp_req_from_router(host, router, packet):
    return valid_arp_req(host, packet, info.get("router_mac", host, router))


def valid_arp_req_to_router(host, router, packet):
    return valid_arp_req(host, packet, info.get("host_mac", host))


def valid_arp_reply(host, packet, addr_s, addr_d):
    if ARP not in packet:
        return False

    a = packet[ARP]
    if not a.get_field("op").i2repr(a, a.op) == "is-at":
        return False

    if a[ARP].hwsrc != addr_s:
        return False

    if a[ARP].hwdst != addr_d:
        return False

    return True


def valid_arp_reply_from_router(host, router, packet):
    src = info.get("router_mac", router, host)
    dst = info.get("host_mac", host)
    return valid_arp_reply(host, packet, src, dst)


def valid_arp_reply_to_router(host, router, packet):
    src = info.get("host_mac", host)
    dst = info.get("router_mac", host, router)
    return valid_arp_reply(host, packet, src, dst)


def valid_icmp_unreachable(host, packet):
    return ICMP in packet and packet[ICMP].type == 3 and packet[ICMP].code == 2


def cull_icmp_unreachable(host, packets):
    culled_packets = []
    count = 0
    for packet in packets:
        if valid_icmp_unreachable(host, packet):
            count += 1
        else:
            culled_packets.append(packet)

    return count, culled_packets


def cull_dull_packets(host, router, packets):
    """Remove uninteresting packets"""
    router_f = {
        valid_arp_req_from_router : False,
        valid_arp_reply_to_router : False,
    }
    host_f = {
        valid_arp_req_to_router,
        valid_arp_reply_from_router,
    }

    culled_packets = []
    for packet in packets:
        v = False
        for fn, b in router_f.items():
            if fn(host, router, packet):
                if b:
                    return False, []

                router_f[fn] = True
                v = True
                break

        for fn in host_f:
            if fn(host, router, packet):
                v = True

        if not v:
            culled_packets.append(packet)

    return True, culled_packets


def validate_all_from_host(host, packets):
    """True if all packets are sent from host (an eventual replies)"""
    for packet in packets:
        if Ether not in packet:
            return False

        if packet[Ether].src != info.get("host_mac", host):
            return False

    return True


def validate_all_from_host_or_replies(host, packets):
    """True if all packets are sent from host (an eventual replies)"""
    for ps, pr in zip(packets[::2], packets[1::2]):
        if Ether not in ps or Ether not in pr:
            return False

        if ps[Ether].src != info.get("host_mac", host):
            return False

        if pr[Ether].dst != info.get("host_mac", host):
            return False

    return True


def sender_default(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    res, packets = cull_dull_packets(hs, router, packets)
    _, packets = cull_icmp_unreachable(hs, packets)
    ok = validate_all_from_host(hs, packets)
    if not ok:
        ok = validate_all_from_host_or_replies(hs, packets)

    return res and ok


def router_arp_reply_p(testname, packets):
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()
    if len(packets) < 2:
        error("No reply received")
        dump_packets(origpackets)
        return False

    if Ether not in packets[1]:
        error("Packet not of Ethernet type")
        dump_packets(origpackets)
        return False

    e = packets[1][Ether]
    if e.src != info.get("router_mac", hr, router):
        error("Wrong source address")
        error("Expected: {}".format(info.get("router_mac", hr, router)))
        error("Got: {}".format(e.src))
        dump_packets(origpackets)
        return False

    if e.dst != info.get("host_mac", hr):
        error("Wrong destination address")
        error("Expected: {}".format(info.get("host_mac", hr)))
        error("Got: {}".format(e.dst))
        dump_packets(origpackets)
        return False

    if ARP not in packets[0]:
        error("Packet not of ARP type")
        dump_packets(origpackets)
        return False

    a = packets[1][ARP]

    if a.get_field("op").i2repr(a, a.op) != "is-at":
        error("Wrong ARP type")
        dump_packets(origpackets)
        return False

    if a[ARP].hwdst != info.get("host_mac", hr):
        error("Wrong destination in ARP reply")
        error("Expected: {}".format(info.get("host_mac", hr)))
        error("Got: {}".format(a[ARP].hwdst))
        dump_packets(origpackets)
        return False

    return True


def router_arp_reply_a(testname):
    """Test the router responds to an ARP request"""
    hs = TESTS[testname].host_s
    r_ip = info.get("router_ip", hs)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    return [Ether(src=s_mac, dst=ETHER_BROADCAST) / ARP(psrc=s_ip, pdst=r_ip)]


def router_arp_request_p(testname, packets):
    # at this point we're not interested in whether the router actually
    # delivered the packet, just the arp request.
    hr = TESTS[testname].host_r
    origpackets = packets.copy()

    if len(packets) < 1:
        error("No packet received!")
        dump_packets(origpackets)
        return False

    assert ARP in packets[0], "No ARP request!"
    a = packets[0][ARP]
    if a.get_field("op").i2repr(a, a.op) != "who-has":
        error("Wrong ARP type")

    if a.pdst != info.get("host_ip", hr):
        error("Wrong ARP address request")
        error("Expected {}".format(info.get("host_ip", hr)))
        error("Got {}".format(a.pdst))
        dump_packets(origpackets)
        return False

    return True


def router_arp_request_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router

    r_mac = info.get("router_mac", hs, router)
    target_ip = info.get("host_ip", hr)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)

    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip)]


def forward_p(testname, packets):
    # The router may or may not (depending on its ARP cache) also send us an
    # ARP request
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()

    res, packets = cull_dull_packets(hr, router, packets)
    icmp_ur, packets = cull_icmp_unreachable(hr, packets)

    if not len(packets):
        error("No packet received")
        dump_packets(origpackets)
        return False

    nr_pkts = 2 if testname == "forward_no_arp" else 1
    if (hs in {0, 1} and hr in {2, 3}) or (hs in {2, 3} and hs in {0, 1}):
        nr_pkts += 2

    if not res or len(packets) > nr_pkts:
        error("Excess packets:")
        dump_packets(origpackets)

        return False

    ipPresent = False
    for p in packets:
        if IP in p:
            ipPresent = True
            break

    if not ipPresent:
        error("No IP packet from router")
        dump_packets(origpackets)
        return False

    i = p[IP]
    result = True

    if testname == "ttl":
        crt = i.ttl == 63
        if not crt:
            error("Wrong TTL value")
            error("Expected: ttl=63")
            error("Got: ttl={}".format(i.ttl))

        result = result and crt
    if testname == "checksum":
        router_chk = i.chksum
        i.chksum = 0
        correct_chk = checksum(bytes(i))

        crt = router_chk == correct_chk
        if not crt:
            error("Wrong checksum value")
            error("Expected: checksum=0x{:04x}".format(correct_chk))
            error("Got: checksum=0x{:04x}".format(i.chksum))

        result = result and crt

    crt = i.dst == info.get("host_ip", hr)
    if not crt:
        error("Wrong IP destination value")
        error("Expected: destination={}".format(info.get("host_ip", hr)))
        error("Got: destination={}".format(i.dst))

    result = result and crt

    crt = i.src == info.get("host_ip", hs)
    if not crt:
        error("Wrong IP source value")
        error("Expected: destination={}".format(info.get("host_ip", hs)))
        error("Got: destination={}".format(i.src))

    result = result and crt
    if not result:
        dump_packets(origpackets)

    return result


def forward_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    r_mac = info.get("router_mac", hs, router)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    target_ip = info.get("host_ip", hr)

    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip)]


def forward_no_arp_a(testname):
    """Send two packets; there should be at most just one! ARP request"""
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    r_mac = info.get("router_mac", hs, router)
    target_ip = info.get("host_ip", hr)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)

    packet = Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip)
    return [packet, packet]


def wrong_checksum_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    r_mac = info.get("router_mac", hs, router)
    target_ip = info.get("host_ip", hr)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)

    i = IP(src=s_ip, dst=target_ip)
    chk = checksum(bytes(i))
    chk = (chk + 1) % (2 ** 16)
    i.chksum = chk

    return Ether(src=s_mac, dst=r_mac) / i


def icmp_timeout_p(testname, packets):
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    if not len(packets):
        error("No packet received")
        dump_packets(origpackets)
        return False

    if not res or len(packets) > 2:
        error("Excess packets:")
        dump_packets(origpackets)
        return False

    if ICMP not in packets[1]:
        error("No ICMP packet from router")
        dump_packets(origpackets)
        return False

    i = packets[1][ICMP]
    if not (i.type == 11 and i.code == 0):
        error("Wrong ICMP type and/or code")
        error("Expected type=11, code=0")
        error("Got type={}, code={}".format(i.type, i.code))
        dump_packets(origpackets)
        return False

    return True


def icmp_timeout_a(testname):
    hr = TESTS[testname].host_r
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    target_ip = info.get("host_ip", hr)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    r_mac = info.get("router_mac", hs, router)

    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip, ttl=1)]


def host_unreachable_p(testname, packets):
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    if not len(packets):
        error("No packet received")
        dump_packets(origpackets)
        return False

    if not res or len(packets) > 2:
        error("Excess packets:")
        dump_packets(origpackets)
        return False

    if ICMP not in packets[1]:
        error("No ICMP packet from router")
        dump_packets(origpackets)
        return False

    i = packets[1][ICMP]
    if not (i.type == 3 and i.code == 0):
        error("Wrong ICMP type and/or code")
        error("Expected type=3, code=0")
        error("Got type={}, code={}".format(i.type, i.code))
        dump_packets(origpackets)
        return False

    return True


def host_unreachable_a(testname):
    target_ip = "10.0.0.1"
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    r_mac = info.get("router_mac", hs, router)

    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip)]


def router_icmp_p(testname, packets):
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    if len(packets) < 2:
        error("No packet received")
        dump_packets(origpackets)
        return False

    if not res or len(packets) > 2:
        error("Excess packets:")
        dump_packets(origpackets)

        return False

    if ICMP not in packets[1]:
        error("No ICMP packet from router")
        dump_packets(origpackets)
        return False

    i = packets[1][ICMP]
    if not (i.type == 0 and i.code == 0):
        error("Wrong ICMP type and/or code")
        error("Expected type=0, code=0")
        error("Got type={}, code={}".format(i.type, i.code))
        dump_packets(origpackets)
        return False

    return True


def router_icmp_a(testname):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    r_mac = info.get("router_mac", router, hs)
    r_ip = info.get("router_ip", hs)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=r_ip) / ICMP()]


def forward10packets_p(testname, packets):
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)
    if not res:
        error("Excess packets")
        dump_packets(origpackets)
        return False

    if len(packets) < 20 or len(packets) > 22:  # for the final test, allow arp
        error("Wrong number of packets!")
        error("Expected: 20")
        error("Got: {}".format(len(packets)))
        dump_packets(origpackets)
        return False

    return True


def forward10packets_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    router = TESTS[testname].router
    r_mac = info.get("router_mac", router, hs)
    target_ip = info.get("host_ip", hr)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs)
    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip)
            / ICMP()] * 10


Test = namedtuple("Test", ["host_s", "host_r", "router", "active_fn", "passive_fn"])
TESTS = OrderedDict([
        ("router_arp_reply", Test(0, 0, 0, router_arp_reply_a, router_arp_reply_p)),
        ("router_arp_request", Test(0, 1, 0, router_arp_request_a, router_arp_request_p)),
        ("forward", Test(0, 1, 0, forward_a, forward_p)),
        ("forward_no_arp", Test(0, 1, 0, forward_no_arp_a, forward_p)),
        ("ttl", Test(0, 1, 0, forward_a, forward_p)),
        ("checksum", Test(0, 1, 0, forward_a, forward_p)),
        ("wrong_checksum", Test(0, 1, 0, wrong_checksum_a, check_nothing)),
        ("forward02", Test(0, 2, 0, forward_a, forward_p)),
        ("forward03", Test(0, 3, 0, forward_a, forward_p)),
        ("forward10", Test(1, 0, 0, forward_a, forward_p)),
        ("forward12", Test(1, 2, 0, forward_a, forward_p)),
        ("forward13", Test(1, 3, 0, forward_a, forward_p)),
        ("forward20", Test(2, 0, 0, forward_a, forward_p)),
        ("forward21", Test(2, 1, 0, forward_a, forward_p)),
        ("forward23", Test(2, 3, 0, forward_a, forward_p)),
        ("forward30", Test(3, 0, 0, forward_a, forward_p)),
        ("forward31", Test(3, 1, 0, forward_a, forward_p)),
        ("forward32", Test(3, 2, 0, forward_a, forward_p)),
        ("router_icmp", Test(0, 0, 0, router_icmp_a, router_icmp_p)),
        ("icmp_timeout", Test(0, 0, 0, icmp_timeout_a, icmp_timeout_p)),
        ("host_unreachable", Test(0, 0, 0, host_unreachable_a, host_unreachable_p)),
        ("forward10packets", Test(0, 1, 0, forward10packets_a, forward10packets_p)),
        ("forward10across", Test(0, 3, 0, forward10packets_a, forward10packets_p)),
        ])
