#!/usr/bin/python2

import os
from pathlib import Path
import threading
import time
import signal
import sys

import tests
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

import info

import os.path
from os import path

POINTS_PER_TEST = 1


def signal_handler(signal, frame):
    sys.exit(0)


def static_arp():
    srcp = os.path.join("src", info.ARP_TABLE)
    return path.exists(info.ARP_TABLE) or path.exists(srcp)


class FullTopo(Topo):
    def build(self, nr=2, nh=2):
        routers = []
        for i in range(nr):
            routers.append(self.addHost(info.get("router_name", i)))

        for i in range(nr):
            for j in range(i + 1, nr):
                ifn = info.get("r2r_if_name", i, j)
                self.addLink(routers[i], routers[j], intfName1=ifn,
                             intfName2=ifn)

        for i in range(nr):
            for j in range(nh):
                hidx = i * nh + j

                host = self.addHost(info.get("host_name", hidx))
                i1 = info.get("host_if_name", hidx)
                i2 = info.get("router_if_name", j)
                self.addLink(host, routers[i], intfName1=i1, intfName2=i2)


class FullNM(object):
    def __init__(self, net, n_routers, n_hosts):
        self.net = net
        self.hosts = []
        self.routers = []
        self.n_hosts = n_hosts
        for i in range(n_routers):
            r = self.net.get(info.get("router_name", i))
            hosts = []
            for j in range(n_hosts):
                hidx = i * n_hosts + j
                h = self.net.get(info.get("host_name", hidx))
                hosts.append(h)
                self.hosts.append(h)

            self.routers.append((r, hosts))

    def setup_ifaces(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                host_ip = info.get("host_ip", hidx)
                router_ip = info.get("router_ip", hidx)
                host_if = info.get("host_if_name", hidx)
                router_if = info.get("router_if_name", j)

                router.setIP(router_ip, prefixLen=24, intf=router_if)
                host.setIP(host_ip, prefixLen=24, intf=host_if)

        nr = len(self.routers)
        for i in range(nr):
            for j in range(i + 1, nr):
                ri_if = info.get("r2r_if_name", i, j)
                rj_if = info.get("r2r_if_name", i, j)
                ri_ip = info.get("r2r_ip1", i, j)
                rj_ip = info.get("r2r_ip2", i, j)
                self.routers[i][0].setIP(ri_ip, prefixLen=24, intf=ri_if)
                self.routers[j][0].setIP(rj_ip, prefixLen=24, intf=rj_if)

    def setup_macs(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                h_mac = info.get("host_mac", hidx)
                h_if = info.get("host_if_name", hidx)
                host.cmd("ifconfig {} hw ether {}".format(h_if, h_mac))

                r_mac = info.get("router_mac", hidx, i)
                r_if = info.get("router_if_name", j)
                router.cmd("ifconfig {} hw ether {}".format(r_if, r_mac))

        nr = len(self.routers)
        for i in range(nr):
            for j in range(i + 1, nr):
                ri_mac = info.get("r2r_mac", i, j)
                rj_mac = info.get("r2r_mac", j, i)
                ri_if = info.get("r2r_if_name", i, j)
                rj_if = info.get("r2r_if_name", i, j)
                self.routers[i][0].cmd("ifconfig {} hw ether {}".format(ri_if,
                                                                    ri_mac))
                self.routers[j][0].cmd("ifconfig {} hw ether {}".format(rj_if,
                                                                    rj_mac))

    def disable_unneeded(self):
        def disable_ipv6(host):
            host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
            host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')

        def disable_nic_checksum(host, iface):
            host.cmd('ethtool iface {} --offload rx off tx off'.format(iface))
            host.cmd('ethtool -K {} tx-checksum-ip-generic off'.format(iface))

        def disable_arp(host, iface):
            host.cmd("ip link set dev {} arp off".format(iface))

        for i, (router, hosts) in enumerate(self.routers):
            disable_ipv6(router)
            for j, host in enumerate(hosts):
                disable_ipv6(host)
                hidx = i * len(hosts) + j
                h_if = info.get("host_if_name", hidx)
                disable_nic_checksum(host, h_if)

            # we want complete control over these actions
            router.cmd('echo "0" > /proc/sys/net/ipv4/ip_forward')
            router.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
            if not static_arp():
                for (i, (router, hosts)) in enumerate(self.routers):
                    for j in range(len(hosts)):
                        hidx = i * len(hosts) + j
                        ifn = info.get("router_if_name", hidx)
                        disable_arp(router, ifn)

    def add_default_routes(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                ip = info.get("router_ip", hidx)
                host.cmd("ip route add default via {}".format(ip))

    def add_hosts_entries(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                for h in range(len(self.hosts)):
                    ip = info.get("host_ip", h)
                    # FIXME entries should be added only if they aren't there.
                    host.cmd("echo '{} h{}' >> /etc/hosts".format(ip, h))

    def setup(self):
        self.disable_unneeded()
        self.setup_ifaces()
        self.setup_macs()
        self.add_hosts_entries()
        self.add_default_routes()

    def start_routers(self):
        ifaces = ""
        for i in range(len(self.routers)):
            for j in range(i + 1, len(self.routers)):
                ifaces += "{} ".format(info.get("r2r_if_name", i, j))

        for i in range(self.n_hosts):
            ifaces += "{} ".format(info.get("router_if_name", i))

        for i, (router, _) in enumerate(self.routers):
            out = info.get("out_file", i)
            err = info.get("err_file", i)
            rtable = info.get("rtable", i)
            rname = "router{}".format(i)
            router.cmd("ln -s router {}".format(rname))
            if not len(router.cmd("pgrep {}".format(rname))):
                cmd = "./{} {} {} > {} 2> {} &".format(rname, rtable, ifaces,
                                                       out, err)
                router.cmd(cmd)
                time.sleep(info.TIMEOUT / 2)

    def run_test(self, testname):
        # restart router if dead
        self.start_routers()

        log = os.path.join(info.LOGDIR, testname)
        Path(log).mkdir(parents=True, exist_ok=True)

        test = tests.TESTS[testname]
        for hp in range(len(self.hosts)):
            lout = os.path.join(log, info.get("output_file", hp))
            lerr = os.path.join(log, info.get("error_file", hp))
            cmd = "./checker.py \
                    --passive \
                    --testname={} \
                    --host={} \
                    > {} \
                    2> {} &".format(testname, hp, lout, lerr)
            self.hosts[hp].cmd(cmd)

        time.sleep(info.TIMEOUT / 2)
        cmd = "./checker.py \
                --active \
                --testname={} \
                --host={} &".format(testname, test.host_s)
        self.hosts[test.host_s].cmd(cmd)

        results = {}
        time.sleep(info.TIMEOUT)
        for hp in range(len(self.hosts)):
            lout = os.path.join(log, info.get("output_file", hp))
            with open(lout, "r") as fin:
                results[hp] = fin.read().strip("\r\n")

        return results


def validate_test_results(results):
    passed = True
    for result in results.values():
        passed = passed and (result == "PASS")

    return passed


def should_skip(testname):
    if static_arp():
        return testname in {"router_arp_reply", "router_arp_request"}

    return False


def main(run_tests=False):
    topo = FullTopo(nr=info.N_ROUTERS, nh=info.N_HOSTSEACH)

    net = Mininet(topo)
    net.start()

    nm = FullNM(net, info.N_ROUTERS, info.N_HOSTSEACH)

    nm.setup()

    print("{:=^80}\n".format(" Running tests "))
    if run_tests:
        for testname in tests.TESTS:
            skipped = False

            if should_skip(testname):
                skipped = True
                passed = False
            else:
                results = nm.run_test(testname)
                passed = validate_test_results(results)
            str_status = "PASSED" if passed else "FAILED"
            if skipped:
                str_status = "SKIPPED"
            print("{: >20} {:.>50} {: >8}".format(testname, "", str_status))
            time.sleep(info.TIMEOUT / 2)

    else:
        net.startTerms()
        signal.signal(signal.SIGINT, signal_handler)
        forever = threading.Event()
        forever.wait()

    net.stop()


if __name__ == "__main__":
    # Tell mininet to print useful information
    if len(sys.argv) > 1 and sys.argv[1] == "tests":
        main(run_tests=True)
    else:
        setLogLevel("info")
        main()
