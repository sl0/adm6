#!/usr/bin/env python
#encoding:utf8
#
# file:    device_tests.py
# author: sl0
# date:   2013-03-18
#

import unittest
from adm6.adm6configparser import Adm6ConfigParser
from adm6.filter6 import IP6_Filter, Ip6_Filter_Rule
from adm6.device import ThisDevice, DevTest
from adm6.hostnet6 import HostNet6
from sys import stdout
from os.path import expanduser as homedir
from ipaddr import IPv6Network

rule = {}

class ThisDevice_tests(unittest.TestCase):
    """
    some tests for class Ip6_Filter_Rule
    """

    def test_01_adm6_is_instance(self):
        """
        dv-01 ThisDevice: adm6 is instance
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        self.assertIsInstance(dev, ThisDevice)

    def test_02_unkn_is_not_instance(self):
        """
        dv-02 ThisDevice: unknown is not instance
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        try:
            dev = ThisDevice('unknown', cfg, hn6)
            value = True
        except:
            value = False
        self.assertFalse(value)

    def test_03_adm6_read_interfaces(self):
        """
        dv-03 ThisDevice: linux read_interface_file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('')
        except:
            pass
        self.assertEquals(err, False)

    def test_04_adm6_read_interfaces_fail(self):
        """
        dv-04 ThisDevice: linux read_interface_file fails
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('not_exisiting_file')
        except:
            pass
        self.assertEquals(err, True)

    def test_05_obi_read_interfaces(self):
        """
        dv-05 ThisDevice: OpenBSD read_interface_file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('obi-wan', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('')
        except:
            pass
        self.assertEquals(err, False)

    def test_06_linux_read_routingtab(self):
        """
        dv-06 ThisDevice: linux read_routing_tab
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('r-ex', cfg, hn6)
        err = False
        try:
            dev.routingtab = []
            err = dev.read_routingtab_file('')
        except:
            err = True
        self.assertEquals(err, False)
        expect = 28 # r-ex routingtable has 29 lines, one unreachable!
        value = len(dev.routingtab)
        self.assertEquals(expect, value)

    def test_07_linux_read_routingtab_fail(self):
        """
        dv-07 ThisDevice: linux read_routing_tab fails
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.routingtab = []
            err = dev.read_routingtab_file('asd')
        except:
            err = False
        self.assertEquals(err, True)
        expect = 0 # 'asd' does not exist!
        value = len(dev.routingtab)
        self.assertEquals(expect, value)

    def test_08_linux_read_routingtab(self):
        """
        dv-08 ThisDevice: read_routing_tab for invalid os
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('r-ex', cfg, hn6)
        err = False
        try:
            dev.routingtab = []
            dev.device_os = "invalid os"
            err = dev.read_routingtab_file('')
        except:
            err = True
        self.assertEquals(err, True)
        expect = 0 # invalid os has no valid routingtable!
        value = len(dev.routingtab)
        self.assertEquals(expect, value)

    def test_09_read_rules(self):
        """
        dv-09 ThisDevice: read_rules
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        cnt = 0
        try:
            err = dev.read_rules()
        except:
            err = -1
        self.assertEquals(err, 24)

    def test_10_read_rulefile(self):
        """
        dv-10 ThisDevice: read exisitng rule file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hpath = cfg.get_adm6_home()
        hfile = hpath + '/etc/hostnet6'
        rfile = hpath + '/etc/00-rules.admin'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        try:
            err = dev.read_rule_file(rfile)
        except:
            err = -1
        self.assertEquals(err, 40)
        #self.assertTrue(False)

    def test_11_read_rulefile(self):
        """
        dv-11 ThisDevice: read non exisitng rule file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hpath = cfg.get_adm6_home()
        hfile = hpath + '/etc/hostnet6'
        rfile = hpath + '/etc/10-rules.users'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        try:
            err = dev.read_rule_file(rfile)
        except:
            err = -1
        self.assertEquals(err, 0)
        #self.assertTrue(False)

    def test_12_read_rules(self):
        """
        dv-12 ThisDevice: read rules for www incl. err line
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('www', cfg, hn6)
        try:
            err = dev.read_rules()
        except:
            err = -1
        self.assertEquals(err, 26)

    def test_13_show_interfaces_r_ex(self):
        """
        dv-13 ThisDevice: show interfaces r-ex
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('r-ex', cfg, hn6)
        expect ="""# Interfaces:                                                                  #
#  eth0:   fe80::200:24ff:fec4:d818/64                                         #
#  eth1:   fe80::200:24ff:fec4:d819/64                                         #
#  eth1:   2001:db8:0:1::1/64                                                  #
#  eth1:   2001:db8:0:1::53/64                                                 #
#  eth2:   fe80::200:24ff:fec6:fc84/64                                         #
#  eth3:   fe80::200:24ff:fec6:fc85/64                                         #
#  eth3:   2001:db8::2/64                                                      #
#  lo:   ::1/128                                                               #
#  sit1:   2001:db8:0:3::1/64                                                  #
#  sit1:   fe80::574f:173/128                                                  #
#  tun0:   fe80:0:ff00::1/64                                                   #
#  tun1:   fe80:0:fe00::1/64                                                   #
#  tun2:   fe80:0:fd00::1/64                                                   #
#  tun3:   fe80:0:fc00::1/64                                                   #
#  tun4:   fe80:0:fb00::1/64                                                   #
#  tun5:   fe80:0:fa00::1/64                                                   #
"""
        message = dev.show_interfaces()
        self.assertEquals(message, expect)

    def test_14_show_interfaces_obi_wan(self):
        """
        dv-14 ThisDevice: show interfaces obi-wan
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('obi-wan', cfg, hn6)
        expect ="""# Interfaces:                                                                  #
#  lo0::   ::1/128                                                             #
#  lo0::   fe80::1/128                                                         #
#  sis0::   2001:db8:1:1::2/128                                                #
#  sis0::   fe80::200:24ff:feca:1d9c/128                                       #
#  sis1::   fe80::200:24ff:feca:1d9d/128                                       #
#  gif0::   2001:db8:1:5afe::2/128                                             #
#  gif0::   fe80::200:24ff:feca:1d9c/128                                       #
"""
        message = dev.show_interfaces()
        self.assertEquals(message, expect)

    def test_15_show_routingtab_adm6(self):
        """
        dv-15 ThisDevice: show routingtab adm6
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        expect ="""# Routingtable:                                                                #
#          [ target,                next_hop,          interface ]             #
# Route 1: [IPv6Network('2001:db8:0:beef::/64'), IPv6Network('::/0'), 'eth0']  #
# Route 2: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth0']             #
# Route 3: [IPv6Network('::/0'), IPv6Network('fe80::a00:27ff:fe59:d69e/128'), 'eth0']#
"""
        message = dev.show_routingtab()
        self.assertEquals(message, expect)

    def test_16_show_routingtab_r_ex(self):
        """
        dv-16 ThisDevice: show routingtab r-ex
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('r-ex', cfg, hn6)
        expect = """# Routingtable:                                                                #
#          [ target,                next_hop,          interface ]             #
# Route 1: [IPv6Network('2001:db8:1::/64'), IPv6Network('::/0'), 'eth3']       #
# Route 2: [IPv6Network('2001:db8:1:1::/64'), IPv6Network('::/0'), 'eth1']     #
# Route 3: [IPv6Network('2001:db8:1:2::/64'), IPv6Network('::/0'), 'sit1']     #
# Route 4: [IPv6Network('2001:db8:1:3::/64'), IPv6Network('::/128'), 'sit1']   #
# Route 5: [IPv6Network('2001:db8:1:fa00::/56'), IPv6Network('fe80:0:fa00::2/128'), 'tun0']#
# Route 6: [IPv6Network('2001:db8:1:fb00::/56'), IPv6Network('fe80:0:fb00::2/128'), 'tun1']#
# Route 7: [IPv6Network('2001:db8:1:fc00::/56'), IPv6Network('fe80:0:fc00::2/128'), 'tun2']#
# Route 8: [IPv6Network('2001:db8:1:fd00::/56'), IPv6Network('fe80:0:fd00::2/128'), 'tun3']#
# Route 9: [IPv6Network('2001:db8:1:fe00::/56'), IPv6Network('fe80:0:fe00::2/128'), 'tun4']#
# Route 10: [IPv6Network('2001:db8:1:ff00::/56'), IPv6Network('fe80:0:ff00::2/128'), 'tun5']#
# Route 11: [IPv6Network('2000::/3'), IPv6Network('2001:db8:1::1/128'), 'eth3']#
# Route 12: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth1']            #
# Route 13: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth0']            #
# Route 14: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth2']            #
# Route 15: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth3']            #
# Route 16: [IPv6Network('fe80::/64'), IPv6Network('::/128'), 'sit1']          #
# Route 17: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun0']            #
# Route 18: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun1']            #
# Route 19: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun2']            #
# Route 20: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun3']            #
# Route 21: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun4']            #
# Route 22: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'tun5']            #
# Route 23: [IPv6Network('fe80:0:fa00::/64'), IPv6Network('::/0'), 'tun0']     #
# Route 24: [IPv6Network('fe80:0:fb00::/64'), IPv6Network('::/0'), 'tun1']     #
# Route 25: [IPv6Network('fe80:0:fc00::/64'), IPv6Network('::/0'), 'tun2']     #
# Route 26: [IPv6Network('fe80:0:fd00::/64'), IPv6Network('::/0'), 'tun3']     #
# Route 27: [IPv6Network('fe80:0:fe00::/64'), IPv6Network('::/0'), 'tun4']     #
# Route 28: [IPv6Network('fe80:0:ff00::/64'), IPv6Network('::/0'), 'tun5']     #
"""
        message = dev.show_routingtab()
        self.assertEquals(message, expect)

    def test_17_show_rules_adm6(self):
        """
        dv-17 ThisDevice: show rules adm6
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('adm6', cfg, hn6)
        try:
            err = dev.read_rules()
        except:
            err = -1
        expect ="""#  1: ['admin', 'obi-wan', 'tcp', '22', 'accept']                              #
#  2: ['admin', 'ns', 'tcp', '22', 'accept']                                   #
#  3: ['admin', 'r-ex', 'tcp', '22', 'accept']                                 #
#  4: ['admin', 'obi-wan', 'tcp', '22', 'accept']                              #
#  5: ['admin', 'www', 'tcp', '22', 'accept']                                  #
#  6: ['admin', 'ns', 'tcp', '22', 'accept']                                   #
#  7: ['admin', 'r-ex', 'tcp', '22', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
#  8: ['ns', 'admin', 'udp', '514', 'accept']                                  #
#  9: ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                          #
#  10: ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                         #
#  11: ['ns', 'any', 'udp', '53', 'accept', 'NOSTATE']                         #
#  12: ['any', 'ns', 'udp', '53', 'accept', 'NOIF', 'NOSTATE']                 #
#  13: ['any', 'ns', 'tcp', '25', 'accept']                                    #
#  14: ['ns', 'any', 'tcp', '25', 'accept']                                    #
#  15: ['any', 'www', 'tcp', '80', 'accept']                                   #
#  16: ['jhx6', 'www', 'tcp', '22', 'accept']                                  #
#  17: ['nag', 'any', 'icmpv6', 'echo-request', 'accept']                      #
#  18: ['any', 'nag', 'icmpv6', 'echo-reply', 'accept']                        #
#  19: ['any', 'nag', 'icmpv6', 'destination-unreachable', 'accept']           #
#  20: ['nag', 'any', 'tcp', '0:', 'accept']                                   #
#  21: ['many', 'www', 'tcp', '80', 'accept']                                  #
#  22: ['nag', 'www', 'tcp', '80', 'accept']                                   #
#  23: ['nag', 'www', 'tcp', '25', 'accept']                                   #
#  24: ['www', 'nag', 'tcp', '113', 'accept']                                  #
#                                                                              #
"""
        message = dev.show_rules()
        print "M:", message
        self.assertEquals(message, expect)

    def test_18_show_rules_www(self):
        """
        dv-18 ThisDevice: show rules www
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice('www', cfg, hn6)
        try:
            err = dev.read_rules()
        except:
            err = -1
        expect ="""#  1: ['admin', 'obi-wan', 'tcp', '22', 'accept']                              #
#  2: ['admin', 'ns', 'tcp', '22', 'accept']                                   #
#  3: ['admin', 'r-ex', 'tcp', '22', 'accept']                                 #
#  4: ['admin', 'obi-wan', 'tcp', '22', 'accept']                              #
#  5: ['admin', 'www', 'tcp', '22', 'accept']                                  #
#  6: ['admin', 'ns', 'tcp', '22', 'accept']                                   #
#  7: ['admin', 'r-ex', 'tcp', '22', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
#  8: ['ns', 'admin', 'udp', '514', 'accept']                                  #
#  9: ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                          #
#  10: ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                         #
#  11: ['ns', 'any', 'udp', '53', 'accept', 'NOSTATE']                         #
#  12: ['any', 'ns', 'udp', '53', 'accept', 'NOIF', 'NOSTATE']                 #
#  13: ['any', 'ns', 'tcp', '25', 'accept']                                    #
#  14: ['ns', 'any', 'tcp', '25', 'accept']                                    #
#  15: ['any', 'www', 'tcp', '80', 'accept']                                   #
#  16: ['jhx6', 'www', 'tcp', '22', 'accept']                                  #
#  17: ['nag', 'any', 'icmpv6', 'echo-request', 'accept']                      #
#  18: ['any', 'nag', 'icmpv6', 'echo-reply', 'accept']                        #
#  19: ['any', 'nag', 'icmpv6', 'destination-unreachable', 'accept']           #
#  20: ['nag', 'any', 'tcp', '0:', 'accept']                                   #
#  21: ['many', 'www', 'tcp', '80', 'accept']                                  #
#  22: ['nag', 'www', 'tcp', '80', 'accept']                                   #
#  23: ['nag', 'www', 'tcp', '25', 'accept']                                   #
#  24: ['www', 'nag', 'tcp', '113', 'accept']                                  #
#  25: ['any', 'ns', 'udp', '123', 'accept', 'NOSTATE']                        #
#  26: ['admin', 'ns', 'tcp', '514', 'accept', 'NOSTATE', 'FORCED']            #
#                                                                              #
"""
        message = dev.show_rules()
        print "M:", message
        self.assertEquals(message, expect)

    def test_19_address_is_own_adm6(self):
        """
        dv-19 ThisDevice: test own addresses adm6
        """
        dbg = 0
        device_name = 'adm6'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        # check first address
        expect = True
        addr = IPv6Network('2001:db8:0:beef::4711/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, expect)
        # check second address
        expect = True
        addr = IPv6Network('2001:db8:0:beef:a00:27ff:fe0d:1f8f/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, expect)
        # check loopback address
        expect = True
        addr = IPv6Network('::1/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, expect)
        # check nonlocal address
        expect = False
        addr = IPv6Network('2001:db8:0:beef::4713/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, expect)

    def test_20_address_is_own_ns(self):
        """
        dv-20 ThisDevice: test own addresses ns
        """
        dbg = 0
        device_name = 'ns'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        # check first address
        addr = IPv6Network('2001:db8:0:1::23/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check second address
        addr = IPv6Network('2001:db8:0:1:200:24ff:fecc:220d/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check loopback address
        addr = IPv6Network('::1/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check nonlocal address
        addr = IPv6Network('2001:db8:0:beef::4713/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, False)

    def test_21_address_is_own_www(self):
        """
        dv-21 ThisDevice: test own addresses www
        """
        dbg = 1
        device_name = 'www'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        # check first address
        addr = IPv6Network('2001:db8:1:2::2010/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check second address
        addr = IPv6Network('2001:db8:0:1:200:24ff:fec3:e051/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check loopback address
        addr = IPv6Network('::1/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, True)
        # check nonlocal address
        addr = IPv6Network('2001:db8:0:beef::4713/128')
        ifname = dev.address_is_own(addr)
        self.assertEquals(ifname, False)

    def test_22_look_for_r_ex(self):
        """
        dv-22 ThisDevice: look for route entries r-ex
        """
        #dbg = 0
        device_name = 'r-ex'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        #
        expect = ('eth3', 0)
        message = dev.look_for('2001:db8:1::1')
        print "M1:", message
        self.assertEquals(message, expect)
        #
        expect = ('eth1', 1)
        message = dev.look_for('2001:db8:1:1::1')
        print "M2:", message
        self.assertEquals(message, expect)
        #
        expect = ('sit1', 2)
        message = dev.look_for('2001:db8:1:2::1')
        print "M3:", message
        self.assertEquals(message, expect)
        #
        expect = ('eth3', 10)
        message = dev.look_for('2001:db8::1')
        print "M4:", message
        self.assertEquals(message, expect)
        #
        expect = ('eth3', 10)
        message = dev.look_for('2001:0db8:affe::1')
        print "M5:", message
        self.assertEquals(message, expect)
        #
        expect = ('eth3', 10)
        message = dev.look_for('2001:0db8:1:f901::1')
        print "M6:", message
        self.assertEquals(message, expect)
        #
        expect = ('tun0', 4)
        message = dev.look_for('2001:0db8:1:fa0e::1')
        print "M7:", message
        self.assertEquals(message, expect)
        #
        expect = ('tun4', 8)
        message = dev.look_for('2001:0db8:1:feed::1')
        print "M8:", message
        self.assertEquals(message, expect)

    def test_23_do_rules_adm6(self):
        """
        dv-23 ThisDevice: do rules adm6
        """
        dbg = 0
        device_name = 'adm6'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        #print "N:", device_name
        #print "O:", device_os
        #print "P", path
        #print "F:", fwd
        #print "A:", asy
        #print "R:", dev.rules
        #print dev.show_rules()
        f6 = IP6_Filter(dbg, path, device_name, device_os, fwd, asy, ifa)
        expect ="""# begin on rules expecting interface and routing for: Debian GNU/Linux, wheezy #
############################################################################ # #
# Rule 1: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 1: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 1:    outgoing traffic!                                                 #
# Rule 1: count: 1                                                             #
############################################################################ # #
# Rule 2: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 2: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 2:    outgoing traffic!                                                 #
# Rule 2: count: 2                                                             #
# Rule 2:    outgoing traffic!                                                 #
# Rule 2: count: 3                                                             #
############################################################################ # #
# Rule 3: has  5 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept']                                     #
# Rule 3: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 3:    outgoing traffic!                                                 #
# Rule 3: count: 4                                                             #
# Rule 3:    outgoing traffic!                                                 #
# Rule 3: count: 5                                                             #
############################################################################ # #
# Rule 4: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 4: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 4:    outgoing traffic!                                                 #
# Rule 4: count: 6                                                             #
############################################################################ # #
# Rule 5: has  5 items :                                                       #
# ['admin', 'www', 'tcp', '22', 'accept']                                      #
# Rule 5: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 5:    outgoing traffic!                                                 #
# Rule 5: count: 7                                                             #
############################################################################ # #
# Rule 6: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 6: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 6:    outgoing traffic!                                                 #
# Rule 6: count: 8                                                             #
# Rule 6:    outgoing traffic!                                                 #
# Rule 6: count: 9                                                             #
############################################################################ # #
# Rule 7: has  9 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
# Rule 7: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 7:    outgoing traffic!                                                 #
# Rule 7: count: 10                                                            #
# Rule 7:    outgoing traffic!                                                 #
# Rule 7: count: 11                                                            #
############################################################################ # #
# Rule 8: has  5 items :                                                       #
# ['ns', 'admin', 'udp', '514', 'accept']                                      #
# Rule 8: has  2 source(s) and 1 destination(s) in hostnet6                    #
# Rule 8:    incoming traffic!                                                 #
# Rule 8: count: 12                                                            #
# Rule 8:    incoming traffic!                                                 #
# Rule 8: count: 13                                                            #
############################################################################ # #
# Rule 9: has  6 items :                                                       #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 9: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 9: bypassing traffic, nothing done!                                     #
# Rule 9: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 10: has  6 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 10: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 10: bypassing traffic, nothing done!                                    #
# Rule 10: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 11: has  6 items :                                                      #
# ['ns', 'any', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 11: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 11: bypassing traffic, nothing done!                                    #
# Rule 11: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 12: has  7 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOIF', 'NOSTATE']                      #
# Rule 12: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 12: bypassing traffic, nothing done!                                    #
# Rule 12: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 13: has  5 items :                                                      #
# ['any', 'ns', 'tcp', '25', 'accept']                                         #
# Rule 13: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 13: bypassing traffic, nothing done!                                    #
# Rule 13: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 14: has  5 items :                                                      #
# ['ns', 'any', 'tcp', '25', 'accept']                                         #
# Rule 14: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 14: bypassing traffic, nothing done!                                    #
# Rule 14: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 15: has  5 items :                                                      #
# ['any', 'www', 'tcp', '80', 'accept']                                        #
# Rule 15: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 15: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 16: has  5 items :                                                      #
# ['jhx6', 'www', 'tcp', '22', 'accept']                                       #
# Rule 16: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 16: nothing done                                                        #
############################################################################ # #
# Rule 17: has  5 items :                                                      #
# ['nag', 'any', 'icmpv6', 'echo-request', 'accept']                           #
# Rule 17: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 17: nothing done                                                        #
############################################################################ # #
# Rule 18: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'echo-reply', 'accept']                             #
# Rule 18: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 18: nothing done                                                        #
############################################################################ # #
# Rule 19: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'destination-unreachable', 'accept']                #
# Rule 19: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 19: nothing done                                                        #
############################################################################ # #
# Rule 20: has  5 items :                                                      #
# ['nag', 'any', 'tcp', '0:', 'accept']                                        #
# Rule 20: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 20: nothing done                                                        #
############################################################################ # #
# Rule 21: has  5 items :                                                      #
# ['many', 'www', 'tcp', '80', 'accept']                                       #
# Rule 21: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 21: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 22: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '80', 'accept']                                        #
# Rule 22: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 22: nothing done                                                        #
############################################################################ # #
# Rule 23: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '25', 'accept']                                        #
# Rule 23: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 23: nothing done                                                        #
############################################################################ # #
# Rule 24: has  5 items :                                                      #
# ['www', 'nag', 'tcp', '113', 'accept']                                       #
# Rule 24: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 24: nothing done                                                        #
############################################################################ # #
# adm6: ready, 24 rules found                                                  #
"""
        message = dev.do_rules(f6)
        print "M:", message
        self.assertEquals(message, expect)

    def test_24_do_rules_www(self):
        """
        dv-24 ThisDevice: do rules www
        """
        dbg = 0
        device_name = 'www'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        #print "N:", device_name
        #print "O:", device_os
        #print "P", path
        #print "F:", fwd
        #print "A:", asy
        #print "R:", dev.rules
        #print dev.show_rules()
        f6 = IP6_Filter(dbg, path, device_name, device_os, fwd, asy, ifa)
        expect ="""# begin on rules expecting interface and routing for: Debian GNU/Linux, Lenny  #
############################################################################ # #
# Rule 1: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 1: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 1: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 2: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 2: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 2: bypassing traffic, nothing done!                                     #
# Rule 2: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 3: has  5 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept']                                     #
# Rule 3: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 3: bypassing traffic, nothing done!                                     #
# Rule 3: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 4: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 4: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 4: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 5: has  5 items :                                                       #
# ['admin', 'www', 'tcp', '22', 'accept']                                      #
# Rule 5: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 5:    incoming traffic!                                                 #
# Rule 5: count: 1                                                             #
############################################################################ # #
# Rule 6: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 6: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 6: bypassing traffic, nothing done!                                     #
# Rule 6: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 7: has  9 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
# Rule 7: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 7: bypassing traffic but FORCED                                         #
# Rule 7: count: 2                                                             #
# Rule 7: bypassing traffic but FORCED                                         #
# Rule 7: count: 3                                                             #
############################################################################ # #
# Rule 8: has  5 items :                                                       #
# ['ns', 'admin', 'udp', '514', 'accept']                                      #
# Rule 8: has  2 source(s) and 1 destination(s) in hostnet6                    #
# Rule 8: bypassing traffic, nothing done!                                     #
# Rule 8: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 9: has  6 items :                                                       #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 9: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 9: bypassing traffic, nothing done!                                     #
# Rule 9: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 10: has  6 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 10: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 10: bypassing traffic, nothing done!                                    #
# Rule 10: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 11: has  6 items :                                                      #
# ['ns', 'any', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 11: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 11: bypassing traffic, nothing done!                                    #
# Rule 11: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 12: has  7 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOIF', 'NOSTATE']                      #
# Rule 12: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 12: bypassing traffic, nothing done!                                    #
# Rule 12: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 13: has  5 items :                                                      #
# ['any', 'ns', 'tcp', '25', 'accept']                                         #
# Rule 13: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 13: bypassing traffic, nothing done!                                    #
# Rule 13: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 14: has  5 items :                                                      #
# ['ns', 'any', 'tcp', '25', 'accept']                                         #
# Rule 14: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 14: bypassing traffic, nothing done!                                    #
# Rule 14: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 15: has  5 items :                                                      #
# ['any', 'www', 'tcp', '80', 'accept']                                        #
# Rule 15: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 15:    incoming traffic!                                                #
# Rule 15: count: 4                                                            #
############################################################################ # #
# Rule 16: has  5 items :                                                      #
# ['jhx6', 'www', 'tcp', '22', 'accept']                                       #
# Rule 16: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 16: nothing done                                                        #
############################################################################ # #
# Rule 17: has  5 items :                                                      #
# ['nag', 'any', 'icmpv6', 'echo-request', 'accept']                           #
# Rule 17: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 17: nothing done                                                        #
############################################################################ # #
# Rule 18: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'echo-reply', 'accept']                             #
# Rule 18: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 18: nothing done                                                        #
############################################################################ # #
# Rule 19: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'destination-unreachable', 'accept']                #
# Rule 19: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 19: nothing done                                                        #
############################################################################ # #
# Rule 20: has  5 items :                                                      #
# ['nag', 'any', 'tcp', '0:', 'accept']                                        #
# Rule 20: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 20: nothing done                                                        #
############################################################################ # #
# Rule 21: has  5 items :                                                      #
# ['many', 'www', 'tcp', '80', 'accept']                                       #
# Rule 21: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 21:    incoming traffic!                                                #
# Rule 21: count: 5                                                            #
############################################################################ # #
# Rule 22: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '80', 'accept']                                        #
# Rule 22: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 22: nothing done                                                        #
############################################################################ # #
# Rule 23: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '25', 'accept']                                        #
# Rule 23: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 23: nothing done                                                        #
############################################################################ # #
# Rule 24: has  5 items :                                                      #
# ['www', 'nag', 'tcp', '113', 'accept']                                       #
# Rule 24: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 24: nothing done                                                        #
############################################################################ # #
# Rule 25: has  6 items :                                                      #
# ['any', 'ns', 'udp', '123', 'accept', 'NOSTATE']                             #
# Rule 25: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 25: bypassing traffic, nothing done!                                    #
# Rule 25: bypassing traffic, nothing done!                                    #
############################################################################ # #
# Rule 26: has  7 items :                                                      #
# ['admin', 'ns', 'tcp', '514', 'accept', 'NOSTATE', 'FORCED']                 #
# Rule 26: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 26: bypassing traffic but FORCED                                        #
# Rule 26: count: 6                                                            #
# Rule 26: bypassing traffic but FORCED                                        #
# Rule 26: count: 7                                                            #
############################################################################ # #
# www: ready, 26 rules found                                                   #
"""
        message = dev.do_rules(f6)
        print "M:", message
        self.assertEquals(message, expect)
        #self.assertFalse(True)

    def test_25_do_rules_r_ex(self):
        """
        dv-25 ThisDevice: do rules r-ex
        """
        dbg = 0
        device_name = 'r-ex'
        cfg = Adm6ConfigParser(".adm6.conf")
        path = str(cfg.get_device_home(device_name))
        device_os = cfg.get_os(device_name)
        hfile = cfg.get_adm6_home()
        hfile += '/etc/hostnet6'
        hn6 = HostNet6(hfile)
        dev = ThisDevice(device_name, cfg, hn6)
        fwd = dev.device_fwd
        asy = dev.device_asym
        ifa = dev.interfaces
        rul = dev.read_rules()
        #print "N:", device_name
        #print "O:", device_os
        #print "P", path
        #print "F:", fwd
        #print "A:", asy
        #print "R:", dev.rules
        #print dev.show_rules()
        f6 = IP6_Filter(dbg, path, device_name, device_os, fwd, asy, ifa)
        expect ="""# begin on rules expecting interface and routing for: Debian GNU/Linux, wheezy #
############################################################################ # #
# Rule 1: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 1: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 1: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 2: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 2: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 2: traversing traffic, action needed                                    #
# Rule 2: count: 1                                                             #
# Rule 2: traversing traffic, action needed                                    #
# Rule 2: count: 2                                                             #
############################################################################ # #
# Rule 3: has  5 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept']                                     #
# Rule 3: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 3: traversing traffic, action needed                                    #
# Rule 3: count: 3                                                             #
# Rule 3: traversing traffic, action needed                                    #
# Rule 3: count: 4                                                             #
############################################################################ # #
# Rule 4: has  5 items :                                                       #
# ['admin', 'obi-wan', 'tcp', '22', 'accept']                                  #
# Rule 4: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 4: bypassing traffic, nothing done!                                     #
############################################################################ # #
# Rule 5: has  5 items :                                                       #
# ['admin', 'www', 'tcp', '22', 'accept']                                      #
# Rule 5: has  1 source(s) and 1 destination(s) in hostnet6                    #
# Rule 5: traversing traffic, action needed                                    #
# Rule 5: count: 5                                                             #
############################################################################ # #
# Rule 6: has  5 items :                                                       #
# ['admin', 'ns', 'tcp', '22', 'accept']                                       #
# Rule 6: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 6: traversing traffic, action needed                                    #
# Rule 6: count: 6                                                             #
# Rule 6: traversing traffic, action needed                                    #
# Rule 6: count: 7                                                             #
############################################################################ # #
# Rule 7: has  9 items :                                                       #
# ['admin', 'r-ex', 'tcp', '22', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
# Rule 7: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 7: traversing traffic, action needed                                    #
# Rule 7: count: 8                                                             #
# Rule 7: traversing traffic, action needed                                    #
# Rule 7: count: 9                                                             #
############################################################################ # #
# Rule 8: has  5 items :                                                       #
# ['ns', 'admin', 'udp', '514', 'accept']                                      #
# Rule 8: has  2 source(s) and 1 destination(s) in hostnet6                    #
# Rule 8: traversing traffic, action needed                                    #
# Rule 8: count: 10                                                            #
# Rule 8: traversing traffic, action needed                                    #
# Rule 8: count: 11                                                            #
############################################################################ # #
# Rule 9: has  6 items :                                                       #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 9: has  1 source(s) and 2 destination(s) in hostnet6                    #
# Rule 9: traversing traffic, action needed                                    #
# Rule 9: count: 12                                                            #
# Rule 9: traversing traffic, action needed                                    #
# Rule 9: count: 13                                                            #
############################################################################ # #
# Rule 10: has  6 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 10: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 10: traversing traffic, action needed                                   #
# Rule 10: count: 14                                                           #
# Rule 10: traversing traffic, action needed                                   #
# Rule 10: count: 15                                                           #
############################################################################ # #
# Rule 11: has  6 items :                                                      #
# ['ns', 'any', 'udp', '53', 'accept', 'NOSTATE']                              #
# Rule 11: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 11: traversing traffic, action needed                                   #
# Rule 11: count: 16                                                           #
# Rule 11: traversing traffic, action needed                                   #
# Rule 11: count: 17                                                           #
############################################################################ # #
# Rule 12: has  7 items :                                                      #
# ['any', 'ns', 'udp', '53', 'accept', 'NOIF', 'NOSTATE']                      #
# Rule 12: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 12: traversing traffic, action needed                                   #
# Rule 12: count: 18                                                           #
# Rule 12: traversing traffic, action needed                                   #
# Rule 12: count: 19                                                           #
############################################################################ # #
# Rule 13: has  5 items :                                                      #
# ['any', 'ns', 'tcp', '25', 'accept']                                         #
# Rule 13: has  1 source(s) and 2 destination(s) in hostnet6                   #
# Rule 13: traversing traffic, action needed                                   #
# Rule 13: count: 20                                                           #
# Rule 13: traversing traffic, action needed                                   #
# Rule 13: count: 21                                                           #
############################################################################ # #
# Rule 14: has  5 items :                                                      #
# ['ns', 'any', 'tcp', '25', 'accept']                                         #
# Rule 14: has  2 source(s) and 1 destination(s) in hostnet6                   #
# Rule 14: traversing traffic, action needed                                   #
# Rule 14: count: 22                                                           #
# Rule 14: traversing traffic, action needed                                   #
# Rule 14: count: 23                                                           #
############################################################################ # #
# Rule 15: has  5 items :                                                      #
# ['any', 'www', 'tcp', '80', 'accept']                                        #
# Rule 15: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 15: traversing traffic, action needed                                   #
# Rule 15: count: 24                                                           #
############################################################################ # #
# Rule 16: has  5 items :                                                      #
# ['jhx6', 'www', 'tcp', '22', 'accept']                                       #
# Rule 16: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 16: nothing done                                                        #
############################################################################ # #
# Rule 17: has  5 items :                                                      #
# ['nag', 'any', 'icmpv6', 'echo-request', 'accept']                           #
# Rule 17: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 17: nothing done                                                        #
############################################################################ # #
# Rule 18: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'echo-reply', 'accept']                             #
# Rule 18: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 18: nothing done                                                        #
############################################################################ # #
# Rule 19: has  5 items :                                                      #
# ['any', 'nag', 'icmpv6', 'destination-unreachable', 'accept']                #
# Rule 19: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 19: nothing done                                                        #
############################################################################ # #
# Rule 20: has  5 items :                                                      #
# ['nag', 'any', 'tcp', '0:', 'accept']                                        #
# Rule 20: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 20: nothing done                                                        #
############################################################################ # #
# Rule 21: has  5 items :                                                      #
# ['many', 'www', 'tcp', '80', 'accept']                                       #
# Rule 21: has  1 source(s) and 1 destination(s) in hostnet6                   #
# Rule 21: traversing traffic, action needed                                   #
# Rule 21: count: 25                                                           #
############################################################################ # #
# Rule 22: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '80', 'accept']                                        #
# Rule 22: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 22: nothing done                                                        #
############################################################################ # #
# Rule 23: has  5 items :                                                      #
# ['nag', 'www', 'tcp', '25', 'accept']                                        #
# Rule 23: has  0 source(s) and 1 destination(s) in hostnet6                   #
# Rule 23: nothing done                                                        #
############################################################################ # #
# Rule 24: has  5 items :                                                      #
# ['www', 'nag', 'tcp', '113', 'accept']                                       #
# Rule 24: has  1 source(s) and 0 destination(s) in hostnet6                   #
# Rule 24: nothing done                                                        #
############################################################################ # #
# r-ex: ready, 24 rules found                                                  #
"""
        message = dev.do_rules(f6)
        print "M:", message
        self.assertEquals(message, expect)
        #self.assertFalse(True)

    def test_26_do_all_devices(self):
        """
        dv-26 ThisDevice: do all devices
        """
        all_devices = DevTest()
