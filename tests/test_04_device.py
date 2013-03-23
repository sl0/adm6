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
from adm6.device import ThisDevice
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
        self.assertEquals(err, 23)

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
        self.assertEquals(err, 39)
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
        self.assertEquals(err, 24)

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
#  eth1:   2010:db8:f002:1::1/64                                               #
#  eth1:   2010:db8:f002:1::53/64                                              #
#  eth2:   fe80::200:24ff:fec6:fc84/64                                         #
#  eth3:   fe80::200:24ff:fec6:fc85/64                                         #
#  eth3:   2010:db8:f002::2/64                                                 #
#  lo:   ::1/128                                                               #
#  sit1:   2010:db8:f002:3::1/64                                               #
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
#  sis0::   2001:db8:23:1::2/128                                               #
#  sis0::   fe80::200:24ff:feca:1d9c/128                                       #
#  sis1::   fe80::200:24ff:feca:1d9d/128                                       #
#  gif0::   2001:db8:23:5afe::2/128                                            #
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
# Route 1: [IPv6Network('2010:db8:f002:beef::/64'), IPv6Network('::/0'), 'eth0']#
# Route 2: [IPv6Network('fe80::/64'), IPv6Network('::/0'), 'eth0']             #
# Route 3: [IPv6Network('::/0'), IPv6Network('fe80::a00:27ff:fe59:d69e/128'), 'eth0']#
"""
        message = dev.show_routingtab()
        #print message
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
        expect ="""# Routingtable:                                                                #
#          [ target,                next_hop,          interface ]             #
# Route 1: [IPv6Network('2001:db8:23::/64'), IPv6Network('::/0'), 'eth3']      #
# Route 2: [IPv6Network('2001:db8:23:1::/64'), IPv6Network('::/0'), 'eth1']    #
# Route 3: [IPv6Network('2001:db8:23:2::/64'), IPv6Network('::/0'), 'sit1']    #
# Route 4: [IPv6Network('2001:db8:23:3::/64'), IPv6Network('::/128'), 'sit1']  #
# Route 5: [IPv6Network('2001:db8:23:fa00::/56'), IPv6Network('fe80:0:fa00::2/128'), 'tun0']#
# Route 6: [IPv6Network('2001:db8:23:fb00::/56'), IPv6Network('fe80:0:fb00::2/128'), 'tun1']#
# Route 7: [IPv6Network('2001:db8:23:fc00::/56'), IPv6Network('fe80:0:fc00::2/128'), 'tun2']#
# Route 8: [IPv6Network('2001:db8:23:fd00::/56'), IPv6Network('fe80:0:fd00::2/128'), 'tun3']#
# Route 9: [IPv6Network('2001:db8:23:fe00::/56'), IPv6Network('fe80:0:fe00::2/128'), 'tun4']#
# Route 10: [IPv6Network('2001:db8:23:ff00::/56'), IPv6Network('fe80:0:ff00::2/128'), 'tun5']#
# Route 11: [IPv6Network('2000::/3'), IPv6Network('2001:db8:23::1/128'), 'eth3']#
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
        expect ="""#  1: ['admin', 'obi-wan', '22', 'tcp', 'accept']                              #
#  2: ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                          #
#  3: ['admin', 'ns', '22', 'tcp', 'accept']                                   #
#  4: ['admin', 'r-ex', '22', 'tcp', 'accept']                                 #
#  5: ['admin', 'obi-wan', '22', 'tcp', 'accept']                              #
#  6: ['admin', 'r-ex', '22', 'tcp', 'accept']                                 #
#  7: ['admin', 'ns', '22', 'tcp', 'accept']                                   #
#  8: ['admin', 'r-ex', '22', 'tcp', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
#  9: ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                          #
#  10: ['ns', 'any', '53', 'udp', 'accept', 'NOSTATE']                         #
#  11: ['any', 'ns', '53', 'udp', 'accept', 'NOIF', 'NOSTATE']                 #
#  12: ['any', 'ns', '25', 'tcp', 'accept']                                    #
#  13: ['ns', 'any', '25', 'tcp', 'accept']                                    #
#  14: ['any', 'www', '80', 'tcp', 'accept']                                   #
#  15: ['jhx6', 'www', '22', 'tcp', 'accept']                                  #
#  16: ['nag', 'any', 'echo-request', 'icmpv6', 'accept']                      #
#  17: ['any', 'nag', 'echo-reply', 'icmpv6', 'accept']                        #
#  18: ['any', 'nag', 'destination-unreachable', 'icmpv6', 'accept']           #
#  19: ['nag', 'any', '0:', 'tcp', 'accept']                                   #
#  20: ['many', 'www', '80', 'tcp', 'accept']                                  #
#  21: ['nag', 'www', '80', 'tcp', 'accept']                                   #
#  22: ['nag', 'www', '25', 'tcp', 'accept']                                   #
#  23: ['www', 'nag', '113', 'tcp', 'accept']                                  #
#                                                                              #
"""
        message = dev.show_rules()
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
        expect ="""#  1: ['admin', 'obi-wan', '22', 'tcp', 'accept']                              #
#  2: ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                          #
#  3: ['admin', 'ns', '22', 'tcp', 'accept']                                   #
#  4: ['admin', 'r-ex', '22', 'tcp', 'accept']                                 #
#  5: ['admin', 'obi-wan', '22', 'tcp', 'accept']                              #
#  6: ['admin', 'r-ex', '22', 'tcp', 'accept']                                 #
#  7: ['admin', 'ns', '22', 'tcp', 'accept']                                   #
#  8: ['admin', 'r-ex', '22', 'tcp', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
#  9: ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                          #
#  10: ['ns', 'any', '53', 'udp', 'accept', 'NOSTATE']                         #
#  11: ['any', 'ns', '53', 'udp', 'accept', 'NOIF', 'NOSTATE']                 #
#  12: ['any', 'ns', '25', 'tcp', 'accept']                                    #
#  13: ['ns', 'any', '25', 'tcp', 'accept']                                    #
#  14: ['any', 'www', '80', 'tcp', 'accept']                                   #
#  15: ['jhx6', 'www', '22', 'tcp', 'accept']                                  #
#  16: ['nag', 'any', 'echo-request', 'icmpv6', 'accept']                      #
#  17: ['any', 'nag', 'echo-reply', 'icmpv6', 'accept']                        #
#  18: ['any', 'nag', 'destination-unreachable', 'icmpv6', 'accept']           #
#  19: ['nag', 'any', '0:', 'tcp', 'accept']                                   #
#  20: ['many', 'www', '80', 'tcp', 'accept']                                  #
#  21: ['nag', 'www', '80', 'tcp', 'accept']                                   #
#  22: ['nag', 'www', '25', 'tcp', 'accept']                                   #
#  23: ['www', 'nag', '113', 'tcp', 'accept']                                  #
#  24: ['any', 'ns', '123', 'udp', 'accept', 'NOSTATE']                        #
#                                                                              #
"""
        message = dev.show_rules()
        self.assertEquals(message, expect)
        #print message
        #self.assertFalse(True)


    def test_19_do_rules_adm6(self):
        """
        dv-19 ThisDevice: do rules adm6
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
# ['admin', 'obi-wan', '22', 'tcp', 'accept']                                  #
############################################################################ # #
# Rule 2: has  6 items :                                                       #
# ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                              #
############################################################################ # #
# Rule 3: has  5 items :                                                       #
# ['admin', 'ns', '22', 'tcp', 'accept']                                       #
############################################################################ # #
# Rule 4: has  5 items :                                                       #
# ['admin', 'r-ex', '22', 'tcp', 'accept']                                     #
############################################################################ # #
# Rule 5: has  5 items :                                                       #
# ['admin', 'obi-wan', '22', 'tcp', 'accept']                                  #
############################################################################ # #
# Rule 6: has  5 items :                                                       #
# ['admin', 'r-ex', '22', 'tcp', 'accept']                                     #
############################################################################ # #
# Rule 7: has  5 items :                                                       #
# ['admin', 'ns', '22', 'tcp', 'accept']                                       #
############################################################################ # #
# Rule 8: has  9 items :                                                       #
# ['admin', 'r-ex', '22', 'tcp', 'accept', 'FORCED', 'INSEC', 'NOIF', 'NOSTATE'] #
############################################################################ # #
# Rule 9: has  6 items :                                                       #
# ['any', 'ns', '53', 'udp', 'accept', 'NOSTATE']                              #
############################################################################ # #
# Rule 10: has  6 items :                                                      #
# ['ns', 'any', '53', 'udp', 'accept', 'NOSTATE']                              #
############################################################################ # #
# Rule 11: has  7 items :                                                      #
# ['any', 'ns', '53', 'udp', 'accept', 'NOIF', 'NOSTATE']                      #
############################################################################ # #
# Rule 12: has  5 items :                                                      #
# ['any', 'ns', '25', 'tcp', 'accept']                                         #
############################################################################ # #
# Rule 13: has  5 items :                                                      #
# ['ns', 'any', '25', 'tcp', 'accept']                                         #
############################################################################ # #
# Rule 14: has  5 items :                                                      #
# ['any', 'www', '80', 'tcp', 'accept']                                        #
############################################################################ # #
# Rule 15: has  5 items :                                                      #
# ['jhx6', 'www', '22', 'tcp', 'accept']                                       #
############################################################################ # #
# Rule 16: has  5 items :                                                      #
# ['nag', 'any', 'echo-request', 'icmpv6', 'accept']                           #
############################################################################ # #
# Rule 17: has  5 items :                                                      #
# ['any', 'nag', 'echo-reply', 'icmpv6', 'accept']                             #
############################################################################ # #
# Rule 18: has  5 items :                                                      #
# ['any', 'nag', 'destination-unreachable', 'icmpv6', 'accept']                #
############################################################################ # #
# Rule 19: has  5 items :                                                      #
# ['nag', 'any', '0:', 'tcp', 'accept']                                        #
############################################################################ # #
# Rule 20: has  5 items :                                                      #
# ['many', 'www', '80', 'tcp', 'accept']                                       #
############################################################################ # #
# Rule 21: has  5 items :                                                      #
# ['nag', 'www', '80', 'tcp', 'accept']                                        #
############################################################################ # #
# Rule 22: has  5 items :                                                      #
# ['nag', 'www', '25', 'tcp', 'accept']                                        #
############################################################################ # #
# Rule 23: has  5 items :                                                      #
# ['www', 'nag', '113', 'tcp', 'accept']                                       #
############################################################################ # #
# adm6: ready, 23 rules found                                                  #
"""
        message = dev.do_rules(f6)
        self.assertEquals(message, expect)
        #print "M:", message
        #self.assertFalse(True)

