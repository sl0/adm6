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
        cnt = 0
        try:
            err = dev.read_rules()
        except:
            err = -1
        self.assertEquals(err, 24)
