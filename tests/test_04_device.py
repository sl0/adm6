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

    def test_d_01_adm6_is_instance(self):
        """
        dv-01 ThisDevice: adm6 is instance
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        dev = ThisDevice('adm6', cfg, hn6)
        self.assertIsInstance(dev, ThisDevice)

    def test_d_02_unkn_is_not_instance(self):
        """
        dv-01 ThisDevice: unknown is not instance
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        try:
            dev = ThisDevice('unknown', cfg, hn6)
            value = True
        except:
            value = False
        self.assertFalse(value)

    def test_d_03_adm6_read_interfaces(self):
        """
        dv-03 ThisDevice: linux read_interface_file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('')
        except:
            pass
        self.assertEquals(err, False)

    def test_d_04_adm6_read_interfaces_fail(self):
        """
        dv-04 ThisDevice: linux read_interface_file fails
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('not_exisiting_file')
        except:
            pass
        self.assertEquals(err, True)

    def test_d_05_obi_read_interfaces(self):
        """
        dv-05 ThisDevice: OpenBSD read_interface_file
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        dev = ThisDevice('obi-wan', cfg, hn6)
        err = False
        try:
            dev.interfaces = []
            err = dev.read_interface_file('')
        except:
            pass
        self.assertEquals(err, False)

    def test_d_06_linux_read_routingtab(self):
        """
        dv-06 ThisDevice: linux read_routing_tab
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
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

    def test_d_07_linux_read_routingtab_fail(self):
        """
        dv-07 ThisDevice: linux read_routing_tab fails
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
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

    def ttest_d_07_linux_read_routingtab(self):
        """
        dv-07 ThisDevice: linux read_routing_tab
        """
        cfg = Adm6ConfigParser(".adm6.conf")
        hn6 = HostNet6()
        dev = ThisDevice('adm6', cfg, hn6)
        err = False
        try:
            dev.routingtab = []
            err = dev.read_routingtab_file('')
        except:
            pass
        print "O:", dev.os
        print "R:", dev.routingtab
        self.assertEquals(err, False)
        self.assertTrue(False)
