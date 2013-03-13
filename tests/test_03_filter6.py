#!/usr/bin/env python
#encoding:utf8
#
# file:    filter6_tests.py
# author: sl0
# date:   2013-03-06
#

import unittest
from adm6.filter6 import IP6_Filter, Ip6_Filter_Rule
from sys import stdout
from os.path import expanduser as homedir
from ipaddr import IPv6Network

rule = {}

class Ip6_Filter_Rule_tests(unittest.TestCase):
    """
    some tests for class Ip6_Filter_Rule
    """
    
    def test_01_create_Filter_Rule(self):
        """
        fr-01 create Filter_Rule object
        """
        my_err = False
        try:
            f = Ip6_Filter_Rule(rule)
        except:
            my_err = True
        self.assertFalse(my_err)
        self.assertFalse(f['i_am_d'])
        self.assertFalse(f['i_am_s'])
        self.assertFalse(f['travers'])
        self.assertFalse(f['insec'])
        self.assertFalse(f['noif'])
        self.assertFalse(f['nonew'])
        self.assertFalse(f['nostate'])
        self.assertEqual(f['sport'], u'1024:')
        self.assertEqual(['Rule-Nr', 'Pair-Nr', 'RuleText'], f.CommentList)
        self.assertEqual(['Output', 'debuglevel'], f.NeverDisplay)
        displaylist = ['Rule-Nr', 'Pair-Nr', 'System-Name', 'System-Forward', 
            'OS', 'Asymmetric', 'RuleText', 'Source', 'Destin', 'Protocol', 
            'sport', 'dport', 'Action', 'nonew', 'noif', 'nostate', 'insec',
            'i_am_s', 'i_am_d', 'travers', 'source-if', 'source-rn', 
            'src-linklocal', 'src-multicast', 'destin-if', 'destin-rn', 
            'dst-linklocal', 'dst-multicast', ]
        self.assertEqual(displaylist, f.DisplayList)
        #f['debuglevel'] = True
        #print f

    def test_02_produce_for_invalid_os_name(self):
        """
        fr-02 produce for invalid os name
        """
        my_err = False
        try:
            fr = Ip6_Filter_Rule(rule)
        except:
            my_err = True
        fr['OS'] = 'Invalid os name'
        self.assertRaises(ValueError, fr.produce ,stdout)


    def test_03_produce_for_linux_as_traversed(self):
        """
        fr-03 produce for linux as traversed host
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_04_produce_for_openbsd(self):
        """
        fr-04 produce for OpenBSD
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'OpenBSD'
        except:
            my_err = True
        fr.produce(ofile)
        expect = "# OpenBSD implementation _not_ ready!"
        #expect = """# n o t   y e t   i m p l e m e n t e d !"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_05_produce_for_bsd(self):
        """
        fr-05 produce for BSD
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'BSD'
        except:
            my_err = True
        fr.produce(ofile)
        expect = "# IPF is n o t  y e t   i m p l e m e n t e d !"
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_06_produce_for_opensolaris(self):
        """
        fr-06 produce for OpenSolaris
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'OpenSolaris'
        except:
            my_err = True
        fr.produce(ofile)
        expect = "# IPF is n o t  y e t   i m p l e m e n t e d !"
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_07_produce_for_wxp(self):
        """
        fr-07 produce for WXP
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Win-XP-SP3'
        except:
            my_err = True
        fr.produce(ofile)
        expect = "# System should not forward until redesigned"
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_08_repr_with_debuglevel(self):
        """
        fr-08 repr with debuglevel
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        fr['debuglevel'] = True
        value = str(fr)
        print "V:", value
        expect = """# Rule-Nr        : 1                                                           #
# Pair-Nr        : 1                                                           #
# System-Forward : True                                                        #
# OS             : Debian                                                      #
# Source         : 2001:db8:1::1                                               #
# Destin         : 2001:db8:2::1                                               #
# Protocol       : tcp                                                         #
# sport          : 1024:                                                       #
# dport          : 22                                                          #
# Action         : accept                                                      #
# nonew          : False                                                       #
# noif           : False                                                       #
# nostate        : False                                                       #
# insec          : False                                                       #
# i_am_s         : False                                                       #
# i_am_d         : False                                                       #
# travers        : True                                                        #
# source-if      : eth0                                                        #
# src-linklocal  : False                                                       #
# destin-if      : eth0                                                        #
# dst-linklocal  : False                                                       #
"""
        self.assertEquals(expect, value)

    def test_09_repr_without_debuglevel(self):
        """
        fr-09 repr without debuglevel
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        fr['debuglevel'] = False
        fr['Abrakadabra'] = True
        value = str(fr)
        print "V:", value
        expect = """# Rule-Nr        : 1                                                           #
# Pair-Nr        : 1                                                           #
# Abrakadabra    : True                                                        #
"""
        self.assertEquals(expect, value)

    def test_10_produce_for_linux_as_source(self):
        """
        fr-10 produce for linux as source host
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = True
            fr['travers'] = False
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth1"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   output__new  -o eth1 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   input___new  -i eth1 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_11_produce_for_linux_as_source_icmpv6(self):
        """
        fr-11 produce for linux as source host icmpv6
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "icmpv6"
            fr['dport'] = "echo-request"
            fr['System-Forward'] = True
            fr['i_am_s'] = True
            fr['travers'] = False
            fr['noif'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth1"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   output__new  -s 2001:db8:1::1 -d 2001:db8:2::1 -p icmpv6 --icmpv6-type echo-request -j ACCEPT -m comment --comment "1,1"\necho -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_12_produce_for_linux_as_source_nonew(self):
        """
        fr-12 produce for linux as source host nonew
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "21"
            fr['nonew'] = True
            fr['System-Forward'] = True
            fr['i_am_s'] = True
            fr['travers'] = False
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth1"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   output__new  -o eth1 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 21 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   input___new  -i eth1 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 21 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        print fr.msg
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_13_produce_for_linux_as_dest(self):
        """
        fr-13 produce for linux as dest host
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = True
            fr['travers'] = False
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   input___new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   output__new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_14_produce_for_linux_as_traversed(self):
        """
        fr-14 produce for linux as traversed host
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_15_produce_for_linux_as_traversed(self):
        """
        fr-15 produce for linux reject rule
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "reject"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j REJECT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j REJECT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_16_produce_for_linux_as_traversed(self):
        """
        fr-16 produce for linux drop rule
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "drop"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 1024: --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j DROP -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 1024: --sport 22 -m state --state     ESTABLISHED,RELATED -j DROP -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)


    def test_17_produce_for_linux_as_traversed(self):
        """
        fr-17 produce for linux accept rule insec
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "tcp"
            fr['dport'] = "22"
            fr['insec'] = True
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -p tcp --sport 0:  --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1 -s 2001:db8:2::1 -p tcp --dport 0:  --sport 22 -m state --state     ESTABLISHED,RELATED -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_18_produce_for_linux_ip6(self):
        """
        fr-18 produce for linux ip6 accept rule
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "ip6"
            fr['dport'] = "all"
            fr['System-Forward'] = True
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1 -d 2001:db8:2::1 -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_19_produce_for_linux_ip6_forced(self):
        """
        fr-19 produce for linux ip6 forced accept rule
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "ip6"
            fr['dport'] = "all"
            fr['System-Forward'] = True
            fr['forced'] = True
            fr['i_am_s'] = True
            fr['i_am_d'] = True
            fr['travers'] = True
            fr['noif'] = True
            fr['nostate'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """/sbin/ip6tables -A   output__new  -s 2001:db8:1::1 -d 2001:db8:2::1 -j ACCEPT -m comment --comment "1,1"
echo -n ".";/sbin/ip6tables -A   input___new  -s 2001:db8:1::1 -d 2001:db8:2::1 -j ACCEPT -m comment --comment "1,1"
echo -n ".";/sbin/ip6tables -A   forward_new  -s 2001:db8:1::1 -d 2001:db8:2::1 -j ACCEPT -m comment --comment "1,1"
echo -n ".";"""
        self.maxDiff = None
        self.assertEquals(expect, fr.msg)

    def test_20_produce_for_linux_forward_forbidden(self):
        """
        fr-20 produce for linux ip6 forward forbidden
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "2001:db8:1::1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "ip6"
            fr['dport'] = "all"
            fr['System-Forward'] = False
            fr['forced'] = False
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['noif'] = True
            fr['nostate'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = False
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = """# System-Forward: False ==> no rule generated"""
        self.maxDiff = None
        #print "M:", fr.msg
        self.assertEquals(expect, fr.msg)

    def test_21_produce_for_linux_forward_linklocal(self):
        """
        fr-21 produce for linux forward linklocal
        """
        my_err = False
        try:
            ofile = open("/dev/null", 'w')
            fr = Ip6_Filter_Rule(rule)
            fr['debuglevel'] = False
            fr['Rule-Nr'] = 1
            fr['Pair-Nr'] = 1
            fr['Protocol'] = 1
            fr['Action'] = "accept"
            fr['Source'] = "fe80::e:db8:1:1"
            fr['Destin'] = "2001:db8:2::1"
            fr['Protocol'] = "ip6"
            fr['dport'] = "all"
            fr['System-Forward'] = True
            fr['forced'] = False
            fr['i_am_s'] = False
            fr['i_am_d'] = False
            fr['travers'] = True
            fr['source-if'] = "eth0"
            fr['destin-if'] = "eth0"
            fr['src-linklocal'] = True
            fr['dst-linklocal'] = False
            fr['OS'] = 'Debian'
        except:
            my_err = True
        fr.produce(ofile)
        expect = "# link-local ==> no forward"
        self.maxDiff = None
        #print "M:", fr.msg
        self.assertEquals(expect, fr.msg)

    def test_22_produce_for_openbsd_icmpv6(self):
            """
            fr-22 produce for OpenBSD icmpv6
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Protocol'] = 1
                fr['Action'] = "accept"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "icmpv6"
                fr['dport'] = "echo-request"
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce(ofile)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_23_produce_for_openbsd_tcp_nonew(self):
            """
            fr-23 produce for OpenBSD tcp nonew
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "reject"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "4711"
                fr['nonew'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce(ofile)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_24_produce_for_openbsd_tcp_drop(self):
            """
            fr-24 produce for OpenBSD tcp drop
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "4711"
                fr['insec'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce(ofile)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_25_produce_for_openbsd_ip6(self):
            """
            fr-25 produce for OpenBSD ip6
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "ip6"
                fr['dport'] = "all"
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce(ofile)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)
    
    def test_26_produce_for_openbsd_commented(self):
            """
            fr-26 produce for OpenBSD commented
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "ip6"
                fr['dport'] = "all"
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce_OpenBSD(ofile, True)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_27_produce_for_openbsd_commented(self):
            """
            fr-27 produce for OpenBSD forward forbidden
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "0:"
                fr['System-Forward'] = False
                fr['i_am_s'] = False
                fr['i_am_d'] = False
                fr['travers'] = True
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce_OpenBSD(ofile, False)
            expect = "# System does not forward by configuration"
            #expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_28_produce_for_openbsd_noif(self):
            """
            fr-28 produce for OpenBSD forward noif
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "0:"
                fr['noif'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce_OpenBSD(ofile, False)
            expect = "# OpenBSD implementation _not_ ready!"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_29_produce_for_openbsd_dst_linklocal(self):
            """
            fr-29 produce for OpenBSD forward dst-link-local
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "0:"
                fr['noif'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = True
                fr['OS'] = 'OpenBSD'
            except:
                my_err = True
            fr.produce_OpenBSD(ofile, False)
            expect = "# dst-link-local ==> no filter rule generated"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_30_produce_for_wxp_tcp(self):
            """
            fr-30 produce for wxp tcp
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "0:"
                fr['noif'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, False)
            expect = "# WXP-SP3  n o t   y e t  r e a d y !"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_31_produce_for_wxp_icmpv6(self):
            """
            fr-31 produce for wxp icmpv6
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "icmpv6"
                fr['dport'] = "echo-request"
                fr['noif'] = False
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, False)
            expect = "# WXP-SP3  n o t   y e t  r e a d y !"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_32_produce_for_wxp_nonew(self):
            """
            fr-32 produce for wxp nonew
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "deny"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "25"
                fr['nonew'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, False)
            expect = "# WXP-SP3  n o t   y e t  r e a d y !"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)
    
    def test_33_produce_for_wxp_reject_insec(self):
            """
            fr-33 produce for wxp reject insec
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "reject"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "tcp"
                fr['dport'] = "25"
                fr['insec'] = True
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, False)
            expect = "# WXP-SP3  n o t   y e t  r e a d y !"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_34_produce_for_wxp_ip6_commented(self):
            """
            fr-34 produce for wxp ip6 commented
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "accept"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "ip6"
                fr['dport'] = "all"
                fr['insec'] = False
                fr['System-Forward'] = True
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, True)
            expect = "# WXP-SP3  n o t   y e t  r e a d y !"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_34_produce_for_wxp_ip6_commented(self):
            """
            fr-34 produce for wxp ip6 commented
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "accept"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "ip6"
                fr['dport'] = "all"
                fr['insec'] = False
                fr['System-Forward'] = False
                fr['i_am_s'] = False
                fr['i_am_d'] = False
                fr['travers'] = True
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = False
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, True)
            expect = "# System should not forward by configuration"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)

    def test_35_produce_for_wxp_dst_linklocal(self):
            """
            fr-35 produce for wxp dst-linklocal
            """
            my_err = False
            try:
                ofile = open("/dev/null", 'w')
                fr = Ip6_Filter_Rule(rule)
                fr['debuglevel'] = False
                fr['Rule-Nr'] = 11
                fr['Pair-Nr'] = 1
                fr['Action'] = "accept"
                fr['Source'] = "2001:db8:1::1"
                fr['Destin'] = "2001:db8:2::1"
                fr['Protocol'] = "ip6"
                fr['dport'] = "all"
                fr['insec'] = False
                fr['System-Forward'] = False
                fr['i_am_s'] = True
                fr['i_am_d'] = False
                fr['travers'] = False
                fr['source-if'] = "sis0"
                fr['destin-if'] = "sis0"
                fr['src-linklocal'] = False
                fr['dst-linklocal'] = True
                fr['OS'] = 'winxp3'
            except:
                my_err = True
            fr.produce_wxpsp3(ofile, True)
            expect = "# dst-linklocal ==> no rule generated"
            self.maxDiff = None
            self.assertEquals(expect, fr.msg)



class Ip6_Filter_tests(unittest.TestCase):
    '''some tests for class Ip6_Filter_Rule'''

    def test_01_IP6_Filter_create_Debian(self):
        """
        ft-01 IP6 Filter create an object for Debian
        """
        #init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "Debian GNU/Linux wheezy"
        fwd = False
        asym = False
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        self.assertEquals(fi.os, 'Debian')

    def test_02_IP6_Filter_create_OpenBSD(self):
        """
        ft-02 IP6 Filter create an object for OpenBSD
        """
        #init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "OpenBSD 4.5"
        fwd = False
        asym = False
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        self.assertEquals(fi.os, 'OpenBSD')

    def test_03_IP6_Filter_create_OpenSolaris(self):
        """
        ft-03 IP6 Filter create an object for OpenSolaris
        """
        #init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "OpenSolaris unknown version"
        fwd = False
        asym = False
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        self.assertEquals(fi.os, 'OpenSolaris')

    def test_04_IP6_Filter_create_win_xp_sp3(self):
        """
        ft-04 IP6 Filter create an object for WXP SP3
        """
        #init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "Win-XP-SP3"
        fwd = False
        asym = False
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        self.assertEquals(fi.os, 'Win-XP-SP3')

    def test_05_IP6_Filter_create_unknown_os(self):
        """
        ft-05 IP6 Filter create an object for unknown os
        """
        #init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "Unknown OS"
        fwd = False
        asym = False
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        self.assertEquals(fi.os, 'Unknown operating system for host: ns')

    def test_06_IP6_Filter_append_first_rule(self):
        """
        ft-06 IP6 Filter append first rule
        """
        debug = False
        name = "ns"
        path = "desc/ns/"
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        fi.append(rule_one)
        expect = [rule_one, ]
        self.assertEqual(expect, fi.rules)

    def test_07_IP6_Filter_mangle_start_exist(self):
        """
        ft-07 IP6 Filter mangle-start exisiting file
        """
        debug = False
        name = "www"
        #path = "/home/sl0/adm6/desc/www"
        mach_dir = "~/adm6/desc/www"
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        ofile = open("/dev/null", 'w')
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        fi.msg = ""
        self.assertIsInstance(fi, IP6_Filter)
        file_to_read = "mangle-startup"
        fi.mangle_file(ofile, file_to_read)
        expect = "# start reading mangle-file: %s/" % (path)
        expect += file_to_read
        expect += "# mangle-startup file for testing \n"
        value = fi.msg
        self.assertEqual(expect, value)

    def test_08_IP6_Filter_mangle_end_exist(self):
        """
        ft-08 IP6 Filter mangle-end exisiting file
        """
        debug = False
        name = "ns"
        path = "/home/sl0/adm6/desc/ns"
        mach_dir = "~/adm6/desc/adm6"
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        ofile = open("/dev/null", 'w')
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        file_to_read = "mangle-endup"
        fi.msg = ""
        fi.mangle_file(ofile, file_to_read)
        expect = "# failed reading mangle-file: %s/" % (path)
        #expect = "# start reading mangle-file: %s/" % (path)
        expect += file_to_read
        expect += ", but OK"
        value = fi.msg
        self.assertEqual(expect, value)
    
    def test_09_IP6_Filter_mangle_end_non_exist(self):
        """
        ft-09 IP6 Filter mangle-end non exisiting file
        """
        debug = False
        name = "adm6"
        #path = "/home/sl0/adm6/desc/adm6"
        mach_dir = "~/adm6/desc/adm6"
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        ofile = open("/dev/null", 'w')
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        file_to_read = "mangle-endup"
        fi.msg = ""
        fi.mangle_file(ofile, file_to_read)
        expect = "# failed reading mangle-file: %s/" % (path)
        expect += file_to_read
        expect = "# failed reading mangle-file: /home/sl0/adm6/desc/adm6/mangle-endup, but OK"
        value = fi.msg
        self.assertEqual(expect, value)

    def test_10_IP6_Filter_final_this_rule(self):
        """
        ft-10 IP6 Filter final this rule
        """
        debug = True
        name = "ns"
        path = "/home/sl0/adm6/desc/ns"
        mach_dir = "~/adm6/desc/ns"
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        ofn = "/dev/null"
        ofile = open(ofn, 'w')
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        rule = []
        rule.append("RuleText")                                 # RuleText
        rule.append(True)                                       # System-Fwd
        rule.append(2)                                          # Rule-Nr.
        rule.append(3)                                          # Pair-Nr.
        rule.append(True)
        rule.append(False)
        rule.append(IPv6Network('fe80::1'))                     # source
        rule.append(IPv6Network('ff80::4711'))                  # destin
        rule.append('eth0')                        # source-if
        rule.append(3)                             # source-rn
        rule.append('eth0')                        # destin-if
        rule.append(3)                             # destin-rn
        rule.append('udp')                         # protocol
        rule.append('4711:4713')                   # dport
        rule.append('accept')                      # action
        rule.append('NOIF NOSTATE')                # append     options at last
        fi.rules.append(rule)
        fi.final_this_rule(rule, ofile)
        value = fi.msg
        expect = """# ---------------------------------------------------------------------------- #
# Rule-Nr        : 2                                                           #
# Pair-Nr        : 3                                                           #
# System-Name    : ns                                                          #
# System-Forward : True                                                        #
# OS             : Debian                                                      #
# Asymmetric     : False                                                       #
# RuleText       : RuleText                                                    #
# Source         : fe80::1/128                                                 #
# Destin         : ff80::4711/128                                              #
# Protocol       : udp                                                         #
# sport          : 1024:                                                       #
# dport          : 4711:4713                                                   #
# Action         : accept                                                      #
# nonew          : False                                                       #
# noif           : True                                                        #
# nostate        : True                                                        #
# insec          : False                                                       #
# i_am_s         : True                                                        #
# i_am_d         : False                                                       #
# travers        : False                                                       #
# source-if      : eth0                                                        #
# source-rn      : 3                                                           #
# src-linklocal  : True                                                        #
# src-multicast  : False                                                       #
# destin-if      : eth0                                                        #
# destin-rn      : 3                                                           #
# dst-linklocal  : False                                                       #
# dst-multicast  : True                                                        #
/sbin/ip6tables -A   output__new  -s fe80::1/128 -d ff80::4711/128 -p udp --sport 1024: --dport 4711:4713 -j ACCEPT -m comment --comment "2,3"
/sbin/ip6tables -A   input___new  -d fe80::1/128 -s ff80::4711/128 -p udp --dport 1024: --sport 4711:4713 -j ACCEPT -m comment --comment "2,3"
echo -n ".";"""
        value = fi.msg
        self.assertEqual(expect, value)

    def test_11_IP6_Filter_final_this_rule_forced_linklocal(self):
        """
        ft-11 IP6 Filter final this rule forced linklocal
        """
        debug = True
        name = "ns"
        path = "/home/sl0/adm6/desc/ns"
        mach_dir = "~/adm6/desc/ns"
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        rule_one = ['s', 'd', 'ip6', 'all', 'accept', "#", 'test-comment']
        ofn = "/dev/null"
        ofile = open(ofn, 'w')
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        rule = []
        rule.append("RuleText")                    # RuleText
        rule.append(True)                          # System-Fwd
        rule.append(2)                             # Rule-Nr.
        rule.append(3)                             # Pair-Nr.
        rule.append(True)                          # i_am_s
        rule.append(False)                         # i_am_d
        rule.append(IPv6Network('fe80::1'))        # source
        rule.append(IPv6Network('ff80::4711'))     # destin
        rule.append('eth0')                        # source-if
        rule.append(3)                             # source-rn
        rule.append('eth0')                        # destin-if
        rule.append(3)                             # destin-rn
        rule.append('udp')                         # protocol
        rule.append('4711:4713')                   # dport
        rule.append('accept')                      # action
        rule.append('NOIF NOSTATE FORCED')         # options at last
        fi.rules.append(rule)
        fi.final_this_rule(rule, ofile)
        value = fi.msg
        expect = """# ---------------------------------------------------------------------------- #
# Rule-Nr        : 2                                                           #
# Pair-Nr        : 3                                                           #
# System-Name    : ns                                                          #
# System-Forward : True                                                        #
# OS             : Debian                                                      #
# Asymmetric     : False                                                       #
# RuleText       : RuleText                                                    #
# Source         : fe80::1/128                                                 #
# Destin         : ff80::4711/128                                              #
# Protocol       : udp                                                         #
# sport          : 1024:                                                       #
# dport          : 4711:4713                                                   #
# Action         : accept                                                      #
# nonew          : False                                                       #
# noif           : True                                                        #
# nostate        : True                                                        #
# insec          : False                                                       #
# i_am_s         : True                                                        #
# i_am_d         : True                                                        #
# travers        : True                                                        #
# source-if      : eth0                                                        #
# source-rn      : 3                                                           #
# src-linklocal  : True                                                        #
# src-multicast  : False                                                       #
# destin-if      : eth0                                                        #
# destin-rn      : 3                                                           #
# dst-linklocal  : False                                                       #
# dst-multicast  : True                                                        #
# link-local ==> no forward"""
        value = fi.msg
        self.assertEqual(expect, value)
    
    def test_12_IP6_Filter_mach_output_as_src(self):
        """
        ft-12 IP6 Filter mach_output as src
        """
        debug = True
        name = "adm6"
        mach_dir = "~/adm6/desc/%s" % (name)
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        ofilename = "/dev/null"
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        rule = []
        rule.append("should be RuleText")          # RuleText
        rule.append(True)                          # System-Fwd
        rule.append(1)                             # Rule-Nr.
        rule.append(1)                             # Pair-Nr.
        rule.append(True)                          # i_am_s
        rule.append(False)                         # i_am_d
        rule.append(IPv6Network('2001:db8:1::1'))  # source
        rule.append(IPv6Network('2001:db8:2::11')) # destin
        rule.append('eth0')                        # source-if
        rule.append(1)                             # source-rn
        rule.append('eth0')                        # destin-if
        rule.append(1)                             # destin-rn
        rule.append('udp')                         # protocol
        rule.append('4711')                        # dport
        rule.append('accept')                      # action
        rule.append('NOIF NOSTATE FORCED')         # options at last
        fi.rules.append(rule)
        fi.mach_output(ofilename)
        value = fi.msg
        expect = """#!/bin/bash
#
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   a d m 6   -   A Device Manager for IPv6 packetfiltering        ##"
echo "##                                                                  ##"
echo "##   version:      0.2                                              ##"
echo "##                                                                  ##"
echo "##   device-name:  adm6                                             ##"
echo "##   device-type:  Debian GNU/Linux                                 ##"
echo "##                                                                  ##"
echo "##   date:         2013-03-13 23:23                                 ##"
echo "##   author:       Johannes Hubertz, hubertz-it-consulting GmbH     ##"
echo "##                                                                  ##"
echo "##   license:      GNU general public license version 3             ##"
echo "##                     or any later  version                        ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   some magic abbreviations follow                                ##"
echo "##                                                                  ##"
#
#POLICY_A='ACCEPT'
POLICY_D='DROP'
#
I6='/sbin/ip6tables '
IP6I='/sbin/ip6tables -A   input___new '
IP6O='/sbin/ip6tables -A   output__new '
IP6F='/sbin/ip6tables -A   forward_new '
#
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
for chain in $CHAINS
do
    /sbin/ip6tables -N ${chain}_act >/dev/null 2>/dev/null
    /sbin/ip6tables -N ${chain}_new
done
# but ignore all the boring fault-messages
$I6 -P   INPUT $POLICY_D
$I6 -P  OUTPUT $POLICY_D
$I6 -P FORWARD $POLICY_D
#
# some things need to pass,
# even if you don't like them
# do local and multicast on every interface
LOCAL="fe80::/10"
MCAST="ff02::/10"
#
$IP6I -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
$IP6O -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
#
$IP6I -p ipv6-icmp -s ${MCAST} -j ACCEPT
$IP6I -p ipv6-icmp -d ${MCAST} -j ACCEPT
$IP6O -p ipv6-icmp -s ${MCAST} -j ACCEPT
#
# all prepared now, individual mangling and rules following
#
# failed reading mangle-file: /home/sl0/adm6/desc/adm6/mangle-startup, but OK
# ---------------------------------------------------------------------------- #
# Rule-Nr        : 1                                                           #
# Pair-Nr        : 1                                                           #
# System-Name    : adm6                                                        #
# System-Forward : True                                                        #
# OS             : Debian                                                      #
# Asymmetric     : False                                                       #
# RuleText       : should be RuleText                                          #
# Source         : 2001:db8:1::1/128                                           #
# Destin         : 2001:db8:2::11/128                                          #
# Protocol       : udp                                                         #
# sport          : 1024:                                                       #
# dport          : 4711                                                        #
# Action         : accept                                                      #
# nonew          : False                                                       #
# noif           : True                                                        #
# nostate        : True                                                        #
# insec          : False                                                       #
# i_am_s         : True                                                        #
# i_am_d         : True                                                        #
# travers        : True                                                        #
# source-if      : eth0                                                        #
# source-rn      : 1                                                           #
# src-linklocal  : False                                                       #
# src-multicast  : False                                                       #
# destin-if      : eth0                                                        #
# destin-rn      : 1                                                           #
# dst-linklocal  : False                                                       #
# dst-multicast  : False                                                       #
/sbin/ip6tables -A   output__new  -s 2001:db8:1::1/128 -d 2001:db8:2::11/128 -p udp --sport 1024: --dport 4711 -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   input___new  -d 2001:db8:1::1/128 -s 2001:db8:2::11/128 -p udp --dport 1024: --sport 4711 -j ACCEPT -m comment --comment "1,1"
echo -n ".";/sbin/ip6tables -A   input___new  -s 2001:db8:1::1/128 -d 2001:db8:2::11/128 -p udp --sport 1024: --dport 4711 -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   output__new  -d 2001:db8:1::1/128 -s 2001:db8:2::11/128 -p udp --dport 1024: --sport 4711 -j ACCEPT -m comment --comment "1,1"
echo -n ".";/sbin/ip6tables -A   forward_new  -s 2001:db8:1::1/128 -d 2001:db8:2::11/128 -p udp --sport 1024: --dport 4711 -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -d 2001:db8:1::1/128 -s 2001:db8:2::11/128 -p udp --dport 1024: --sport 4711 -j ACCEPT -m comment --comment "1,1"
echo -n ".";# failed reading mangle-file: /home/sl0/adm6/desc/adm6/mangle-endup, but OK#
#$IP6I -p tcp --dport 22 -j ACCEPT
#$IP6O -p tcp --sport 22 -j ACCEPT
#
# allow ping and pong always (al gusto)
#$IP6O -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6I -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
##
#$IP6I -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6O -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
#
#ICMPv6types="${ICMPv6types} destination-unreachable"
ICMPv6types="${ICMPv6types} echo-request"
ICMPv6types="${ICMPv6types} echo-reply"
ICMPv6types="${ICMPv6types} neighbour-solicitation"
ICMPv6types="${ICMPv6types} neighbour-advertisement"
ICMPv6types="${ICMPv6types} router-solicitation"
ICMPv6types="${ICMPv6types} router-advertisement"
for icmptype in $ICMPv6types
do
    $IP6I -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
    $IP6O -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
done
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j LOG  --log-prefix "unreach: " -m limit --limit 30/second --limit-burst 60
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT
#
CHAINS=""
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
#set -x
for chain in $CHAINS
do
    /sbin/ip6tables -E "${chain}_act" "${chain}_old"
    /sbin/ip6tables -E "${chain}_new" "${chain}_act"
done
#
$I6 -F INPUT
$I6 -A INPUT   -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 0 -j DROP
$I6 -A INPUT   -m rt --rt-type 2 -j LOG --log-prefix "rt-2: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 2 -j DROP
$I6 -A INPUT  -i lo -j ACCEPT
$I6 -A INPUT   --jump input___act
#
$I6 -F OUTPUT
$I6 -A OUTPUT -o lo -j ACCEPT
$I6 -A OUTPUT  --jump output__act
#
$I6 -F FORWARD
$I6 -A FORWARD -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A FORWARD -m rt --rt-type 0 -j DROP
$I6 -A FORWARD --jump forward_act
#
for chain in $CHAINS
do
    /sbin/ip6tables -F "${chain}_old"
    /sbin/ip6tables -X "${chain}_old"
done
$I6 -F logdrop   >/dev/null 2>/dev/null
$I6 -X logdrop   >/dev/null 2>/dev/null
$I6 -N logdrop
$I6 -A   INPUT   --jump logdrop
$I6 -A  OUTPUT   --jump logdrop
$I6 -A FORWARD   --jump logdrop
$I6 -A logdrop -j LOG --log-prefix "drp: " -m limit --limit 3/second --limit-burst 6
$I6 -A logdrop -j DROP
#
/sbin/ip6tables-save -c >/root/last-filter
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##    End of generated filter-rules                                 ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
# EOF
"""
        self.assertEquals(expect, value)

    def test_13_IP6_Filter_mach_output_as_travers(self):
        """
        ft-13 IP6 Filter mach_output as travers
        """
        debug = True
        name = "adm6"
        mach_dir = "~/adm6/desc/%s" % (name)
        path = homedir(mach_dir)
        os = "Debian GNU/Linux"
        fwd = False
        asym = False
        ofilename = "/dev/null"
        fi = IP6_Filter(debug, path, name, os, fwd, asym, None)
        self.assertIsInstance(fi, IP6_Filter)
        rule = []
        rule.append("should be RuleText")          # RuleText
        rule.append(True)                          # System-Fwd
        rule.append(1)                             # Rule-Nr.
        rule.append(1)                             # Pair-Nr.
        rule.append(False)                         # i_am_s
        rule.append(False)                         # i_am_d
        rule.append(IPv6Network('2001:db8:1::1'))  # source
        rule.append(IPv6Network('2001:db8:2::11')) # destin
        rule.append('eth0')                        # source-if
        rule.append(1)                             # source-rn
        rule.append('eth1')                        # destin-if
        rule.append(3)                             # destin-rn
        rule.append('udp')                         # protocol
        rule.append('4711')                        # dport
        rule.append('accept')                      # action
        rule.append('NOSTATE')                     # options at last
        fi.rules.append(rule)
        fi.mach_output(ofilename)
        value = fi.msg
        expect = """#!/bin/bash
#
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   a d m 6   -   A Device Manager for IPv6 packetfiltering        ##"
echo "##                                                                  ##"
echo "##   version:      0.2                                              ##"
echo "##                                                                  ##"
echo "##   device-name:  adm6                                             ##"
echo "##   device-type:  Debian GNU/Linux                                 ##"
echo "##                                                                  ##"
echo "##   date:         2013-03-13 23:23                                 ##"
echo "##   author:       Johannes Hubertz, hubertz-it-consulting GmbH     ##"
echo "##                                                                  ##"
echo "##   license:      GNU general public license version 3             ##"
echo "##                     or any later  version                        ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   some magic abbreviations follow                                ##"
echo "##                                                                  ##"
#
#POLICY_A='ACCEPT'
POLICY_D='DROP'
#
I6='/sbin/ip6tables '
IP6I='/sbin/ip6tables -A   input___new '
IP6O='/sbin/ip6tables -A   output__new '
IP6F='/sbin/ip6tables -A   forward_new '
#
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
for chain in $CHAINS
do
    /sbin/ip6tables -N ${chain}_act >/dev/null 2>/dev/null
    /sbin/ip6tables -N ${chain}_new
done
# but ignore all the boring fault-messages
$I6 -P   INPUT $POLICY_D
$I6 -P  OUTPUT $POLICY_D
$I6 -P FORWARD $POLICY_D
#
# some things need to pass,
# even if you don't like them
# do local and multicast on every interface
LOCAL="fe80::/10"
MCAST="ff02::/10"
#
$IP6I -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
$IP6O -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
#
$IP6I -p ipv6-icmp -s ${MCAST} -j ACCEPT
$IP6I -p ipv6-icmp -d ${MCAST} -j ACCEPT
$IP6O -p ipv6-icmp -s ${MCAST} -j ACCEPT
#
# all prepared now, individual mangling and rules following
#
# failed reading mangle-file: /home/sl0/adm6/desc/adm6/mangle-startup, but OK
# ---------------------------------------------------------------------------- #
# Rule-Nr        : 1                                                           #
# Pair-Nr        : 1                                                           #
# System-Name    : adm6                                                        #
# System-Forward : True                                                        #
# OS             : Debian                                                      #
# Asymmetric     : False                                                       #
# RuleText       : should be RuleText                                          #
# Source         : 2001:db8:1::1/128                                           #
# Destin         : 2001:db8:2::11/128                                          #
# Protocol       : udp                                                         #
# sport          : 1024:                                                       #
# dport          : 4711                                                        #
# Action         : accept                                                      #
# nonew          : False                                                       #
# noif           : False                                                       #
# nostate        : True                                                        #
# insec          : False                                                       #
# i_am_s         : False                                                       #
# i_am_d         : False                                                       #
# travers        : True                                                        #
# source-if      : eth0                                                        #
# source-rn      : 1                                                           #
# src-linklocal  : False                                                       #
# src-multicast  : False                                                       #
# destin-if      : eth1                                                        #
# destin-rn      : 3                                                           #
# dst-linklocal  : False                                                       #
# dst-multicast  : False                                                       #
/sbin/ip6tables -A   forward_new  -i eth0 -s 2001:db8:1::1/128 -d 2001:db8:2::11/128 -p udp --sport 1024: --dport 4711 -j ACCEPT -m comment --comment "1,1"
/sbin/ip6tables -A   forward_new  -o eth0 -d 2001:db8:1::1/128 -s 2001:db8:2::11/128 -p udp --dport 1024: --sport 4711 -j ACCEPT -m comment --comment "1,1"
echo -n ".";# failed reading mangle-file: /home/sl0/adm6/desc/adm6/mangle-endup, but OK#
#$IP6I -p tcp --dport 22 -j ACCEPT
#$IP6O -p tcp --sport 22 -j ACCEPT
#
# allow ping and pong always (al gusto)
#$IP6O -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6I -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
##
#$IP6I -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6O -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
#
#ICMPv6types="${ICMPv6types} destination-unreachable"
ICMPv6types="${ICMPv6types} echo-request"
ICMPv6types="${ICMPv6types} echo-reply"
ICMPv6types="${ICMPv6types} neighbour-solicitation"
ICMPv6types="${ICMPv6types} neighbour-advertisement"
ICMPv6types="${ICMPv6types} router-solicitation"
ICMPv6types="${ICMPv6types} router-advertisement"
for icmptype in $ICMPv6types
do
    $IP6I -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
    $IP6O -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
done
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j LOG  --log-prefix "unreach: " -m limit --limit 30/second --limit-burst 60
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT
#
CHAINS=""
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
#set -x
for chain in $CHAINS
do
    /sbin/ip6tables -E "${chain}_act" "${chain}_old"
    /sbin/ip6tables -E "${chain}_new" "${chain}_act"
done
#
$I6 -F INPUT
$I6 -A INPUT   -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 0 -j DROP
$I6 -A INPUT   -m rt --rt-type 2 -j LOG --log-prefix "rt-2: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 2 -j DROP
$I6 -A INPUT  -i lo -j ACCEPT
$I6 -A INPUT   --jump input___act
#
$I6 -F OUTPUT
$I6 -A OUTPUT -o lo -j ACCEPT
$I6 -A OUTPUT  --jump output__act
#
$I6 -F FORWARD
$I6 -A FORWARD -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A FORWARD -m rt --rt-type 0 -j DROP
$I6 -A FORWARD --jump forward_act
#
for chain in $CHAINS
do
    /sbin/ip6tables -F "${chain}_old"
    /sbin/ip6tables -X "${chain}_old"
done
$I6 -F logdrop   >/dev/null 2>/dev/null
$I6 -X logdrop   >/dev/null 2>/dev/null
$I6 -N logdrop
$I6 -A   INPUT   --jump logdrop
$I6 -A  OUTPUT   --jump logdrop
$I6 -A FORWARD   --jump logdrop
$I6 -A logdrop -j LOG --log-prefix "drp: " -m limit --limit 3/second --limit-burst 6
$I6 -A logdrop -j DROP
#
/sbin/ip6tables-save -c >/root/last-filter
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##    End of generated filter-rules                                 ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
# EOF
"""
        #print "M:", value
        self.assertEquals(expect, value)


if __name__ == "__main__":
        unittest.main()
