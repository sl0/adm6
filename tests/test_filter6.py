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
        expect = "# WXP-SP3  n o t   y e t  i m p l e m e n t e d !"
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


#class Ip6_Filter_tests(unittest.TestCase):
#    '''some tests for class Ip6_Filter_Rule'''
#
#    def test_01_create_IP6_Filter(self):
#        """
#        create a IP6 Filter object
#        """


if __name__ == "__main__":
        unittest.main()
