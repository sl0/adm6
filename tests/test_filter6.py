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

    def test_03_produce_for_linux_as_source(self):
        """
        fr-03 produce for linux as source host
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

    def test_04_produce_for_linux_as_dest(self):
        """
        fr-04 produce for linux as dest host
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

    def test_05_produce_for_linux_as_traversed(self):
        """
        fr-05 produce for linux as traversed host
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

    def test_05_produce_for_linux_as_traversed(self):
        """
        fr-05 produce for linux as traversed host
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

    def test_06_repr_with_debuglevel(self):
        """
        fr-05 produce for linux as traversed host
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


    def test_07_repr_without_debuglevel(self):
        """
        fr-05 produce for linux as traversed host
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




#class Ip6_Filter_tests(unittest.TestCase):
#    '''some tests for class Ip6_Filter_Rule'''
#
#    def test_01_create_IP6_Filter(self):
#        """
#        create a IP6 Filter object
#        """


if __name__ == "__main__":
        unittest.main()
