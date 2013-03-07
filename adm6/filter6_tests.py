#!/usr/bin/env python
#encoding:utf8
#
# file:    filter6_tests.py
# author: sl0
# date:   2013-03-06
#

import unittest
from filter6 import IP6_Filter, Ip6_Filter_Rule
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

    def test_03_produce_for_linux_os_name(self):
        """
        fr-02 produce for invalid os name
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
        except:
            my_err = True
        fr['OS'] = 'Debian'
        #print type(fr)
        #print fr
        msg = fr.produce(ofile)
        print "M:", msg
        #self.assertRaises(ValueError, fr.produce ,stdout)



#class Ip6_Filter_tests(unittest.TestCase):
#    '''some tests for class Ip6_Filter_Rule'''
#
#    def test_01_create_IP6_Filter(self):
#        """
#        create a IP6 Filter object
#        """


if __name__ == "__main__":
        unittest.main()
