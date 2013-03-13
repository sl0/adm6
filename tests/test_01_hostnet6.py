#!/usr/bin/env python
#encoding:utf8
#
# file:    hostnet6_tests.py
# author: sl0
# date:   2013-03-03
#

import unittest
from ipaddr import IPv6Network
from adm6.hostnet6 import HostNet6

class HostNet6_tests(unittest.TestCase):
    '''some tests for class HostNet6'''

    def test_01_read_nonexisting_file(self):
        """
        hn-01 read non existing file, check raise
        """
        my_err = False
        try:
            hn6 = HostNet6("non-existing-file")
        except:
            my_err = True
        self.assertTrue(my_err)
        
    def test_02_read_an_existing_file(self):
        """
        hn-02 read an existing file, check no raise
        """
        my_err = False
        file = "reference-hostnet"
        try:
            hn6 = HostNet6(file)
        except:
            my_err = True
        self.assertFalse(my_err)

    def test_03_evaluate_entries(self):
        """
        hn-03 evaluate entries of reference-hostnet
        """
        file = "reference-hostnet"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file)
            print hn6.entries
        except:
            my_err = True
        print content
        self.assertEquals(content, hn6.entries)

    def test_04_evaluate_appended_entries_fail(self):
        """
        hn-04 entries of reference-hostnet-fail are not appended
        """
        file1 = "reference-hostnet"
        file2 = "reference-hostnet-fail"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file1)
        except:
            my_err = True
        try:
            hn6.append(file2)
        except:
            my_err = True
        self.assertTrue(my_err)
        #print "HN:", hn6.entries
        self.assertEquals(content, hn6.entries)

    def test_05_evaluate_appended_entries_ok(self):
        """
        hn-05 entries of reference-hostnet-append are appended
        """
        file1 = "reference-hostnet"
        file2 = "reference-hostnet-append"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['host-one', IPv6Network('2010:db8:1:beed::6/128')], \
            ['host-two', IPv6Network('2010:db8:1:beed::7/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file1)
            hn6.append(file2)
        except:
            my_err = True
        self.assertEquals(content, hn6.entries)

    def test_06_get_address(self):
        """
        hn-06 get_addrs returns list of given hostname
        """
        file1 = "reference-hostnet"
        my_err = False
        try:
            hn6 = HostNet6(file1)
        except:
            my_err = True
        self.assertFalse(my_err)
        #print "T6:", hn6.entries
        #print "GA1", hn6.get_addrs("host-one")
        #print "GA2", hn6.get_addrs("host-two")
        self.assertEquals([IPv6Network('2010:db8:1:beed::23/128')], hn6.get_addrs('host-one'))
        self.assertEquals( \
            ('host-one', [IPv6Network('2010:db8:1:beed::23/128')]), \
            hn6.show_addr('host-one'))

    def test_07_show_hostnet(self):
        """
        hn-07 show hostnet returns a long string
        """
        ref = """# hostnet6 contents:                                                           #
#    any 2000::/3                                                              #
#    beaf 2001:db8:beaf::/48                                                   #
#    host-one 2010:db8:1:beed::23/128                                          #
#    localhost ::1/128                                                         #
#    many ::/0                                                                 #
# hostnet6:     5 entries found                                                #
#                                                                              #
"""
        file1 = "reference-hostnet"
        my_err = False
        try:
            hn6 = HostNet6(file1)
        except:
            my_err = True
        self.assertFalse(my_err)
        text = hn6.show_hostnet6()
        self.assertEquals(ref, text)
        #print text


if __name__ == "__main__":
        unittest.main()
