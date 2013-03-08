#!/usr/bin/env python
#encoding:utf8
#
# file:   adm6configparser_tests.py
# author: sl0
# date:   2013-03-04
#
"""
Tests for Adm6ConfigParser
"""

import unittest
from adm6.adm6configparser import Adm6ConfigParser


class Adm6ConfigParser_tests(unittest.TestCase):
    '''
    some tests for class adm6configparser
    '''

    def test_01_read_existing_config(self):
        """
        cf-01 read exisiting config file
        """
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
        except:
            my_err = True
        self.assertFalse(my_err)

    def test_02_read_non_existing_config(self):
        """
        cf-02 read non existing config file
        """
        my_err = False
        try:
            cfg = Adm6ConfigParser("non-existing-file")
        except:
            my_err = True
        self.assertTrue(my_err)

    def test_03_get_version_from_config(self):
        """
        cf-03 check version of adm6.conf
        """
        ref = "0.2"
        value = ""
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_version()
        except:
            my_err = True
        self.assertEquals(ref, value)

    def test_04_get_string_from_config(self):
        """
        cf-04 get complete config as a string
        """
        ref = ""
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_show_cf()
        except:
            my_err = True
        self.assertIsInstance(value, str)

    def test_05_get_adm6_home(self):
        """
        cf-05 get adm6 home from config
        """
        ref = "/adm6"
        value = ""
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_adm6_home()
        except:
            my_err = True
        self.assertIn(ref, value)

    def test_06_get_adm6_debuglevel(self):
        """
        cf-06 get adm6 debuglevel from config
        """
        ref = 1
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_adm6_debuglevel()
        except:
            my_err = True
        self.assertEqual(ref, value)

    def test_07_set_adm6_debuglevel(self):
        """
        cf-07 set debuglevel
        """
        ref = True
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.set_adm6_debuglevel(2)
        except:
            my_err = True
        self.assertEqual(ref, value)

    def test_08_dec_inc_debuglevel(self):
        """
        cf-08 decrement adm6 debuglevel by one
        """
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.dec_adm6_debuglevel()
            value = cfg.dec_adm6_debuglevel()
            value = cfg.dec_adm6_debuglevel()
        except:
            my_err = True
        self.assertEqual(True, value)
        value = cfg.get_adm6_debuglevel()
        self.assertEqual(0, value)
        try:
            value = cfg.inc_adm6_debuglevel()
        except:
            my_err = True
        self.assertEqual(True, value)
        value = cfg.get_adm6_debuglevel()
        self.assertEqual(1, value)

    def test_09_get_applyflag_ok(self):
        """
        cf-09 get adm6 applyflag from config
        """
        ref = True
        value = False
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_apply("adm6")
        except:
            my_err = True
        self.assertEqual(ref, value)

    def test_10_get_applyflag_fail(self):
        """
        cf-10 get adm6 applyflag from config
        """
        ref = True
        value = True
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_apply("obi-wan")
        except:
            my_err = True
        self.assertEqual(ref, value)

    def test_11_get_key_filename(self):
        """
        cf-11 get adm6 keyfilename from config
        """
        ref = 'none, please specify your own keyfile'
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_key_filename()
        except:
            my_err = True
        self.assertFalse(my_err)
        self.assertEqual(ref, value)

    def test_12_get_devices(self):
        """
        cf-12 get adm6 devices from config
        """
        ref = 'adm6,r-ex,ns,www,obi-wan'
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_devices()
        except:
            my_err = True
        self.assertFalse(my_err)
        self.assertEqual(ref, value)

    def test_13_get_software(self):
        """
        cf-13 get adm6 software from config
        """
        ref = "['Debian', 'OpenBSD', ]"
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_software()
        except:
            my_err = True
        self.assertFalse(my_err)
        self.assertEqual(ref, value)

    def test_14_get_device_home(self):
        """
        cf-14 get adm6 device_home from config
        """
        ref = "/adm6/desc/ns"
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_device_home('ns')
        except:
            my_err = True
        self.assertIn(ref, value)

    def test_15_get_desc(self):
        """
        cf-15 get adm6 desc from config
        """
        ref = "company dns server"
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_desc('ns')
        except:
            my_err = True
        self.assertIn(ref, value)

    def test_16_get_os(self):
        """
        cf-16 get adm6 os from config
        """
        ref = "Debian GNU/Linux, wheezy"
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_os('ns')
        except:
            my_err = True
        self.assertIn(ref, value)

    def test_17_get_asym_fail(self):
        """
        cf-17 get adm6 non existing asym flag from config
        """
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_asym('ns')
        except:
            my_err = True
        self.assertFalse(value)

    def test_18_get_asym_ok(self):
        """
        cf-18 get adm6 existing true asym flag from config
        """
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_asym('r-ex')
        except:
            my_err = True
        self.assertTrue(value)

    def test_19_get_ip(self):
        """
        cf-19 get adm6 ip from config
        """
        value = None
        ref = "2001:db8:23:2::1"
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_ip('r-ex')
        except:
            my_err = True
        self.assertEqual(ref, value)

    def test_20_get_fwd_ok(self):
        """
        cf-20 get adm6 fwd flag from config
        """
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_fwd('r-ex')
        except:
            my_err = True
        self.assertTrue(value)

    def test_21_get_fwd_fail(self):
        """
        cf-21 get adm6 fwd flag fail from config
        """
        value = None
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.get_fwd('obi-wan')
            self.assertRaises(IOError, cfg.get_fwd, 'obi-wan')
            self.assertRaises(ValueError, cfg.get_fwd, 'obi-wan')
        except:
            my_err = True
        self.assertTrue(my_err)
        #self.assertEquals(None, value)

    def test_22_print_head(self):
        """
        cf-22 get adm6 print head from config
        """
        value = None
        ref = 890
        my_err = False
        cfg = Adm6ConfigParser(".adm6.conf")
        value = len(cfg.print_head('adm6'))
        self.assertEquals(ref, value)
        return
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            value = cfg.print_head('adm6')
        except:
            my_err = True
        self.assertFalse(my_err)
        #self.assertEquals(ref, value)

    def test_23_print_head(self):
        """
        cf-23 get adm6 print all headers from config
        """
        value = None
        ref = True
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
            print cfg.print_all_headers()
            value = cfg.print_all_headers()
        except:
            my_err = True
        self.assertFalse(my_err)
        self.assertEquals(ref, value)
    

if __name__ == "__main__":
    unittest.main()
