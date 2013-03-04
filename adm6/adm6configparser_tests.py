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
from adm6configparser import Adm6ConfigParser


class Adm6ConfigParser_tests(unittest.TestCase):
    '''
    some tests for class adm6configparser
    '''

    def test_01_read_existing_config(self):
        """
        read exisiting config file
        """
        my_err = False
        try:
            cfg = Adm6ConfigParser(".adm6.conf")
        except:
            my_err = True
        self.assertFalse(my_err)

    def test_02_read_non_existing_config(self):
        """
        read non existing config file
        """
        my_err = False
        try:
            cfg = Adm6ConfigParser("non-existing-file")
        except:
            my_err = True
        self.assertTrue(my_err)

    def test_03_get_version_from_config(self):
        """
        check version of adm6.conf
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
        get complete config as a string
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
        get adm6 home from config
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
        get adm6 debuglevel from config
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
        set debuglevel
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
        decrement adm6 debuglevel by one
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
        



if __name__ == "__main__":
    unittest.main()
