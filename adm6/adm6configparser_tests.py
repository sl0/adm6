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


class Adm6ConfigParser_Tests(unittest.TestCase):
    '''some tests for class adm6configparser'''

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


if __name__ == "__main__":
    unittest.main()
