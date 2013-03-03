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


class Adm6cConfigParserTest(unittest.TestCase):
    '''some tests for class adm6configparser'''

    def test_01_read_config(self):
        """
        read the config file
        """
        cfg = Adm6ConfigParser()
        print type(cfg)
        print cfg
        print dir(cfg)
        cfg.show_cf()

if __name__ == "__main__":
    unittest.main()
